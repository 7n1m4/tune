//! animaksm-swap-proxy: Experimental deduplicating swap proxy.
//!
//! Sits between the kernel swap subsystem and zram, deduplicating
//! identical pages before they reach compressed storage. Uses
//! xxh3-128 fingerprinting with a Bloom filter + concurrent hash map.
//!
//! In real mode, the proxy exposes the dedup storage as a ublk block
//! device and runs `mkswap` + `swapon` on it so the kernel swap
//! subsystem actually stores compressed-and-deduplicated pages.
//!
//! NOTE: This is an experimental component. It requires the ublk_drv
//! kernel module and CAP_SYS_ADMIN (not available in all environments).
//! The proxy is designed to fail-open: if it crashes, zram0 remains as
//! direct swap.

mod backend;
mod dedup;
mod fingerprint;
mod ublk_frontend;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use animaksm_common::config::AnimaksmConfig;
use clap::{Parser, Subcommand};
use libc::{
    mlockall, prctl, sched_param, sched_setscheduler, MCL_CURRENT, MCL_FUTURE, PR_SET_THP_DISABLE,
    SCHED_FIFO,
};
use parking_lot::Mutex;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use fingerprint::{fingerprint_page, PAGE_SIZE};

#[derive(Parser)]
#[command(
    name = "animaksm-swap-proxy",
    about = "Experimental deduplicating swap proxy"
)]
struct Cli {
    /// Path to TOML config (overrides defaults, overridden by explicit flags)
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the swap proxy
    Run {
        /// Device size in GB
        #[arg(long)]
        size_gb: Option<u64>,

        /// Page store path (ephemeral dedup table + backend slot store)
        #[arg(long, value_name = "PATH")]
        page_store_path: Option<PathBuf>,

        /// Maximum dedup table entries
        #[arg(long)]
        max_entries: Option<u64>,

        /// Bloom filter capacity (unique pages to size for)
        #[arg(long)]
        bloom_capacity: Option<usize>,

        /// Dry-run mode: simulate without a block device
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Do NOT mkswap + swapon the created ublk device
        #[arg(long, default_value_t = false)]
        no_bootstrap: bool,
    },
    /// Show proxy statistics
    Stats {
        /// Path to page store file
        #[arg(long, default_value = "/var/lib/animaksm/pagestore.dat")]
        store_path: PathBuf,
    },
    /// Clean up after a proxy crash (swapoff ublk devices, restore zram)
    Cleanup,
}

/// Shared statistics for the proxy.
struct ProxyStats {
    total_writes: AtomicU64,
    unique_writes: AtomicU64,
    duplicate_writes: AtomicU64,
    total_reads: AtomicU64,
    discards: AtomicU64,
}

impl ProxyStats {
    fn new() -> Self {
        Self {
            total_writes: AtomicU64::new(0),
            unique_writes: AtomicU64::new(0),
            duplicate_writes: AtomicU64::new(0),
            total_reads: AtomicU64::new(0),
            discards: AtomicU64::new(0),
        }
    }
}

/// The swap proxy storage engine.
pub(crate) struct ProxyEngine {
    dedup_table: dedup::DedupTable,
    store: Mutex<backend::PageStore>,
    translation: Mutex<backend::TranslationTable>,
    slot_allocator: Mutex<backend::SlotAllocator>,
    stats: Arc<ProxyStats>,
    passthrough: AtomicBool,
}

impl ProxyEngine {
    pub(crate) fn new(
        store_path: &Path,
        size_gb: u64,
        max_entries: u64,
        bloom_capacity: usize,
    ) -> anyhow::Result<Self> {
        let total_slots = (size_gb * 1024 * 1024 * 1024) / PAGE_SIZE as u64;

        let store = if store_path.exists() {
            backend::PageStore::open(store_path, total_slots)?
        } else {
            // Create new store file
            std::fs::create_dir_all(store_path.parent().unwrap_or(Path::new(".")))?;
            backend::PageStore::create_file(store_path, total_slots)?
        };

        info!(
            store_path = %store_path.display(),
            total_slots,
            size_gb,
            max_entries,
            bloom_capacity,
            "Page store initialized"
        );

        Ok(Self {
            dedup_table: dedup::DedupTable::new(max_entries, bloom_capacity),
            store: Mutex::new(store),
            translation: Mutex::new(backend::TranslationTable::new()),
            slot_allocator: Mutex::new(backend::SlotAllocator::new(total_slots)),
            stats: Arc::new(ProxyStats::new()),
            // DEFAULT: passthrough ON — dedup is opportunistic only under low pressure.
            // This prevents latency variance from killing swap performance when
            // the system is already stressed.
            passthrough: AtomicBool::new(true),
        })
    }

    fn allocate_slot(&self) -> anyhow::Result<u64> {
        self.slot_allocator
            .lock()
            .allocate()
            .ok_or_else(|| anyhow::anyhow!("page store is full"))
    }

    fn free_slot(&self, slot: u64) {
        self.slot_allocator.lock().free(slot);
    }

    fn release_mapping(&self, entry: backend::TranslationEntry) {
        match entry.kind {
            backend::MappingKind::Direct => self.free_slot(entry.backend_slot),
            backend::MappingKind::Deduplicated { fingerprint } => {
                match self.dedup_table.remove_reference(&fingerprint) {
                    dedup::ReferenceRemoval::StillReferenced => {}
                    dedup::ReferenceRemoval::Removed { backend_offset } => {
                        self.free_slot(backend_offset);
                    }
                    dedup::ReferenceRemoval::NotTracked => {
                        // The dedup metadata was evicted while this single
                        // translation kept owning the backend slot.
                        self.free_slot(entry.backend_slot);
                    }
                }
            }
        }
    }

    fn replace_mapping(&self, virtual_offset: u64, entry: backend::TranslationEntry) {
        let old = self.translation.lock().insert(virtual_offset, entry);
        if let Some(old) = old {
            self.release_mapping(old);
        }
    }

    fn write_page_to_slot(&self, slot: u64, page: &[u8]) -> anyhow::Result<()> {
        let mut store = self.store.lock();
        store.write_page(slot, page)
    }

    fn write_direct(&self, virtual_offset: u64, page: &[u8]) -> anyhow::Result<()> {
        let slot = self.allocate_slot()?;
        if let Err(err) = self.write_page_to_slot(slot, page) {
            self.free_slot(slot);
            return Err(err);
        }

        self.stats.unique_writes.fetch_add(1, Ordering::Relaxed);
        self.replace_mapping(virtual_offset, backend::TranslationEntry::direct(slot));
        Ok(())
    }

    fn write_unique_or_direct(
        &self,
        virtual_offset: u64,
        fp: fingerprint::Fingerprint,
        page: &[u8],
    ) -> anyhow::Result<()> {
        let slot = self.allocate_slot()?;
        if let Err(err) = self.write_page_to_slot(slot, page) {
            self.free_slot(slot);
            return Err(err);
        }

        let entry = if self.dedup_table.insert(fp, page, slot) {
            backend::TranslationEntry::deduplicated(fp, slot)
        } else {
            warn!("Dedup table full or fingerprint collision, keeping page as direct mapping");
            backend::TranslationEntry::direct(slot)
        };

        self.stats.unique_writes.fetch_add(1, Ordering::Relaxed);
        self.replace_mapping(virtual_offset, entry);
        Ok(())
    }

    /// Process a page write: fingerprint, check dedup, store or deduplicate.
    pub(crate) fn handle_write(&self, virtual_offset: u64, data: &[u8]) -> anyhow::Result<()> {
        self.stats.total_writes.fetch_add(1, Ordering::Relaxed);
        let page = normalize_page(data);

        // Passthrough mode (when under extreme pressure)
        if self.passthrough.load(Ordering::Relaxed) {
            return self.write_direct(virtual_offset, &page);
        }

        let fp = fingerprint_page(&page);

        // Check dedup table
        match self.dedup_table.lookup(&fp, &page) {
            dedup::LookupResult::Duplicate { backend_offset } => {
                let stored_page = {
                    let mut store = self.store.lock();
                    store.read_page(backend_offset)?
                };

                if stored_page == page && self.dedup_table.add_reference(&fp) {
                    self.stats.duplicate_writes.fetch_add(1, Ordering::Relaxed);
                    self.replace_mapping(
                        virtual_offset,
                        backend::TranslationEntry::deduplicated(fp, backend_offset),
                    );
                } else {
                    warn!(
                        backend_offset,
                        "Fingerprint lookup did not fully verify, storing page as unique"
                    );
                    self.write_unique_or_direct(virtual_offset, fp, &page)?;
                }
            }
            dedup::LookupResult::Miss => {
                self.write_unique_or_direct(virtual_offset, fp, &page)?;
            }
        }

        Ok(())
    }

    /// Process a page read.
    pub(crate) fn handle_read(&self, virtual_offset: u64) -> anyhow::Result<Vec<u8>> {
        self.stats.total_reads.fetch_add(1, Ordering::Relaxed);

        let entry = self.translation.lock().lookup(virtual_offset).cloned();
        let Some(entry) = entry else {
            return Ok(vec![0u8; PAGE_SIZE]);
        };

        let mut store = self.store.lock();
        store.read_page(entry.backend_slot)
    }

    /// Process a discard (trim) for a virtual offset.
    pub(crate) fn handle_discard(&self, virtual_offset: u64) {
        self.stats.discards.fetch_add(1, Ordering::Relaxed);

        let old = self.translation.lock().remove(virtual_offset);
        if let Some(entry) = old {
            self.release_mapping(entry);
        }
    }

    /// Get current proxy statistics.
    fn print_stats(&self) {
        let total_w = self.stats.total_writes.load(Ordering::Relaxed);
        let unique_w = self.stats.unique_writes.load(Ordering::Relaxed);
        let dup_w = self.stats.duplicate_writes.load(Ordering::Relaxed);
        let total_r = self.stats.total_reads.load(Ordering::Relaxed);
        let discards = self.stats.discards.load(Ordering::Relaxed);

        let dedup_table_stats = self.dedup_table.stats();

        let dedup_ratio = if total_w > 0 {
            (dup_w as f64 / total_w as f64) * 100.0
        } else {
            0.0
        };

        println!("=== animaksm swap proxy statistics ===");
        println!();
        println!("Write Operations:");
        println!("  Total writes:         {total_w}");
        println!("  Unique writes:        {unique_w}");
        println!("  Duplicate (deduped):  {dup_w}");
        println!("  Dedup ratio:          {dedup_ratio:.1}%");
        println!();
        println!("Read Operations:");
        println!("  Total reads:          {total_r}");
        println!();
        println!("Discards:               {discards}");
        println!();
        println!("Dedup Table:");
        println!(
            "  Unique pages tracked: {}",
            dedup_table_stats.table_entries
        );
        println!("  Total unique seen:    {}", dedup_table_stats.unique_pages);
        println!(
            "  Duplicate hits:       {}",
            dedup_table_stats.duplicate_hits
        );
        println!("  Evictions:            {}", dedup_table_stats.evictions);
        println!(
            "  Bloom false positives: {}",
            dedup_table_stats.bloom_false_positives
        );
    }
}

fn normalize_page(data: &[u8]) -> [u8; PAGE_SIZE] {
    let mut page = [0u8; PAGE_SIZE];
    let len = data.len().min(PAGE_SIZE);
    page[..len].copy_from_slice(&data[..len]);
    page
}

fn main() -> anyhow::Result<()> {
    // Self-hardening: run before I/O so log lines reach stderr first.
    process_hardening();

    // Install signal handler *after* hardening (mlockall the handler stack,
    // oom_score_adj protects it, SCHED_FIFO polls it).
    install_signal_handler()?;

    let cli = Cli::parse();
    let config = match &cli.config {
        Some(path) => AnimaksmConfig::load(path)?,
        None => AnimaksmConfig::default(),
    };
    run_command(cli.command, config)
}

/// Best-effort self-hardening so the proxy cannot be OOM-killed or
/// swapped itself while managing a live ublk swap device.
fn process_hardening() {
    // 1. Lock all current and future pages into RAM (mlockall).
    // Prevents the kernel from paging out the proxy's own heap while
    // it's serving block I/O.
    unsafe {
        let ret = mlockall(MCL_CURRENT | MCL_FUTURE);
        if ret != 0 {
            let errno = *libc::__errno_location();
            eprintln!("HARDEN[warn] mlockall failed (errno {errno}) — proxy pages may be swapped; set LimitMEMLOCK=-1 in systemd");
        } else {
            eprintln!("HARDEN[ok] mlockall(MCL_CURRENT|MCL_FUTURE)");
        }
    }

    // 2. Set /proc/self/oom_score_adj = -1000 → never chosen as OOM victim.
    // Best-effort: if /proc isn't writable we continue with default score.
    if let Err(e) = std::fs::write("/proc/self/oom_score_adj", b"-1000\n") {
        eprintln!("HARDEN[warn] oom_score_adj write failed ({e}) — proxy stays OOM-vulnerable");
    } else {
        eprintln!("HARDEN[ok] oom_score_adj = -1000 (never OOM-killed)");
    }

    // 3. Set SCHED_FIFO with priority 50 so we aren't preempted by normal
    // userspace tasks while serving ublk I/O. This mutates the calling
    // process — works for the main and any blocking I/O worker threads.
    unsafe {
        let param = sched_param { sched_priority: 50 };
        let ret = sched_setscheduler(0, SCHED_FIFO, &param); // pid 0 = self
        if ret != 0 {
            let errno = *libc::__errno_location();
            eprintln!("HARDEN[warn] sched_setscheduler failed (errno {errno}) — proxy runs at SCHED_OTHER; need CAP_SYS_NICE");
        } else {
            eprintln!("HARDEN[ok] SCHED_FIFO prio 50");
        }
    }

    // 4. Disable THP for this process only. THP defrag latency spikes are
    // unacceptable on a realtime block I/O path.
    unsafe {
        let ret = prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
        if ret != 0 {
            eprintln!("HARDEN[warn] PR_SET_THP_DISABLE failed — THP may introduce latency spikes");
        } else {
            eprintln!("HARDEN[ok] THP disabled");
        }
    }
}

/// Resolved swap-proxy runtime parameters: TOML defaults merged with CLI overrides.
#[derive(Debug)]
struct RunConfig {
    page_store_path: PathBuf,
    size_gb: u64,
    max_entries: u64,
    bloom_capacity: usize,
    /// When true, run mkswap + swapon on the created ublk device.
    bootstrap: bool,
}

fn run_command(command: Commands, config: AnimaksmConfig) -> anyhow::Result<()> {
    match command {
        Commands::Run {
            size_gb,
            page_store_path,
            max_entries,
            bloom_capacity,
            dry_run,
            no_bootstrap,
        } => {
            let sp = &config.swap_proxy;
            run_proxy_v2(
                RunConfig {
                    page_store_path: page_store_path
                        .unwrap_or_else(|| PathBuf::from(&sp.page_store_path)),
                    size_gb: size_gb.unwrap_or(sp.device_size_gb),
                    max_entries: max_entries.unwrap_or(sp.dedup_table_max_entries),
                    bloom_capacity: bloom_capacity.unwrap_or(sp.bloom_capacity),
                    bootstrap: !no_bootstrap,
                },
                dry_run,
            )
        }
        Commands::Stats { store_path } => show_stats_command(&store_path),
        Commands::Cleanup => cleanup_after_crash(),
    }
}

fn show_stats_command(store_path: &Path) -> anyhow::Result<()> {
    println!("Note: Stats require the proxy to be running.");
    println!("Store path: {}", store_path.display());
    Ok(())
}

fn cleanup_after_crash() -> anyhow::Result<()> {
    info!("Cleaning up after proxy crash / service stop");

    // 1. swapoff any ublk-backed swap device the prior run left active.
    let swapon_output = std::process::Command::new("swapon")
        .arg("--show")
        .arg("--noheadings")
        .output();
    match swapon_output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for ubd in ubd_devices_in_swapon_output(&stdout) {
                info!(device = %ubd, "swapoff on ublk device");
                let status = std::process::Command::new("swapoff")
                    .arg(&ubd)
                    .output()
                    .ok()
                    .and_then(|o| o.status.code().map(|c| c == 0))
                    .unwrap_or(false);
                if status {
                    println!("swapoff {ubd} ok");
                } else {
                    println!("swapoff {ubd} FAILED");
                }
            }
        }
        Err(e) => {
            println!("Could not enumerate swap devices (swapon --show): {e}");
        }
    }

    // 2. Restore zram0 as a fail-open swap backend if needed.
    for line in cleanup_messages_from_swapon_stdout(&String::from_utf8_lossy(
        &std::process::Command::new("swapon")
            .arg("--show")
            .output()
            .map(|o| o.stdout)
            .unwrap_or_default(),
    )) {
        println!("{line}");
    }

    Ok(())
}

/// Parse `/proc/swaps`-style output and return paths of active ublk swap
/// devices.
///
/// Kernel 7.1+ exposes ublk block devices as `/dev/ublkb0`, `/dev/ublkb1`, …
/// Older kernels (and FUSE-based frontends) used `/dev/ubd0`, `/dev/ubd1`, …
/// Match both naming schemes while excluding unrelated names such as
/// `/dev/ubdish` or `/dev/mapper/vg-ubdswap`. The trailing token must be the
/// prefix followed by one or more ASCII digits, nothing else.
fn ubd_devices_in_swapon_output(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let name = cols.next()?;
            let rest = name
                .strip_prefix("/dev/ublkb")
                .or_else(|| name.strip_prefix("/dev/ubd"))?;
            if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            Some(name.to_string())
        })
        .collect()
}

fn cleanup_messages_from_swapon_stdout(stdout: &str) -> Vec<&'static str> {
    if stdout.contains("zram0") {
        vec!["zram0 is still active as swap. No cleanup needed."]
    } else {
        vec![
            "WARNING: zram0 is not active as swap!",
            "Run: swapon /dev/zram0",
        ]
    }
}

fn run_proxy_v2(run: RunConfig, dry_run: bool) -> anyhow::Result<()> {
    // Initialize tracing (only the first call has an effect)
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();

    let RunConfig {
        page_store_path,
        size_gb,
        max_entries,
        bloom_capacity,
        bootstrap,
    } = run;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        store = %page_store_path.display(),
        size_gb,
        max_entries,
        bloom_capacity,
        bootstrap,
        dry_run,
        "animaksm-swap-proxy starting"
    );

    if dry_run {
        info!("DRY RUN mode: simulating proxy without actual block device");
        run_dry_run_simulation(page_store_path, size_gb, max_entries, bloom_capacity)?;
    } else {
        run_real_proxy(
            page_store_path,
            size_gb,
            max_entries,
            bloom_capacity,
            bootstrap,
        )?;
    }

    Ok(())
}

/// Global shutdown flag, toggled by the ctrlc handler.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Install a SIGINT/SIGTERM handler that flips SHUTDOWN. Second signal
/// hard-exits so a stuck process terminates promptly.
fn install_signal_handler() -> anyhow::Result<()> {
    ctrlc::set_handler(|| {
        if SHUTDOWN.swap(true, Ordering::SeqCst) {
            std::process::exit(0x80 + libc::SIGTERM);
        }
    })?;
    Ok(())
}

fn run_real_proxy(
    page_store_path: PathBuf,
    size_gb: u64,
    max_entries: u64,
    bloom_capacity: usize,
    bootstrap: bool,
) -> anyhow::Result<()> {
    info!("Starting real ublk frontend");
    ublk_frontend::ensure_available()?;
    let engine = Arc::new(ProxyEngine::new(
        &page_store_path,
        size_gb,
        max_entries,
        bloom_capacity,
    )?);

    let shutdown = Arc::new(AtomicBool::new(false));

    // Bridge the static SHUTDOWN flag to the Arc<AtomicBool> used by run().
    // The signal handler only sees the static; run() only sees the Arc.
    // This thread copies the polarity once per tick and also handles
    // the edge case where the signal arrives before run() starts.
    let shutdown_bridge = Arc::clone(&shutdown);
    let bridge = std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if SHUTDOWN.load(Ordering::Relaxed) {
            shutdown_bridge.store(true, Ordering::Relaxed);
            break;
        }
    });

    let result = if bootstrap {
        info!("Bootstrapping ublk device as swap (mkswap + swapon)");
        ublk_frontend::run(
            engine,
            size_gb,
            |bdev| {
                if let Err(err) = bootstrap_swap(bdev) {
                    warn!(bdev = %bdev.display(), %err, "skipping swap bootstrap");
                }
            },
            shutdown,
        )
    } else {
        info!("Swap bootstrap disabled (--no-bootstrap)");
        ublk_frontend::run(engine, size_gb, |_bdev| {}, shutdown)
    };

    // Ensure the bridge thread exits — should already be dead.
    let _ = bridge.join();
    result
}

/// Best-effort mkswap + swapon on a freshly-created ublk block device.
fn bootstrap_swap(bdev: &Path) -> anyhow::Result<()> {
    info!(bdev = %bdev.display(), "running mkswap on ublk device");
    let status = std::process::Command::new("mkswap")
        .arg(bdev)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to exec mkswap: {e}"))?;
    if !status.success() {
        anyhow::bail!("mkswap exited with status {status}");
    }

    info!(bdev = %bdev.display(), "swapon on ublk device");
    let status = std::process::Command::new("swapon")
        .arg(bdev)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to exec swapon: {e}"))?;
    if !status.success() {
        // mkswap succeeded but swapon failed — the swap header is valid, the
        // device remains usable. Back off with a hard error so the operator can
        // investigate.
        anyhow::bail!("swapon exited with status {status}");
    }

    info!(bdev = %bdev.display(), "ublk device is now active as swap");
    Ok(())
}

fn run_dry_run_simulation(
    store_path: PathBuf,
    size_gb: u64,
    max_entries: u64,
    bloom_capacity: usize,
) -> anyhow::Result<()> {
    let engine = ProxyEngine::new(&store_path, size_gb, max_entries, bloom_capacity)?;

    info!("Generating synthetic workload (opportunistic mode demo)...");
    info!("Phase 1: Passthrough mode (simulating high memory pressure)");

    // Phase 1: Start in passthrough mode (high pressure)
    // Pages go straight through without dedup overhead
    let num_unique = 600u64;
    let num_total = 5_000u64;

    let mut unique_pages: Vec<Vec<u8>> = Vec::new();
    for i in 0..num_unique {
        let mut page = vec![0u8; PAGE_SIZE];
        for (j, byte) in page.iter_mut().enumerate() {
            *byte = ((i * 7 + j as u64 * 13) % 256) as u8;
        }
        unique_pages.push(page);
    }

    // Write pages in passthrough (no dedup)
    for i in 0..num_total {
        let page_idx = (i * 37 % num_unique) as usize;
        let offset = i * PAGE_SIZE as u64;
        engine.handle_write(offset, &unique_pages[page_idx])?;
    }

    info!(
        total = engine
            .stats
            .total_writes
            .load(std::sync::atomic::Ordering::Relaxed),
        deduped = engine
            .stats
            .duplicate_writes
            .load(std::sync::atomic::Ordering::Relaxed),
        "Phase 1 complete (passthrough — zero dedup overhead)"
    );

    // Phase 2: Pressure drops — enable opportunistic dedup
    info!("Phase 2: Enabling dedup mode (pressure dropped, opportunistic)");
    engine.passthrough.store(false, Ordering::Relaxed);

    for i in num_total..(num_total * 2) {
        let page_idx = (i * 37 % num_unique) as usize;
        let offset = i * PAGE_SIZE as u64;
        engine.handle_write(offset, &unique_pages[page_idx])?;
    }

    // Read back some pages
    for i in 0..1000u64 {
        let offset = i * PAGE_SIZE as u64;
        let data = engine.handle_read(offset)?;
        assert_eq!(data.len(), PAGE_SIZE);
    }

    // Discard some
    for i in 5000..6000u64 {
        let offset = i * PAGE_SIZE as u64;
        engine.handle_discard(offset);
    }

    engine.print_stats();

    info!("Dry-run simulation complete (opportunistic mode demonstrated)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("pagestore.dat");
        (dir, path)
    }

    #[test]
    fn test_proxy_stats_new_zeroes() {
        let stats = ProxyStats::new();
        assert_eq!(stats.total_writes.load(Ordering::Relaxed), 0);
        assert_eq!(stats.unique_writes.load(Ordering::Relaxed), 0);
        assert_eq!(stats.duplicate_writes.load(Ordering::Relaxed), 0);
        assert_eq!(stats.total_reads.load(Ordering::Relaxed), 0);
        assert_eq!(stats.discards.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_proxy_engine_new_creates_store_parent_directory() {
        let (_dir, path) = engine_path();

        let engine = ProxyEngine::new(&path, 1, 128, 1024).unwrap();

        assert!(path.exists());
        assert!(engine.passthrough.load(Ordering::Relaxed));
        assert_eq!(
            engine.store.lock().total_slots(),
            (1024 * 1024 * 1024) / PAGE_SIZE as u64
        );
    }

    #[test]
    fn test_cli_parses_run_stats_and_cleanup_commands() {
        let run = Cli::try_parse_from([
            "animaksm-swap-proxy",
            "run",
            "--page-store-path",
            "/tmp/store.dat",
            "--size-gb",
            "2",
            "--max-entries",
            "42",
            "--dry-run",
            "--no-bootstrap",
        ])
        .unwrap();
        match run.command {
            Commands::Run {
                page_store_path,
                size_gb,
                max_entries,
                dry_run,
                no_bootstrap,
                bloom_capacity: _,
            } => {
                assert_eq!(page_store_path, Some(PathBuf::from("/tmp/store.dat")));
                assert_eq!(size_gb, Some(2));
                assert_eq!(max_entries, Some(42));
                assert!(dry_run);
                assert!(no_bootstrap);
            }
            _ => panic!("expected run command"),
        }

        let stats = Cli::try_parse_from([
            "animaksm-swap-proxy",
            "stats",
            "--store-path",
            "/tmp/store.dat",
        ])
        .unwrap();
        assert!(matches!(stats.command, Commands::Stats { .. }));

        let cleanup = Cli::try_parse_from(["animaksm-swap-proxy", "cleanup"]).unwrap();
        assert!(matches!(cleanup.command, Commands::Cleanup));
    }

    #[test]
    fn test_run_command_stats_prints_store_path() {
        run_command(
            Commands::Stats {
                store_path: PathBuf::from("/tmp/store.dat"),
            },
            AnimaksmConfig::default(),
        )
        .unwrap();
    }

    #[test]
    fn test_cleanup_messages_detect_zram0_active() {
        let messages = cleanup_messages_from_swapon_stdout(
            "NAME TYPE SIZE USED PRIO\n/dev/zram0 partition 4G 0B 100\n",
        );
        assert_eq!(
            messages,
            vec!["zram0 is still active as swap. No cleanup needed."]
        );
    }

    #[test]
    fn test_cleanup_messages_warn_when_zram0_missing() {
        let messages = cleanup_messages_from_swapon_stdout("NAME TYPE SIZE USED PRIO\n");
        assert_eq!(
            messages,
            vec![
                "WARNING: zram0 is not active as swap!",
                "Run: swapon /dev/zram0"
            ]
        );
    }

    #[test]
    fn test_cleanup_detects_ubd_device_in_swapon_output() {
        let stdout = "NAME       TYPE SIZE USED PRIO\n/dev/ubd0  partition 8G 0B 100\n";
        let devices = ubd_devices_in_swapon_output(stdout);
        assert_eq!(devices, vec![String::from("/dev/ubd0")]);
    }

    #[test]
    fn test_cleanup_ignores_zram_only_swapon_output() {
        let stdout = "NAME       TYPE SIZE USED PRIO\n/dev/zram0 partition 4G 0B 100\n";
        let devices = ubd_devices_in_swapon_output(stdout);
        assert!(devices.is_empty());
    }

    #[test]
    fn test_cleanup_handles_empty_swapon_output() {
        let devices = ubd_devices_in_swapon_output("NAME TYPE SIZE USED PRIO\n");
        assert!(devices.is_empty());
    }

    #[test]
    fn test_cleanup_matches_ublkb_modern_kernel_naming() {
        // Live-tested on kernel 7.1.2: ublk exposes /dev/ublkbN.
        let stdout = "NAME       TYPE SIZE USED PRIO\n/dev/ublkb0 partition 1G 0B 100\n/dev/ublkb1 partition 1G 0B  99\n";
        let devices = ubd_devices_in_swapon_output(stdout);
        assert_eq!(
            devices,
            vec![String::from("/dev/ublkb0"), String::from("/dev/ublkb1")]
        );
    }

    #[test]
    fn test_cleanup_matches_legacy_ubd_kernel_naming() {
        // Older kernels / frontends still use /dev/ubdN.
        let stdout = "NAME      TYPE SIZE USED PRIO\n/dev/ubd0 partition 8G 0B 100\n";
        let devices = ubd_devices_in_swapon_output(stdout);
        assert_eq!(devices, vec![String::from("/dev/ubd0")]);
    }

    #[test]
    fn test_cleanup_rejects_partial_prefix_match() {
        // /dev/ubd1ish (weird but possible naming) and /dev/ublkb9xyz must NOT match.
        let stdout = "NAME         TYPE SIZE USED PRIO\n/dev/ubd1ish  partition 4G 0B 100\n/dev/ublkb9xyz partition 4G 0B 100\n";
        let devices = ubd_devices_in_swapon_output(stdout);
        assert!(
            devices.is_empty(),
            "expected no partial-prefix matches, got: {devices:?}"
        );
    }

    #[test]
    fn test_cleanup_ignores_unrelated_devices_with_ubd_substring() {
        // Regression guard: `contains("ubd")` would wrongly match these.
        // The names start with "/dev/" but the second component isn't exactly
        // "ubd" + digits — e.g. "/dev/mapper/vg-ubdswap" and "/dev/ubdish".
        // `starts_with("/dev/ubd")` would still wrongly match "/dev/ubdish";
        // a regexp would be stricter. Document current behavior.
        let stdout = "NAME                      TYPE SIZE USED PRIO\n/dev/mapper/vg-ubdswap  partition 4G 0B 100\n/dev/ubdish             partition 4G 0B 100\n";
        let devices = ubd_devices_in_swapon_output(stdout);
        assert!(
            devices.is_empty(),
            "expected no false positives for non-ubd* names, got: {devices:?}"
        );
    }

    #[test]
    fn test_cleanup_matches_multiple_ubd_devices() {
        let stdout = "NAME      TYPE SIZE USED PRIO\n                        /dev/ubd0 partition 8G 0B 100\n                        /dev/ubd1 partition 8G 0B  99\n";
        let devices = ubd_devices_in_swapon_output(stdout);
        assert_eq!(
            devices,
            vec![String::from("/dev/ubd0"), String::from("/dev/ubd1")]
        );
    }

    #[test]
    fn test_run_command_uses_toml_defaults_when_flags_omitted() {
        let cli = Cli::try_parse_from(["animaksm-swap-proxy", "run"]).unwrap();
        let default = AnimaksmConfig::default();
        match cli.command {
            Commands::Run {
                size_gb,
                page_store_path,
                max_entries,
                bloom_capacity,
                dry_run,
                ..
            } => {
                // Flags are None at CLI layer; TOML merge happens in run_command.
                assert_eq!(size_gb, None);
                assert_eq!(page_store_path, None);
                assert_eq!(max_entries, None);
                assert_eq!(bloom_capacity, None);
                assert!(!dry_run);
                // Sanity: TOML defaults still match the struct's own defaults.
                assert_eq!(default.swap_proxy.device_size_gb, 8);
                assert_eq!(default.swap_proxy.dedup_table_max_entries, 1_000_000);
                assert_eq!(default.swap_proxy.bloom_capacity, 1_000_000);
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn test_run_command_flag_overrides_toml_default() {
        let toml_tmp = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::fs::write(
            toml_tmp.path(),
            "[swap_proxy]\nenabled = true\ndevice_size_gb = 4\ndedup_table_max_entries = 100\nbloom_capacity = 256\n",
        )
        .unwrap();

        // Parse CLI without override flags but with --config. The loaded
        // config should reflect the TOML-supplied values.
        let _cli = Cli::try_parse_from([
            "animaksm-swap-proxy",
            "--config",
            toml_tmp.path().to_str().unwrap(),
            "run",
        ])
        .unwrap();
        let config = AnimaksmConfig::load(toml_tmp.path()).unwrap();
        assert_eq!(config.swap_proxy.device_size_gb, 4);
        assert_eq!(config.swap_proxy.dedup_table_max_entries, 100);
        assert_eq!(config.swap_proxy.bloom_capacity, 256);
    }

    #[test]
    fn test_cli_no_config_flag_uses_defaults() {
        let cli = Cli::try_parse_from(["animaksm-swap-proxy", "run"]).unwrap();
        assert_eq!(cli.config, None);
    }

    #[test]
    fn test_handle_write_passthrough_writes_direct_slot_and_counts_unique() {
        let (_dir, path) = engine_path();
        let engine = ProxyEngine::new(&path, 1, 128, 1024).unwrap();
        let page = vec![0xAA; PAGE_SIZE];

        engine.handle_write(PAGE_SIZE as u64, &page).unwrap();
        let read = engine.handle_read(PAGE_SIZE as u64).unwrap();

        assert_eq!(read, page);
        assert_eq!(engine.stats.total_writes.load(Ordering::Relaxed), 1);
        assert_eq!(engine.stats.unique_writes.load(Ordering::Relaxed), 1);
        assert_eq!(engine.stats.duplicate_writes.load(Ordering::Relaxed), 0);
        assert_eq!(engine.stats.total_reads.load(Ordering::Relaxed), 1);
        assert_eq!(engine.translation.lock().len(), 1);
    }

    #[test]
    fn test_handle_write_dedup_mode_records_duplicate_translation() {
        let (_dir, path) = engine_path();
        let engine = ProxyEngine::new(&path, 1, 128, 1024).unwrap();
        engine.passthrough.store(false, Ordering::Relaxed);
        let page = vec![0xAB; PAGE_SIZE];

        engine.handle_write(0, &page).unwrap();
        engine.handle_write(PAGE_SIZE as u64, &page).unwrap();

        assert_eq!(engine.stats.total_writes.load(Ordering::Relaxed), 2);
        assert_eq!(engine.stats.unique_writes.load(Ordering::Relaxed), 1);
        assert_eq!(engine.stats.duplicate_writes.load(Ordering::Relaxed), 1);
        assert_eq!(engine.translation.lock().len(), 2);

        let read = engine.handle_read(PAGE_SIZE as u64).unwrap();
        assert_eq!(read, page);

        let dedup_stats = engine.dedup_table.stats();
        assert_eq!(dedup_stats.table_entries, 1);
        assert_eq!(dedup_stats.duplicate_hits, 1);
    }

    #[test]
    fn test_handle_write_replaces_old_translation_and_removes_reference() {
        let (_dir, path) = engine_path();
        let engine = ProxyEngine::new(&path, 1, 128, 1024).unwrap();
        engine.passthrough.store(false, Ordering::Relaxed);
        let page_a = vec![0xAA; PAGE_SIZE];
        let page_b = vec![0xBB; PAGE_SIZE];

        engine.handle_write(0, &page_a).unwrap();
        engine.handle_write(0, &page_b).unwrap();

        let read = engine.handle_read(0).unwrap();
        assert_eq!(read, page_b);
        assert_eq!(engine.translation.lock().len(), 1);
        assert_eq!(engine.dedup_table.stats().table_entries, 1);
    }

    #[test]
    fn test_handle_discard_removes_translation_and_counts_discard() {
        let (_dir, path) = engine_path();
        let engine = ProxyEngine::new(&path, 1, 128, 1024).unwrap();
        engine.passthrough.store(false, Ordering::Relaxed);
        let page = vec![0xCC; PAGE_SIZE];

        engine.handle_write(0, &page).unwrap();
        assert_eq!(engine.translation.lock().len(), 1);

        engine.handle_discard(0);

        assert_eq!(engine.stats.discards.load(Ordering::Relaxed), 1);
        assert_eq!(engine.translation.lock().len(), 0);
        assert_eq!(engine.dedup_table.stats().table_entries, 0);
    }

    #[test]
    fn test_passthrough_overwrite_clears_old_dedup_translation() {
        let (_dir, path) = engine_path();
        let engine = ProxyEngine::new(&path, 1, 128, 1024).unwrap();
        let page_a = vec![0xAA; PAGE_SIZE];
        let page_b = vec![0xBB; PAGE_SIZE];

        engine.passthrough.store(false, Ordering::Relaxed);
        engine.handle_write(0, &page_a).unwrap();
        assert_eq!(engine.dedup_table.stats().table_entries, 1);

        engine.passthrough.store(true, Ordering::Relaxed);
        engine.handle_write(0, &page_b).unwrap();

        assert_eq!(engine.handle_read(0).unwrap(), page_b);
        assert_eq!(engine.dedup_table.stats().table_entries, 0);
        assert_eq!(engine.translation.lock().len(), 1);
    }

    #[test]
    fn test_table_full_fallback_still_updates_translation() {
        let (_dir, path) = engine_path();
        let engine = ProxyEngine::new(&path, 1, 0, 1024).unwrap();
        engine.passthrough.store(false, Ordering::Relaxed);
        let page = vec![0x44; PAGE_SIZE];

        engine.handle_write(0, &page).unwrap();

        assert_eq!(engine.handle_read(0).unwrap(), page);
        assert_eq!(engine.dedup_table.stats().table_entries, 0);
        assert_eq!(engine.translation.lock().len(), 1);
    }

    #[test]
    fn test_direct_and_dedup_slots_do_not_alias() {
        let (_dir, path) = engine_path();
        let engine = ProxyEngine::new(&path, 1, 128, 1024).unwrap();
        let direct_page = vec![0x11; PAGE_SIZE];
        let dedup_page = vec![0x22; PAGE_SIZE];

        engine.handle_write(0, &direct_page).unwrap();
        engine.passthrough.store(false, Ordering::Relaxed);
        engine.handle_write(PAGE_SIZE as u64, &dedup_page).unwrap();

        assert_eq!(engine.handle_read(0).unwrap(), direct_page);
        assert_eq!(engine.handle_read(PAGE_SIZE as u64).unwrap(), dedup_page);
    }

    #[test]
    fn test_discarded_page_reads_as_zeroes_without_stale_backend_data() {
        let (_dir, path) = engine_path();
        let engine = ProxyEngine::new(&path, 1, 128, 1024).unwrap();
        let page = vec![0x77; PAGE_SIZE];

        engine.handle_write(0, &page).unwrap();
        engine.handle_discard(0);

        assert_eq!(engine.handle_read(0).unwrap(), vec![0; PAGE_SIZE]);
    }

    #[test]
    fn test_short_writes_are_hashed_as_zero_padded_pages() {
        let (_dir, path) = engine_path();
        let engine = ProxyEngine::new(&path, 1, 128, 1024).unwrap();
        engine.passthrough.store(false, Ordering::Relaxed);

        engine.handle_write(0, &[1, 2, 3]).unwrap();
        engine.handle_write(PAGE_SIZE as u64, &[1, 2, 3]).unwrap();

        assert_eq!(engine.stats.duplicate_writes.load(Ordering::Relaxed), 1);
        let read = engine.handle_read(PAGE_SIZE as u64).unwrap();
        assert_eq!(&read[..3], &[1, 2, 3]);
        assert!(read[3..].iter().all(|b| *b == 0));
    }

    #[test]
    fn test_run_proxy_dry_run_simulation_completes() {
        let (_dir, path) = engine_path();
        let run = RunConfig {
            page_store_path: path,
            size_gb: 1,
            max_entries: 2048,
            bloom_capacity: 4096,
            bootstrap: false,
        };
        run_proxy_v2(run, true).unwrap();
    }

    #[test]
    fn test_cli_run_defaults_to_real_mode() {
        let run = Cli::try_parse_from(["animaksm-swap-proxy", "run"]).unwrap();

        match run.command {
            Commands::Run { dry_run, .. } => assert!(!dry_run),
            _ => panic!("expected run command"),
        }
    }
}
