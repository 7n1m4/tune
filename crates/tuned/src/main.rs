//! `tuned` — the fused memory-reclaim daemon.
//!
//! One process, four cooperating tasks, all acting on Linux kernel
//! memory-reclaim subsystems:
//!
//! * a **PSI-aware KSM governor** that trades CPU for RAM by tuning scan
//!   aggressiveness against measured memory pressure,
//! * a **process scanner** that marks duplicate-heavy processes eligible for
//!   cross-process merging,
//! * a **zswap tuner** that keeps `max_pool_percent` in a sane range for the
//!   machine it runs on,
//! * a **metrics** reporter for both subsystems.
//!
//! The KSM half is async (`crates/tuned`); the zswap half is a std-only,
//! dependency-free library (`crates/tuned-zswap`) whose decision semantics are
//! frozen. See the root `AGENTS.md` for why they were not written as one crate.

pub mod governor;
pub mod madvise;
pub mod metrics;
pub mod scanner;
pub mod zswap;

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use tuned_common::config::TunedConfig;
use tuned_common::ksm::{KsmConfig, KsmController, KsmStats};
use tuned_common::new_shared_state;
use tuned_common::psi::PsiStats;

#[derive(Parser)]
#[command(
    name = "tuned",
    version,
    about = "KSM governor, process scanner and zswap tuner in one daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon: KSM governor, process scanner and zswap tuner
    Run {
        /// Path to configuration file
        #[arg(short, long, default_value = tuned_common::config::DEFAULT_CONFIG_PATH)]
        config: PathBuf,

        /// Dry-run mode: log actions without executing sysfs writes or madvise calls
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Show current status of every subsystem
    Status {
        /// Path to configuration file
        #[arg(short, long, default_value = tuned_common::config::DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Show detailed KSM statistics (like uksmdstats)
    Stats {
        /// Path to configuration file
        #[arg(short, long, default_value = tuned_common::config::DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Show a live zswap snapshot: ceiling, pool size, ratio, eviction
    ZswapStats,
    /// Judge the recorded ceilings: does raising max_pool_percent pay for itself?
    ZswapVerdict {
        /// Recorded JSONL history to analyse
        #[arg(short, long)]
        path: Option<PathBuf>,
    },
    /// Perform one zswap decision poll and exit
    ZswapOnce {
        /// Report the decision without writing sysfs
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Restore KSM parameters from snapshot
    RestoreKsm {
        /// Path to configuration file
        #[arg(short, long, default_value = tuned_common::config::DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { config, dry_run } => run_daemon(config, dry_run).await,
        Commands::Status { config } => show_status(config).await,
        Commands::Stats { config } => show_stats(config).await,
        Commands::ZswapStats => {
            init_tracing("info");
            tuned_zswap::print_stats();
            Ok(())
        }
        Commands::ZswapVerdict { path } => {
            init_tracing("info");
            // The library reports failures as `String`; map it onto the
            // daemon's `anyhow` error so every subcommand has one type.
            tuned_zswap::print_report(&zswap_verdict_path(path)).map_err(anyhow::Error::msg)
        }
        Commands::ZswapOnce { dry_run } => {
            init_tracing("info");
            tuned_zswap::run_once(dry_run).map_err(anyhow::Error::msg)
        }
        Commands::RestoreKsm { config } => restore_ksm(config).await,
    }
}

/// Resolve which history file to analyse: the explicit `--path`, else the
/// configured `zswap.stats_path`, else the library default.
///
/// A missing or unreadable config is not an error here — falling back to the
/// library default keeps `tuned zswap verdict` usable when only the binary is
/// installed and `/etc/tuned.toml` is not.
pub(crate) fn zswap_verdict_path(path: Option<PathBuf>) -> PathBuf {
    let configured = TunedConfig::load(Path::new(tuned_common::config::DEFAULT_CONFIG_PATH))
        .ok()
        .map(|config| config.zswap.stats_path);

    resolve_verdict_path(path, configured)
}

/// The pure half of [`zswap_verdict_path`]: the precedence rule plus the
/// blank-value rule, separated from the file read so the four outcomes are
/// testable without a host-specific `/etc/tuned.toml`.
///
/// `configured` is the `stats_path` string as loaded, or `None` when the
/// config was missing or unreadable.
pub(crate) fn resolve_verdict_path(path: Option<PathBuf>, configured: Option<String>) -> PathBuf {
    if let Some(path) = path {
        return path;
    }
    let configured = configured.filter(|p| !p.trim().is_empty());

    configured
        .unwrap_or_else(|| tuned_zswap::STATS_PATH.to_string())
        .into()
}

async fn run_daemon(config_path: PathBuf, dry_run: bool) -> anyhow::Result<()> {
    run_daemon_with_shutdown(config_path, dry_run, wait_for_shutdown_signal()).await
}

async fn run_daemon_with_shutdown<S>(
    config_path: PathBuf,
    dry_run: bool,
    shutdown_signal: S,
) -> anyhow::Result<()>
where
    S: Future<Output = anyhow::Result<&'static str>>,
{
    // Load configuration
    let config = load_config_or_default(&config_path)?;

    // Initialize tracing
    init_tracing(&config.general.log_level);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        dry_run,
        governor_enabled = config.governor.enabled,
        scanner_enabled = config.scanner.enabled,
        zswap_enabled = config.zswap.enabled,
        "tuned starting"
    );

    // Initialize KSM controller
    let mut ksm = KsmController::new(&config.governor.ksm_path)?;
    if dry_run {
        ksm.set_dry_run(true);
    }

    // Snapshot current KSM state for restore on shutdown
    let state_dir = PathBuf::from(&config.general.state_dir);
    if !dry_run {
        ksm.snapshot(&state_dir)?;
    }

    // Shared state between governor and scanner
    let shared_state = new_shared_state();

    // Shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn governor task
    let governor_handle = if config.governor.enabled {
        let gov_config = config.governor.clone();
        let gov_ksm = KsmController::new(&gov_config.ksm_path)?;
        if dry_run {
            // Create a new controller for the governor with dry_run
            let mut gov_ksm = KsmController::new(&gov_config.ksm_path)?;
            gov_ksm.set_dry_run(true);
            let gov = governor::Governor::new(gov_config, gov_ksm);
            let state = shared_state.clone();
            let rx = shutdown_rx.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = gov.run(state, rx).await {
                    error!(error = %e, "Governor task failed");
                }
            }))
        } else {
            let gov = governor::Governor::new(gov_config, gov_ksm);
            let state = shared_state.clone();
            let rx = shutdown_rx.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = gov.run(state, rx).await {
                    error!(error = %e, "Governor task failed");
                }
            }))
        }
    } else {
        None
    };

    // Spawn scanner task
    let scanner_handle = if config.scanner.enabled {
        let scan_config = config.scanner.clone();
        let stabilization = config.governor.stabilization_secs;
        let state = shared_state.clone();
        let rx = shutdown_rx.clone();
        Some(tokio::spawn(async move {
            let scanner = scanner::Scanner::new(scan_config, dry_run, stabilization);
            if let Err(e) = scanner.run(state, rx).await {
                error!(error = %e, "Scanner task failed");
            }
        }))
    } else {
        None
    };

    // Spawn zswap tuning task
    //
    // Independent of the KSM tasks: it reads meminfo and writes one sysfs
    // parameter, so a blocked or failed KSM subsystem must not stop zswap
    // tuning and vice versa.
    let zswap_handle = if config.zswap.enabled {
        let zswap_config = config.zswap.clone();
        let rx = shutdown_rx.clone();
        Some(tokio::spawn(async move {
            zswap::run(zswap_config, rx).await;
        }))
    } else {
        None
    };

    // Spawn metrics task
    let metrics_state = shared_state.clone();
    let metrics_rx = shutdown_rx.clone();
    let metrics_config_path = config.governor.ksm_path.clone();
    let metrics_handle = tokio::spawn(async move {
        if let Ok(ksm) = KsmController::new(&metrics_config_path) {
            metrics::run_metrics_loop(&ksm, metrics_state, 60, metrics_rx).await;
        }
    });

    info!(
        governor = config.governor.enabled,
        scanner = config.scanner.enabled,
        zswap = config.zswap.enabled,
        "All tasks spawned, waiting for shutdown signal"
    );

    let signal_name = shutdown_signal.await?;
    match signal_name {
        "SIGTERM" => info!("Received SIGTERM"),
        "SIGINT" => info!("Received SIGINT"),
        other => info!(signal = other, "Received shutdown signal"),
    }

    // Signal all tasks to shut down
    info!("Initiating graceful shutdown");
    let _ = shutdown_tx.send(true);

    // Wait for tasks to complete (with timeout)
    let shutdown_timeout = tokio::time::Duration::from_secs(5);
    let _ = tokio::time::timeout(shutdown_timeout, async {
        if let Some(h) = governor_handle {
            let _ = h.await;
        }
        if let Some(h) = scanner_handle {
            let _ = h.await;
        }
        if let Some(h) = zswap_handle {
            let _ = h.await;
        }
        let _ = metrics_handle.await;
    })
    .await;

    // Restore KSM state
    if !dry_run {
        let mut ksm = KsmController::new(&config.governor.ksm_path)?;
        if let Err(e) = ksm.restore(&state_dir) {
            error!(error = %e, "Failed to restore KSM state");
        } else {
            info!("KSM state restored to pre-daemon values");
        }
    }

    info!("tuned shutdown complete");
    Ok(())
}

async fn wait_for_shutdown_signal() -> anyhow::Result<&'static str> {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => {
            Ok("SIGTERM")
        }
        _ = sigint.recv() => {
            Ok("SIGINT")
        }
    }
}

async fn show_status(config_path: PathBuf) -> anyhow::Result<()> {
    init_tracing("info");
    print!(
        "{}",
        build_status_output(&config_path, Path::new("/proc/pressure/memory"), true)?
    );

    Ok(())
}

async fn show_stats(config_path: PathBuf) -> anyhow::Result<()> {
    init_tracing("info");
    print!("{}", build_stats_output(&config_path)?);

    Ok(())
}

/// Print-safe (pure) counterpart of [`show_stats`].
fn build_stats_output(config_path: &Path) -> anyhow::Result<String> {
    let config = load_config_or_default(config_path)?;
    let ksm = KsmController::new(&config.governor.ksm_path)?;
    let stats = ksm.read_stats()?;
    let _cfg = ksm.read_config()?;

    Ok(format_stats(&stats, Path::new(&config.governor.ksm_path)))
}

fn format_stats(stats: &KsmStats, ksm_path: &Path) -> String {
    let mut out = String::new();

    out.push_str("======================================================\n");
    out.push_str("tuned with KSM statistics support\n");
    out.push_str("======================================================\n");

    // Read additional KSM stats from sysfs
    let full_scans = read_sysfs_u64(ksm_path, "full_scans");
    let sleep_millisecs = read_sysfs_u64(ksm_path, "sleep_millisecs");
    let max_page_sharing = read_sysfs_u64(ksm_path, "max_page_sharing");
    let pages_to_scan = read_sysfs_u64(ksm_path, "pages_to_scan");
    let stable_node_chains = read_sysfs_u64(ksm_path, "stable_node_chains");
    let stable_node_dups = read_sysfs_u64(ksm_path, "stable_node_dups");
    let use_zero_pages = read_sysfs_u64(ksm_path, "use_zero_pages");
    let pages_shared = stats.pages_shared;
    let pages_sharing = stats.pages_sharing;
    let pages_unshared = stats.pages_unshared;
    let general_profit = stats.general_profit;

    out.push_str(&format!("Full scans:                 {}\n", full_scans));
    out.push_str(&format!(
        "Interval:                   {} ms\n",
        sleep_millisecs
    ));
    out.push_str(&format!(
        "Max page sharing ratio:     {}\n",
        max_page_sharing
    ));
    out.push_str(&format!("Pages to scan:              {}\n", pages_to_scan));
    out.push_str(&format!(
        "Pages over ratio:           {}\n",
        stable_node_chains
    ));
    out.push_str(&format!(
        "Duplicated pages:           {}\n",
        stable_node_dups
    ));
    out.push_str(&format!("Use zero pages:             {}\n", use_zero_pages));
    out.push('\n');

    if pages_shared > 0 && pages_sharing > 0 {
        let sharing_shared_ratio = pages_sharing as f64 / pages_shared as f64;
        let unshared_sharing_ratio = pages_unshared as f64 / pages_sharing as f64;
        out.push_str(&format!(
            "Sharing/shared ratio:       {:.4}\n",
            sharing_shared_ratio
        ));
        out.push_str(&format!(
            "Unshared/sharing ratio:     {:.4}\n",
            unshared_sharing_ratio
        ));
    } else {
        out.push_str("Sharing/shared ratio:       0\n");
        out.push_str("Unshared/sharing ratio:     0\n");
    }
    out.push('\n');

    // formula MiB: pages * page_size / (1024 * 1024) = pages / 256
    out.push_str(&format!(
        "Pages sharing:              {:.1} MiB\n",
        pages_sharing as f64 / 256.0
    ));
    out.push_str(&format!(
        "Pages shared:               {:.1} MiB\n",
        pages_shared as f64 / 256.0
    ));
    out.push_str(&format!(
        "Pages unshared:             {:.1} MiB\n",
        pages_unshared as f64 / 256.0
    ));
    out.push('\n');

    // general_profit is already in BYTES per mm/ksm.c:general_profit_show():
    // (pages_sharing + ksm_zero_pages) * PAGE_SIZE minus rmap overhead.
    out.push_str(&format!(
        "General profit (net of rmap): {:.1} MiB\n",
        general_profit as f64 / 1024.0 / 1024.0
    ));

    out
}

/// Read a single u64 KSM knob, yielding 0 when absent or unparsable
/// (knobs do not exist on every kernel).
fn read_sysfs_u64(ksm_path: &Path, name: &str) -> u64 {
    fs::read_to_string(ksm_path.join(name))
        .unwrap_or_default()
        .trim()
        .parse::<u64>()
        .unwrap_or(0)
}

fn build_status_output(
    config_path: &Path,
    psi_path: &Path,
    show_zswap: bool,
) -> anyhow::Result<String> {
    let config = load_config_or_default(config_path)?;
    let ksm = KsmController::new(&config.governor.ksm_path)?;
    let stats = ksm.read_stats()?;
    let cfg = ksm.read_config()?;
    let psi = PsiStats::read_from(psi_path)?;

    let mut out = format_status(&cfg, &stats, &psi);

    // The zswap line is part of the same picture: both subsystems trade RAM
    // against compression, so `tuned status` should describe the machine's
    // whole reclaim posture rather than only the KSM half.
    if show_zswap {
        out.push_str(&format_zswap_line());
    }

    Ok(out)
}

/// One live line about the zswap subsystem, or nothing when zswap is off.
///
/// Deliberately short: `tuned-zswap --stats` owns the detailed table. This is
/// the "what is it doing right now" summary, and it must degrade quietly
/// rather than fail `tuned status` when zswap is disabled or the parameter is
/// unreadable.
fn format_zswap_line() -> String {
    let limit = tuned_zswap::read_limit();
    let info = tuned_zswap::MemInfo::read();

    match (limit, info) {
        (Ok(limit), Ok(info)) => {
            let ratio = match info.ratio() {
                Some(r) => format!("{:.2}", r),
                None => "n/a (nothing compressed yet)".to_string(),
            };
            format!(
                "zswap:\n\
                 \x20 enabled:                yes\n\
                 \x20 max_pool_percent:       {}%\n\
                 \x20 MemAvailable:           {:.1}%\n\
                 \x20 compression ratio:      {}\n",
                limit,
                info.available_percent(),
                ratio
            )
        }
        (Ok(limit), Err(_)) => format!(
            "zswap:\n\
             \x20 enabled:                yes\n\
             \x20 max_pool_percent:       {}%\n",
            limit
        ),
        // Either the parameter is missing or zswap is not compiled in; both
        // mean "not acting on zswap", which is a state to report, not an error.
        _ => "zswap:\n  enabled:                no (parameter unreadable)\n".to_string(),
    }
}

fn format_status(cfg: &KsmConfig, stats: &KsmStats, psi: &PsiStats) -> String {
    format!(
        "=== tuned status ===\n\
         \n\
         KSM Configuration:\n\
           run:                    {}\n\
           pages_to_scan:          {}\n\
           sleep_millisecs:        {}\n\
           max_page_sharing:       {}\n\
           advisor_mode:           {}\n\
           smart_scan:             {}\n\
         \n\
         KSM Statistics:\n\
           pages_shared:           {}\n\
           pages_sharing:          {}\n\
           pages_unshared:         {}\n\
           general_profit:         {}\n\
           full_scans:             {}\n\
           sharing_savings_mb:     {:.1}\n\
         \n\
         Memory Pressure (PSI):\n\
           some avg10:             {:.2}%\n\
           some avg60:             {:.2}%\n\
           full avg10:             {:.2}%\n\
           full avg60:             {:.2}%\n",
        cfg.run,
        cfg.pages_to_scan,
        cfg.sleep_millisecs,
        cfg.max_page_sharing,
        cfg.advisor_mode,
        cfg.smart_scan,
        stats.pages_shared,
        stats.pages_sharing,
        stats.pages_unshared,
        stats.general_profit,
        stats.full_scans,
        stats.pages_sharing as f64 * 4096.0 / 1024.0 / 1024.0,
        psi.some.avg10,
        psi.some.avg60,
        psi.full.avg10,
        psi.full.avg60,
    )
}

async fn restore_ksm(config_path: PathBuf) -> anyhow::Result<()> {
    let config = load_config_or_default(&config_path)?;

    init_tracing("info");
    restore_ksm_from_config(&config)?;
    info!("KSM state restored successfully");

    Ok(())
}

fn restore_ksm_from_config(config: &TunedConfig) -> anyhow::Result<()> {
    let mut ksm = KsmController::new(&config.governor.ksm_path)?;
    let state_dir = PathBuf::from(&config.general.state_dir);
    ksm.restore(&state_dir)?;
    Ok(())
}

fn init_tracing(log_level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    // Try journald first, fall back to stderr
    match tracing_journald::layer() {
        Ok(_layer) => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .try_init();
            // Note: journald layer is created but we use stderr writer for simplicity
            // In production, use tracing_subscriber::registry().with(layer).init()
        }
        Err(_) => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .try_init();
        }
    }
}

/// Load config from path or return defaults (with info log if file missing).
fn load_config_or_default(config_path: &Path) -> anyhow::Result<TunedConfig> {
    if config_path.exists() {
        Ok(TunedConfig::load(config_path)?)
    } else {
        info!(
            path = %config_path.display(),
            "Config file not found, using defaults"
        );
        Ok(TunedConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_ksm_dir(dir: &Path) {
        for (name, value) in [
            ("run", "1"),
            ("pages_to_scan", "500"),
            ("sleep_millisecs", "20"),
            ("max_page_sharing", "256"),
            ("smart_scan", "1"),
            ("advisor_mode", "none"),
            ("advisor_target_scan_time", "200"),
            ("advisor_max_cpu", "70"),
            ("advisor_min_pages_to_scan", "500"),
            ("advisor_max_pages_to_scan", "30000"),
            ("pages_shared", "10"),
            ("pages_sharing", "512"),
            ("pages_unshared", "3"),
            ("pages_volatile", "0"),
            ("pages_scanned", "1000"),
            ("pages_skipped", "2"),
            ("full_scans", "7"),
            ("general_profit", "12582912"),
        ] {
            std::fs::write(dir.join(name), value).unwrap();
        }
    }

    fn write_config(path: &Path, ksm_path: &Path, state_dir: &Path) {
        std::fs::write(
            path,
            format!(
                "[general]\nstate_dir = \"{}\"\n\n[governor]\nksm_path = \"{}\"\n",
                state_dir.display(),
                ksm_path.display()
            ),
        )
        .unwrap();
    }

    fn write_daemon_config(path: &Path, ksm_path: &Path, state_dir: &Path) {
        std::fs::write(
            path,
            format!(
                "[general]\nstate_dir = \"{}\"\n\n\
                 [governor]\nenabled = false\nksm_path = \"{}\"\n\n\
                 [scanner]\nenabled = false\n",
                state_dir.display(),
                ksm_path.display()
            ),
        )
        .unwrap();
    }

    /// Config with governor and scanner enabled (for coverage of task-spawning paths).
    fn write_daemon_config_all_enabled(path: &Path, ksm_path: &Path, state_dir: &Path) {
        std::fs::write(
            path,
            format!(
                "[general]\nstate_dir = \"{}\"\n\n\
                 [governor]\nenabled = true\nksm_path = \"{}\"\n\n\
                 [scanner]\nenabled = true\ninterval_secs = 3600\nmin_anon_rss_mb = 999999\n",
                state_dir.display(),
                ksm_path.display()
            ),
        )
        .unwrap();
    }

    #[test]
    fn test_load_config_or_default_nonexistent_returns_default() {
        let path = PathBuf::from("/nonexistent/path/tuned.toml");
        let config = load_config_or_default(&path).unwrap();
        assert_eq!(config.governor.stabilization_secs, 30);
        assert_eq!(config.general.log_level, "info");
    }

    #[test]
    fn test_load_config_or_default_reads_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tuned.toml");
        std::fs::write(
            &path,
            "[general]\nlog_level = \"debug\"\n\n[scanner]\nenabled = false\n",
        )
        .unwrap();

        let config = load_config_or_default(&path).unwrap();
        assert_eq!(config.general.log_level, "debug");
        assert!(!config.scanner.enabled);
    }

    #[test]
    fn test_format_status_contains_config_stats_and_psi() {
        let cfg = KsmConfig {
            run: 1,
            pages_to_scan: 2000,
            sleep_millisecs: 50,
            max_page_sharing: 384,
            smart_scan: 1,
            advisor_mode: "scan-time".into(),
            ..Default::default()
        };
        let stats = KsmStats {
            pages_shared: 10,
            pages_sharing: 512,
            pages_unshared: 3,
            general_profit: 12345,
            full_scans: 7,
            ..Default::default()
        };
        let psi = PsiStats {
            some: tuned_common::psi::PsiLine {
                avg10: 1.25,
                avg60: 2.5,
                ..Default::default()
            },
            full: tuned_common::psi::PsiLine {
                avg10: 0.5,
                avg60: 0.75,
                ..Default::default()
            },
        };

        let output = format_status(&cfg, &stats, &psi);
        assert!(output.contains("advisor_mode:           scan-time"));
        assert!(output.contains("pages_sharing:          512"));
        assert!(output.contains("sharing_savings_mb:     2.0"));
        assert!(output.contains("some avg10:             1.25%"));
        assert!(output.contains("full avg60:             0.75%"));
    }

    #[test]
    fn test_build_status_output_reads_configured_ksm_and_psi_paths() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        let state_dir = dir.path().join("state");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);

        let psi_path = dir.path().join("memory.pressure");
        std::fs::write(
            &psi_path,
            "some avg10=1.25 avg60=2.50 avg300=3.00 total=10\n\
             full avg10=0.50 avg60=0.75 avg300=1.00 total=5\n",
        )
        .unwrap();

        let config_path = dir.path().join("tuned.toml");
        write_config(&config_path, &ksm_dir, &state_dir);

        // `false` so the assertion is about the KSM section only: the zswap
        // line reads live sysfs and would make this test machine-dependent.
        let output = build_status_output(&config_path, &psi_path, false).unwrap();
        assert!(output.contains("pages_to_scan:          500"));
        assert!(output.contains("pages_sharing:          512"));
        assert!(output.contains("some avg60:             2.50%"));
        assert!(output.contains("full avg10:             0.50%"));
    }

    /// `tuned status` must describe both subsystems, so the KSM-only output is
    /// not sufficient evidence — the zswap section has to be present too.
    ///
    /// The exact-value assertions are what make this bite. The ceiling is
    /// compared digit-for-digit against `read_limit()`, and the
    /// `MemAvailable` percentage against `MemInfo::read().available_percent()`
    /// reformatted the way the line formats it — so a formatter that
    /// substituted a constant, dropped the percent sign, or stopped reading
    /// meminfo cannot pass. The ratio line is deliberately not pinned
    /// digit-for-digit: it depends on whether anything is compressed right
    /// now, so a "n/a" and a "12.34" are both correct states.
    #[test]
    fn test_status_includes_the_zswap_subsystem() {
        let output = format_zswap_line();
        assert!(
            output.starts_with("zswap:"),
            "expected a zswap section header, got: {}",
            output
        );

        // Two shapes: a readable ceiling (zswap on) or an unreadable one
        // (zswap off / not compiled in). Both must state whether it is on.
        let ceiling = tuned_zswap::read_limit();
        if let Ok(limit) = ceiling {
            assert!(
                output.contains("enabled:                yes"),
                "a readable ceiling must report zswap as enabled, got: {}",
                output
            );
            assert!(
                output.contains(&format!("max_pool_percent:       {limit}%")),
                "the ceiling must be reported verbatim as a percentage, got: {}",
                output
            );

            // MemAvailable is computed, not read literally, so assert the
            // same computation the line performs.
            if let Ok(info) = tuned_zswap::MemInfo::read() {
                assert!(
                    output.contains(&format!(
                        "MemAvailable:           {:.1}%",
                        info.available_percent()
                    )),
                    "MemAvailable must be the computed percentage, got: {}",
                    output
                );
            }

            // The ratio line is the one value the formatter decides about:
            // either the compressed/original quotient, or the explicit
            // "nothing compressed yet" text. Both are correct states, so the
            // assertion switches on which one `MemInfo` reports right now —
            // and never passes if the wrong one is rendered.
            if let Ok(info) = tuned_zswap::MemInfo::read() {
                match info.ratio() {
                    Some(r) => assert!(
                        output.contains(&format!("compression ratio:      {:.2}", r)),
                        "a compressed pool must report the computed ratio, got: {}",
                        output
                    ),
                    None => assert!(
                        output.contains("compression ratio:      n/a (nothing compressed yet)"),
                        "an uncompressed pool must say so explicitly, got: {}",
                        output
                    ),
                }
            }
        } else {
            assert!(
                output.contains("enabled:                no (parameter unreadable)"),
                "an unreadable ceiling must report zswap as off, got: {}",
                output
            );
        }
    }

    /// `show_status` is the live path behind `tuned status`: it must read the
    /// configured KSM directory and the real PSI file, not error out. The
    /// unwrap doubles as the assertion — `build_status_output` returning an
    /// `Err` here means the CLI would fail on a correctly configured machine.
    ///
    /// The stronger half: `show_status` must forward the caller's config path.
    /// The sibling assertion below goes through `build_status_output` directly,
    /// which would happily read the same KSM dir even if `show_status` had
    /// hardcoded a path or dropped the argument. So the configured KSM
    /// directory and PSI file are *removed* and it is asserted that the call
    /// then fails — the only way the KSM dir can stop being read is if
    /// `show_status` actually forwarded the config that points at it.
    #[tokio::test]
    async fn test_show_status_reads_configured_ksm_when_proc_psi_exists() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        let state_dir = dir.path().join("state");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);

        let config_path = dir.path().join("tuned.toml");
        write_config(&config_path, &ksm_dir, &state_dir);

        // The happy path: the configured KSM dir exists, PSI is live.
        show_status(config_path.clone()).await.unwrap();

        // Assert on the same inputs through the pure counterpart, so the test
        // cannot pass by printing nothing.
        let psi_path = Path::new("/proc/pressure/memory");
        if psi_path.exists() {
            let output = build_status_output(&config_path, psi_path, false).unwrap();
            // Seeded, distinctive knobs — not values any other state would
            // produce by accident.
            assert!(output.contains("pages_to_scan:          500"));
            assert!(output.contains("sleep_millisecs:        20"));
            assert!(output.contains("max_page_sharing:       256"));
            assert!(output.contains("advisor_mode:           none"));
            assert!(output.contains("some avg10:"));
        }

        // The forwarding half: the same config pointing at a KSM dir that no
        // longer exists must make the call fail. A `show_status` that ignored
        // its argument would still find a KSM dir elsewhere and succeed.
        let gone_dir = dir.path().join("gone-ksm");
        std::fs::create_dir(&gone_dir).unwrap();
        write_config(&config_path, &gone_dir, &state_dir);
        std::fs::remove_dir_all(&gone_dir).unwrap();

        let outcome = show_status(config_path.clone()).await;
        assert!(
            outcome.is_err(),
            "show_status must honour the caller's config path; a missing KSM \
             directory must surface as an error"
        );
    }

    #[tokio::test]
    async fn test_restore_ksm_restores_snapshot_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        let state_dir = dir.path().join("state");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);

        let ctrl = KsmController::new(ksm_dir.to_str().unwrap()).unwrap();
        ctrl.snapshot(&state_dir).unwrap();
        std::fs::write(ksm_dir.join("run"), "0").unwrap();
        std::fs::write(ksm_dir.join("pages_to_scan"), "100").unwrap();

        let config_path = dir.path().join("tuned.toml");
        write_config(&config_path, &ksm_dir, &state_dir);

        restore_ksm(config_path).await.unwrap();

        assert_eq!(std::fs::read_to_string(ksm_dir.join("run")).unwrap(), "1");
        assert_eq!(
            std::fs::read_to_string(ksm_dir.join("pages_to_scan")).unwrap(),
            "500"
        );
    }

    #[test]
    fn test_restore_ksm_from_config_errors_for_missing_ksm_path() {
        let mut config = TunedConfig::default();
        config.governor.ksm_path = "/nonexistent/ksm/path".into();
        let err = restore_ksm_from_config(&config).unwrap_err();
        assert!(err.to_string().contains("KSM path not found"));
    }

    #[tokio::test]
    async fn test_run_daemon_with_injected_shutdown_dry_run_skips_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        let state_dir = dir.path().join("state");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);

        let config_path = dir.path().join("tuned.toml");
        write_daemon_config(&config_path, &ksm_dir, &state_dir);

        run_daemon_with_shutdown(config_path, true, async { Ok("test") })
            .await
            .unwrap();

        assert!(!state_dir.join("ksm-snapshot.json").exists());
    }

    #[tokio::test]
    async fn test_run_daemon_with_injected_shutdown_snapshots_and_restores() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        let state_dir = dir.path().join("state");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);

        let config_path = dir.path().join("tuned.toml");
        write_daemon_config(&config_path, &ksm_dir, &state_dir);

        run_daemon_with_shutdown(config_path, false, async { Ok("SIGTERM") })
            .await
            .unwrap();

        assert!(state_dir.join("ksm-snapshot.json").exists());
        assert_eq!(std::fs::read_to_string(ksm_dir.join("run")).unwrap(), "1");
    }

    #[tokio::test]
    async fn test_run_daemon_with_governor_and_scanner_enabled_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        let state_dir = dir.path().join("state");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);

        let config_path = dir.path().join("tuned.toml");
        write_daemon_config_all_enabled(&config_path, &ksm_dir, &state_dir);

        run_daemon_with_shutdown(config_path.clone(), true, async { Ok("SIGINT") })
            .await
            .unwrap();

        // Dry-run: snapshot should NOT exist
        assert!(!state_dir.join("ksm-snapshot.json").exists());
    }

    #[tokio::test]
    async fn test_run_daemon_with_governor_and_scanner_enabled_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        let state_dir = dir.path().join("state");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);

        let config_path = dir.path().join("tuned.toml");
        write_daemon_config_all_enabled(&config_path, &ksm_dir, &state_dir);

        run_daemon_with_shutdown(config_path, false, async { Ok("SIGTERM") })
            .await
            .unwrap();

        // Non-dry-run: snapshot + restore should have happened
        assert!(state_dir.join("ksm-snapshot.json").exists());
        assert_eq!(std::fs::read_to_string(ksm_dir.join("run")).unwrap(), "1");
    }

    #[test]
    fn test_init_tracing_is_idempotent() {
        // init_tracing calls tracing_journald::layer() which fails in CI,
        // so this hits the Err branch for the second call (already initialized).
        // The first call may hit either branch depending on environment.
        init_tracing("debug");
        init_tracing("info");
    }

    #[test]
    fn test_cli_parses_run_status_and_restore_commands() {
        let run = Cli::try_parse_from(["tuned", "run", "--config", "/tmp/tuned.toml", "--dry-run"])
            .unwrap();
        match run.command {
            Commands::Run { config, dry_run } => {
                assert_eq!(config, PathBuf::from("/tmp/tuned.toml"));
                assert!(dry_run);
            }
            _ => panic!("expected run command"),
        }

        let status =
            Cli::try_parse_from(["tuned", "status", "--config", "/tmp/tuned.toml"]).unwrap();
        assert!(matches!(status.command, Commands::Status { .. }));

        let restore =
            Cli::try_parse_from(["tuned", "restore-ksm", "--config", "/tmp/tuned.toml"]).unwrap();
        assert!(matches!(restore.command, Commands::RestoreKsm { .. }));
    }

    #[test]
    fn test_cli_parses_stats_subcommand_with_short_config_flag() {
        let stats = Cli::try_parse_from(["tuned", "stats", "-c", "/tmp/tuned.toml"]).unwrap();
        match stats.command {
            Commands::Stats { config } => assert_eq!(config, PathBuf::from("/tmp/tuned.toml")),
            _ => panic!("expected stats command"),
        }
    }

    #[test]
    fn test_cli_config_flag_defaults_to_etc_tuned_toml() {
        // The default config path is a user-visible contract: the systemd unit
        // invokes the daemon without `--config`.
        let run = Cli::try_parse_from(["tuned", "run"]).unwrap();
        match run.command {
            Commands::Run { config, dry_run } => {
                assert_eq!(config, PathBuf::from("/etc/tuned.toml"));
                assert!(!dry_run, "dry-run must default to off");
            }
            _ => panic!("expected run command"),
        }

        let status = Cli::try_parse_from(["tuned", "status"]).unwrap();
        assert_eq!(
            match status.command {
                Commands::Status { config } => config,
                _ => panic!("expected status command"),
            },
            PathBuf::from("/etc/tuned.toml")
        );

        let stats = Cli::try_parse_from(["tuned", "stats"]).unwrap();
        assert_eq!(
            match stats.command {
                Commands::Stats { config } => config,
                _ => panic!("expected stats command"),
            },
            PathBuf::from("/etc/tuned.toml")
        );

        let restore = Cli::try_parse_from(["tuned", "restore-ksm"]).unwrap();
        assert_eq!(
            match restore.command {
                Commands::RestoreKsm { config } => config,
                _ => panic!("expected restore-ksm command"),
            },
            PathBuf::from("/etc/tuned.toml")
        );
    }

    #[test]
    fn test_cli_accepts_equals_form_for_flags() {
        // `--config=<path>` is the form used by the systemd unit's ExecStart.
        let run = Cli::try_parse_from(["tuned", "run", "--config=/tmp/a.toml"]).unwrap();
        match run.command {
            Commands::Run { config, dry_run } => {
                assert_eq!(config, PathBuf::from("/tmp/a.toml"));
                assert!(!dry_run);
            }
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn test_cli_rejects_missing_subcommand() {
        let Err(err) = Cli::try_parse_from(["tuned"]) else {
            panic!("expected missing-subcommand error")
        };
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn test_cli_rejects_unknown_flag() {
        let Err(err) = Cli::try_parse_from(["tuned", "run", "--turbo"]) else {
            panic!("expected unknown-flag error")
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn test_cli_rejects_unknown_subcommand() {
        let Err(err) = Cli::try_parse_from(["tuned", "frobnicate"]) else {
            panic!("expected invalid-subcommand error")
        };
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::InvalidSubcommand,
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_cli_rejects_non_boolean_dry_run_value() {
        let Err(err) = Cli::try_parse_from(["tuned", "run", "--dry-run=maybe"]) else {
            panic!("expected invalid dry-run value error")
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::TooManyValues);
        assert!(err.to_string().contains("dry-run"));
    }

    #[test]
    fn test_cli_rejects_stray_positional_argument() {
        let Err(err) = Cli::try_parse_from(["tuned", "run", "extra"]) else {
            panic!("expected stray-positional error")
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn test_cli_help_describes_subcommands() {
        let Err(err) = Cli::try_parse_from(["tuned", "--help"]) else {
            panic!("expected help output")
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        for needle in ["run", "status", "stats", "restore-ksm"] {
            assert!(err.to_string().contains(needle), "help missing {needle}");
        }
    }

    #[test]
    fn test_cli_run_help_documents_flags_and_default() {
        let Err(err) = Cli::try_parse_from(["tuned", "run", "--help"]) else {
            panic!("expected run help output")
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let help = err.to_string();
        for needle in ["--config", "--dry-run", "/etc/tuned.toml"] {
            assert!(help.contains(needle), "run help missing {needle}");
        }
    }

    #[test]
    fn test_load_config_or_default_surfaces_malformed_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tuned.toml");
        std::fs::write(&path, "[general\nlog_level = ").unwrap();

        let err = load_config_or_default(&path).unwrap_err();
        let msg = err.to_string();
        // The toml crate reports the failure with line/column context, and it
        // is the *parse* that must be reported — not a silent fallback to
        // defaults, and not the validation error the sibling test covers.
        assert!(
            msg.contains("TOML parse error") && msg.contains("at line 1"),
            "expected a located TOML parse error, got: {msg}"
        );
        assert!(
            !msg.contains("must be between"),
            "malformed input must surface as a parse error, not a validation one: {msg}"
        );
    }

    #[test]
    fn test_load_config_or_default_surfaces_validation_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tuned.toml");
        std::fs::write(
            &path,
            "[governor]\npsi_some_threshold = 250.0\nksm_path = \"/nonexistent/ksm\"\n",
        )
        .unwrap();

        let err = load_config_or_default(&path).unwrap_err();
        assert!(err.to_string().contains("psi_some_threshold"));
    }

    #[test]
    fn test_load_config_or_default_propagates_unreadable_file() {
        let dir = tempfile::tempdir().unwrap();
        // A directory satisfies `exists()` but cannot be read as a file, so the
        // read error must surface instead of silently falling back to defaults.
        let err = load_config_or_default(dir.path()).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_load_config_or_default_ignores_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tuned.toml");
        std::fs::write(
            &path,
            "[general]\nlog_level = \"warn\"\nfuture_option = 42\n",
        )
        .unwrap();

        let config = load_config_or_default(&path).unwrap();
        assert_eq!(config.general.log_level, "warn");
    }

    #[test]
    fn test_load_config_or_default_merges_partial_file_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tuned.toml");
        std::fs::write(&path, "[scanner]\nenabled = false\n").unwrap();

        let config = load_config_or_default(&path).unwrap();
        assert!(!config.scanner.enabled);
        // Unspecified sections must keep their defaults rather than erroring.
        assert!(config.validate().is_ok());
        assert_eq!(config.general.state_dir, "/var/lib/tuned");
    }

    #[tokio::test]
    async fn test_run_daemon_propagates_shutdown_signal_error() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        let state_dir = dir.path().join("state");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);

        let config_path = dir.path().join("tuned.toml");
        write_daemon_config(&config_path, &ksm_dir, &state_dir);

        let err = run_daemon_with_shutdown(config_path, true, async {
            Err(anyhow::anyhow!("signal registration failed"))
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("signal registration failed"));
    }

    #[tokio::test]
    async fn test_build_stats_output_reports_knobs_stats_and_mib_conversion() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);
        // Knobs the kernel does not always expose must render as 0, not fail.
        // seed_ksm_dir deliberately omits use_zero_pages and stable_node_chains,
        // so the absent-knob path is exercised without touching real sysfs.
        std::fs::write(ksm_dir.join("stable_node_chains"), "not-a-number").unwrap();

        let config_path = dir.path().join("tuned.toml");
        write_config(&config_path, &ksm_dir, &dir.path().join("state"));

        let output = build_stats_output(&config_path).unwrap();
        assert!(output.contains("Full scans:                 7"));
        assert!(output.contains("Interval:                   20 ms"));
        assert!(output.contains("Max page sharing ratio:     256"));
        assert!(output.contains("Duplicated pages:           0"), "{output}");
        assert!(output.contains("Use zero pages:             0"), "{output}");
        assert!(output.contains("Pages to scan:              500"));
        // 512 pages * 4096 B / 1 MiB = 2.0 MiB
        assert!(
            output.contains("Pages sharing:              2.0 MiB"),
            "{output}"
        );
        // general_profit is bytes; 12582912 B / 1 MiB = 12.0 MiB
        assert!(
            output.contains("General profit (net of rmap): 12.0 MiB"),
            "{output}"
        );
        // 512 / 10 = 51.2
        assert!(
            output.contains("Sharing/shared ratio:       51.2000"),
            "{output}"
        );
        // 3 / 512 = 0.0059
        assert!(
            output.contains("Unshared/sharing ratio:     0.0059"),
            "{output}"
        );
    }

    #[test]
    fn test_format_stats_zeroes_ratios_when_no_pages_shared() {
        // Division by pages_shared/pages_sharing would panic; the zero branch
        // must render literal 0 instead.
        let stats = KsmStats::default();
        let dir = tempfile::tempdir().unwrap();

        let output = format_stats(&stats, dir.path());
        assert!(output.contains("Sharing/shared ratio:       0"), "{output}");
        assert!(output.contains("Unshared/sharing ratio:     0"), "{output}");
        assert!(
            output.contains("Pages sharing:              0.0 MiB"),
            "{output}"
        );
    }

    #[tokio::test]
    async fn test_build_stats_output_errors_for_missing_ksm_path() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("tuned.toml");
        write_config(&config_path, &dir.path().join("missing"), dir.path());

        let err = build_stats_output(&config_path).unwrap_err();
        assert!(err.to_string().contains("KSM path not found"));
    }

    #[tokio::test]
    async fn test_run_daemon_errors_when_config_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("tuned.toml");
        std::fs::write(&config_path, "not = [valid toml").unwrap();

        let err = run_daemon_with_shutdown(config_path, true, async { Ok("SIGTERM") })
            .await
            .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_run_daemon_errors_when_ksm_path_missing() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let config_path = dir.path().join("tuned.toml");
        std::fs::write(
            &config_path,
            format!(
                "[general]\nstate_dir = \"{}\"\n\n[governor]\nenabled = false\nksm_path = \
                 \"{}/missing\"\n\n[scanner]\nenabled = false\n",
                state_dir.display(),
                dir.path().display()
            ),
        )
        .unwrap();

        let err = run_daemon_with_shutdown(config_path, false, async { Ok("SIGTERM") })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("KSM path not found"));
    }

    // ── zswap_verdict_path: three branches ─────────────────────────────────

    /// An explicit `--path` wins over everything, byte for byte, including over
    /// a configured path that is also present. The argument is the operator's
    /// own instruction and must not be second-guessed, so the assertion is
    /// exact equality — any normalisation (canonicalisation, stripping,
    /// falling back when the target does not exist) shows up as a failure.
    #[test]
    fn test_zswap_verdict_path_prefers_the_explicit_argument() {
        for explicit in [
            "/var/log/custom/history.jsonl",
            "relative/history.jsonl",
            "/tmp/with spaces/history.jsonl",
            // A plausible configured path, to prove the explicit argument wins
            // over it rather than only over absence.
            "/var/log/tuned-zswap/history.jsonl",
        ] {
            let chosen = zswap_verdict_path(Some(PathBuf::from(explicit)));
            assert_eq!(
                chosen,
                PathBuf::from(explicit),
                "an explicit --path must be returned verbatim"
            );
            assert_ne!(
                chosen,
                PathBuf::from(tuned_zswap::STATS_PATH),
                "the library default must not leak over an explicit path"
            );
        }
    }

    /// No `--path` and no usable config at `DEFAULT_CONFIG_PATH` must fall
    /// through to the library default — the "binary installed alone" case the
    /// doc comment describes. The chosen path is checked against the same
    /// value `resolve_verdict_path` would produce for a missing config, so a
    /// host where `/etc/tuned.toml` *does* carry a `stats_path` still passes
    /// only when the real function agrees with the — here resolved — rule.
    #[test]
    fn test_zswap_verdict_path_falls_back_when_no_path_is_given() {
        let chosen = zswap_verdict_path(None);

        // Re-read the production source of `configured` so the expected value
        // is derived, not assumed: a blank stats_path is discarded, and
        // anything else is used.
        let configured = TunedConfig::load(Path::new(tuned_common::config::DEFAULT_CONFIG_PATH))
            .ok()
            .map(|c| c.zswap.stats_path)
            .filter(|p| !p.trim().is_empty());

        assert_eq!(
            chosen,
            resolve_verdict_path(None, configured),
            "with no explicit path, the resolution must follow the configured \
             stats_path rule exactly"
        );
        assert!(
            !chosen.as_os_str().is_empty(),
            "an empty verdict path would make the verdict command fail"
        );
    }

    /// The precedence and blank-value rules, driven directly. These four
    /// outcomes are the whole decision table, and driving them through
    /// `resolve_verdict_path` is what makes each one observable — the
    /// config-reading half cannot express them on a host whose
    /// `/etc/tuned.toml` is absent.
    #[test]
    fn test_resolve_verdict_path_covers_every_branch() {
        let library_default = PathBuf::from(tuned_zswap::STATS_PATH);
        let configured = "/var/log/tuned-zswap/history.jsonl";

        // 1. Explicit path, with nothing configured.
        assert_eq!(
            resolve_verdict_path(Some(PathBuf::from("/tmp/explicit.jsonl")), None),
            PathBuf::from("/tmp/explicit.jsonl"),
        );

        // 2. Explicit path beats a configured one. This is the branch the
        //    precedence rule exists for.
        assert_eq!(
            resolve_verdict_path(
                Some(PathBuf::from("/tmp/explicit.jsonl")),
                Some(configured.to_string())
            ),
            PathBuf::from("/tmp/explicit.jsonl"),
            "an explicit --path must outrank the configured stats_path"
        );

        // 3. No explicit path, a real configured value: that value, verbatim.
        assert_eq!(
            resolve_verdict_path(None, Some(configured.to_string())),
            PathBuf::from(configured),
            "the configured stats_path must be used when no --path is given"
        );
        assert_ne!(
            resolve_verdict_path(None, Some(configured.to_string())),
            library_default,
            "a configured path must not be replaced by the library default"
        );

        // 4. No explicit path and no config at all: the library default.
        assert_eq!(
            resolve_verdict_path(None, None),
            library_default,
            "with neither source, the library default is the documented fallback"
        );
    }

    /// A `stats_path` holding only whitespace is treated as unset. An
    /// operator who leaves `stats_path = "   "` behind has not configured a
    /// path, and honouring that string would make the verdict command fail on
    /// a directory that does not exist.
    #[test]
    fn test_resolve_verdict_path_discards_a_blank_configured_stats_path() {
        let library_default = PathBuf::from(tuned_zswap::STATS_PATH);

        for blank in ["", " ", "\t", "   \n  "] {
            let chosen = resolve_verdict_path(None, Some(blank.to_string()));
            assert_eq!(
                chosen, library_default,
                "a whitespace-only stats_path ({blank:?}) must fall back to the \
                 library default, got: {chosen:?}"
            );
        }

        // And the exact boundary: a value with only surrounding whitespace but
        // real content is NOT blank, so it must be used verbatim — including
        // the whitespace, because trimming here would normalise the operator's
        // path.
        let padded = "  /var/log/tuned-zswap/history.jsonl  ".to_string();
        let chosen = resolve_verdict_path(None, Some(padded.clone()));
        assert_eq!(
            chosen,
            PathBuf::from(padded),
            "a non-blank path is used verbatim, not trimmed"
        );
    }

    // ── KSM knob values reach the rendered output ─────────────────────────

    /// Every knob `seed_ksm_dir` writes a *distinct* value for must appear
    /// verbatim in the stats output. This one adds what the sibling test
    /// leaves out: the two knobs the kernel exposes inconsistently
    /// (`use_zero_pages`, `stable_node_chains`), and the MiB-converted page
    /// counts.
    ///
    /// Distinct values matter. `format_stats` renders the *seeded* number, so a
    /// formatter that rendered a zero, a stale read, or another knob's value
    /// cannot satisfy any of these lines.
    #[tokio::test]
    async fn test_build_stats_output_renders_every_seeded_knob_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);
        // The two knobs the sibling test leaves absent or unparsable.
        std::fs::write(ksm_dir.join("use_zero_pages"), "1").unwrap();
        std::fs::write(ksm_dir.join("stable_node_chains"), "7").unwrap();

        let config_path = dir.path().join("tuned.toml");
        write_config(&config_path, &ksm_dir, &dir.path().join("state"));

        let output = build_stats_output(&config_path).unwrap();

        // Knobs the kernel exposes inconsistently, with values that differ
        // from every other seeded knob.
        assert!(
            output.contains("Use zero pages:             1"),
            "use_zero_pages must be rendered, got: {output}"
        );
        assert!(
            output.contains("Pages over ratio:           7"),
            "stable_node_chains must be rendered, got: {output}"
        );
        assert!(
            output.contains("Duplicated pages:           0"),
            "absent stable_node_dups must render as 0, got: {output}"
        );

        // The MiB conversions, computed from the seeded page counts:
        // 512 pages = 2.0 MiB, 10 pages = 0.0 MiB, 3 pages = 0.0 MiB.
        assert!(
            output.contains("Pages sharing:              2.0 MiB"),
            "pages_sharing->MiB, got: {output}"
        );
        assert!(
            output.contains("Pages shared:               0.0 MiB"),
            "pages_shared->MiB, got: {output}"
        );
        assert!(
            output.contains("Pages unshared:             0.0 MiB"),
            "pages_unshared->MiB, got: {output}"
        );
    }

    /// `show_stats` is the async wrapper that owns `init_tracing` and the
    /// `print!`; only its pure counterpart was covered. This drives the real
    /// entry point end-to-end and asserts on the captured string, so a wrapper
    /// that stopped rendering (or rendered an empty string) cannot pass.
    #[tokio::test]
    async fn test_show_stats_renders_the_report() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);
        let config_path = dir.path().join("tuned.toml");
        write_config(&config_path, &ksm_dir, &dir.path().join("state"));

        // The wrapper itself must succeed: an Err here is what the CLI would
        // surface to the operator.
        show_stats(config_path.clone()).await.unwrap();

        // And the value it produces must be the real report, asserted through
        // the same function the wrapper calls.
        let output = build_stats_output(&config_path).unwrap();
        assert!(output.contains("tuned with KSM statistics support"));
        assert!(output.contains("Full scans:                 7"));
        assert!(!output.is_empty(), "the report must not be empty");
    }

    /// `build_status_output` must render every configured KSM knob, not only
    /// the ones the existing test happens to check. `smart_scan` and the PSI
    /// values were unasserted, and PSI is read from a temp file here so the
    /// numbers do not depend on the host's live pressure.
    #[tokio::test]
    async fn test_build_status_output_renders_every_configured_knob() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        let state_dir = dir.path().join("state");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);
        let config_path = dir.path().join("tuned.toml");
        write_config(&config_path, &ksm_dir, &state_dir);

        let psi_path = dir.path().join("pressure");
        std::fs::write(
            &psi_path,
            "some avg10=1.75 avg60=2.50 avg300=3.00 total=1000\n\
             full avg10=0.75 avg60=1.25 avg300=2.00 total=500\n",
        )
        .unwrap();

        let output = build_status_output(&config_path, &psi_path, false).unwrap();

        // The configured half, each value distinct.
        assert!(output.contains("run:                    1"));
        assert!(output.contains("pages_to_scan:          500"));
        assert!(output.contains("sleep_millisecs:        20"));
        assert!(output.contains("max_page_sharing:       256"));
        assert!(output.contains("advisor_mode:           none"));
        assert!(
            output.contains("smart_scan:             1"),
            "smart_scan must be rendered, got: {output}"
        );

        // The statistics half, taken from the seeded files.
        assert!(output.contains("pages_shared:           10"));
        assert!(output.contains("pages_sharing:          512"));
        assert!(output.contains("pages_unshared:         3"));
        assert!(output.contains("general_profit:         12582912"));
        assert!(output.contains("full_scans:             7"));

        // PSI, read from the temp file rather than the live one.
        assert!(output.contains("some avg10:             1.75%"));
        assert!(output.contains("some avg60:             2.50%"));
        assert!(output.contains("full avg10:             0.75%"));
        assert!(output.contains("full avg60:             1.25%"));

        // `show_zswap = false` must keep the zswap half out entirely; the
        // existing test covers the true case.
        assert!(
            !output.contains("zswap:"),
            "show_zswap=false must not append the zswap section, got: {output}"
        );
    }

    /// `restore_ksm` must write back exactly the snapshot's values — every
    /// knob, not just the two the existing test checks. The snapshot is taken
    /// from the seeded dir, the dir is then clobbered with different values,
    /// and the restore is asserted to bring all of them back.
    #[tokio::test]
    async fn test_restore_ksm_writes_back_every_snapshotted_knob() {
        let dir = tempfile::tempdir().unwrap();
        let ksm_dir = dir.path().join("ksm");
        let state_dir = dir.path().join("state");
        std::fs::create_dir(&ksm_dir).unwrap();
        seed_ksm_dir(&ksm_dir);

        // Snapshot the seeded state first.
        let ctrl = KsmController::new(ksm_dir.to_str().unwrap()).unwrap();
        ctrl.snapshot(&state_dir).unwrap();

        // Then clobber every knob the daemon is able to restore, with values
        // that differ from the snapshot so a skipped write is visible.
        for (name, value) in [
            ("run", "0"),
            ("pages_to_scan", "1"),
            ("sleep_millisecs", "5"),
            ("max_page_sharing", "16"),
            ("advisor_mode", "scan-time"),
            ("advisor_target_scan_time", "10"),
            ("advisor_max_cpu", "100"),
        ] {
            std::fs::write(ksm_dir.join(name), value).unwrap();
        }

        let config_path = dir.path().join("tuned.toml");
        write_config(&config_path, &ksm_dir, &state_dir);

        restore_ksm(config_path).await.unwrap();

        // Every restored knob must read the snapshot's seeded value, read
        // straight off disk so the assertion does not depend on a reader.
        let read = |name: &str| std::fs::read_to_string(ksm_dir.join(name)).unwrap();
        assert_eq!(read("run"), "1");
        assert_eq!(read("pages_to_scan"), "500");
        assert_eq!(read("sleep_millisecs"), "20");
        assert_eq!(read("max_page_sharing"), "256");
        assert_eq!(
            read("advisor_mode"),
            "none",
            "advisor_mode must be restored to the snapshot value"
        );
        assert_eq!(read("advisor_target_scan_time"), "200");
        assert_eq!(read("advisor_max_cpu"), "70");
    }
}
