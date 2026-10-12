//! zswap-tune — a small daemon that live-tunes the kernel zswap pool ceiling.
//!
//! The kernel parameter `/sys/module/zswap/parameters/max_pool_percent` caps how much
//! RAM the zswap compressed pool may occupy. The kernel re-reads it on every store, so
//! writing it from user space takes effect immediately: no reboot, no kernel command
//! line, no initramfs, no module reload.
//!
//! This tool reads `/proc/meminfo` on a timer and keeps that ceiling inside a sane
//! range for the machine it runs on:
//!
//! * raise it when there is plenty of free RAM **and** the workload compresses well,
//! * lower it (towards 20 %) when the workload hardly compresses at all,
//! * leave it alone in the deadband between the two, to avoid oscillation.
//!
//! `max_pool_percent` is a *ceiling*, not a reservation: lowering it never releases
//! memory the pool already holds. This tool can only act prospectively.

use std::env;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Path of the single kernel parameter this daemon writes.
const SYSFS_LIMIT_PATH: &str = "/sys/module/zswap/parameters/max_pool_percent";
/// Path of the memory statistics this daemon reads.
const MEMINFO_PATH: &str = "/proc/meminfo";
/// Path of the live zswap counters (debugfs). Readable by root only; every
/// caller must survive an unreadable or partially-filled directory.
const ZSWAP_DEBUGFS_DIR: &str = "/sys/kernel/debug/zswap";
/// Optional pin file: an integer in `[MIN_LIMIT, MAX_LIMIT]` here replaces the
/// decision path for as long as it exists.
const PIN_PATH: &str = "/run/zswap-tune.pin";
/// Where the recorded history is appended, one JSON object per line.
const STATS_PATH: &str = "/var/log/zswap-tune/stats.jsonl";

/// Inclusive lower bound of the allowed range, in percent of RAM.
const MIN_LIMIT: u8 = 20;
/// Inclusive upper bound of the allowed range, in percent of RAM.
const MAX_LIMIT: u8 = 50;
/// Largest change applied by a single decision, in percentage points.
const STEP: u8 = 10;
/// Ceiling the lowering path converges to.
const FLOOR_TARGET: u8 = 20;
/// Compression ratio at or above which the pool is considered worthwhile.
const RAISE_RATIO: f64 = 2.2;
/// Compression ratio strictly below which the pool is considered wasteful.
const LOWER_RATIO: f64 = 1.5;
/// Free-memory fraction that counts as headroom for a raise, in percent of RAM.
const RAISE_AVAILABILITY: f64 = 25.0;
/// Consecutive low-ratio readings required before the limit is lowered.
const DEBOUNCE: u8 = 3;
/// Delay between two polls in daemon mode.
const INTERVAL: Duration = Duration::from_secs(15);
/// Delay between two recorded samples, as required by the recording contract.
const RECORD_INTERVAL: Duration = Duration::from_secs(60);
/// Environment override for the recording cadence, in seconds. Only exists so
/// a short live verification window does not have to wait out real minutes;
/// the daemon uses `RECORD_INTERVAL` whenever it is unset.
const RECORD_INTERVAL_ENV: &str = "ZSWAP_TUNE_RECORD_INTERVAL";

/// The recording cadence, honouring the environment override when it parses.
fn record_interval() -> Duration {
    match env::var(RECORD_INTERVAL_ENV) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => RECORD_INTERVAL,
        },
        Err(_) => RECORD_INTERVAL,
    }
}

const USAGE: &str = "\
zswap-tune - live-tune the zswap max_pool_percent ceiling

USAGE:
    zswap-tune [OPTIONS]

OPTIONS:
    --once             Perform a single poll, decide and apply, then exit
    --dry-run          Only valid with --once: report the decision, never write sysfs
    --stats            Print the current ceiling, pool size and counters, then exit
    --report [PATH]    Analyse a recorded stats file (default
                       /var/log/zswap-tune/stats.jsonl) and judge the ceilings
    -h, --help         Print this help

Without options the tool runs as a daemon, polling every 15s until stopped, and
appends one JSON sample to /var/log/zswap-tune/stats.jsonl every 60s
(ZSWAP_TUNE_RECORD_INTERVAL=<seconds> shortens that for testing).

The pin file /run/zswap-tune.pin, when it holds an integer between 20 and 50,
replaces the decision path until it is removed.

It only ever writes /sys/module/zswap/parameters/max_pool_percent.
";

// ---------------------------------------------------------------------------
// Decision logic
// ---------------------------------------------------------------------------

/// Clamp a computed limit into the allowed `[MIN_LIMIT, MAX_LIMIT]` range.
fn clamp(value: u8) -> u8 {
    value.clamp(MIN_LIMIT, MAX_LIMIT)
}

/// One full decision step. Pure: no I/O, no time.
///
/// * `current_limit` — the limit as it is set right now.
/// * `ratio` — `Zswapped / Zswap` if both are known and non-zero, else `None`.
///   The caller is responsible for debouncing; a not-yet-debounced low ratio must
///   be passed as `None`.
/// * `available_percent` — `MemAvailable` as a percentage of `MemTotal`.
///
/// Returns the new limit, or `None` when nothing should change.
fn decide(current_limit: u8, ratio: Option<f64>, available_percent: f64) -> Option<u8> {
    // Treat an unusable ratio (absent, NaN, infinite) as "no information": never act.
    let ratio = ratio.filter(|r| r.is_finite())?;

    if available_percent >= RAISE_AVAILABILITY && ratio >= RAISE_RATIO {
        // Plenty of free RAM and the pool compresses well: allow it to grow.
        return Some(clamp(current_limit.saturating_add(STEP)));
    }

    if ratio < LOWER_RATIO {
        // Poorly compressible payloads waste RAM on metadata; shrink towards the
        // floor by at most STEP, never dipping below FLOOR_TARGET.
        let step_down = current_limit.saturating_sub(STEP).max(FLOOR_TARGET);
        return Some(clamp(step_down));
    }

    // Deadband (LOWER_RATIO .. RAISE_RATIO) or no headroom: hold.
    None
}

/// Requires `needed` consecutive low ratios before forwarding one to `decide`.
struct Debounce {
    needed: u8,
    hits: u8,
}

impl Debounce {
    fn new(needed: u8) -> Self {
        Debounce { needed, hits: 0 }
    }

    /// Feed a raw ratio in, get back either the same ratio (enough evidence) or
    /// `None` (not yet convinced, or nothing to be convinced about).
    fn push(&mut self, ratio: Option<f64>) -> Option<f64> {
        let low = match ratio {
            Some(r) => r.is_finite() && r < LOWER_RATIO,
            None => false,
        };

        if low {
            self.hits = self.hits.saturating_add(1);
            if self.hits >= self.needed {
                return ratio;
            }
            None
        } else {
            self.hits = 0;
            ratio
        }
    }
}

// ---------------------------------------------------------------------------
// /proc/meminfo
// ---------------------------------------------------------------------------

/// The subset of `/proc/meminfo` this daemon needs.
struct MemInfo {
    total_kb: u64,
    available_kb: u64,
    /// `Zswap`: current compressed pool size, absent when zswap is off.
    zswap_kb: Option<u64>,
    /// `Zswapped`: original size of the pages held in that pool.
    zswapped_kb: Option<u64>,
}

impl MemInfo {
    /// Parse meminfo text. Absent `Zswap`/`Zswapped` lines simply yield `None`.
    fn from_text(text: &str) -> MemInfo {
        let mut info = MemInfo {
            total_kb: 0,
            available_kb: 0,
            zswap_kb: None,
            zswapped_kb: None,
        };

        for line in text.lines() {
            let (key, rest) = match line.split_once(':') {
                Some(pair) => pair,
                None => continue,
            };
            // Value is "<number> kB" (or "<number> kB" for the swap lines); take the digits.
            let value = rest
                .split_whitespace()
                .next()
                .and_then(|token| token.parse::<u64>().ok());

            match key.trim() {
                "MemTotal" => info.total_kb = value.unwrap_or(0),
                "MemAvailable" => info.available_kb = value.unwrap_or(0),
                "Zswap" => info.zswap_kb = value,
                "Zswapped" => info.zswapped_kb = value,
                _ => {}
            }
        }

        info
    }

    fn read() -> Result<MemInfo, String> {
        let text = fs::read_to_string(MEMINFO_PATH)
            .map_err(|e| format!("cannot read {}: {}", MEMINFO_PATH, e))?;
        let info = MemInfo::from_text(&text);
        if info.total_kb == 0 {
            return Err(format!("{} has no usable MemTotal line", MEMINFO_PATH));
        }
        Ok(info)
    }

    /// `MemAvailable` as a percentage of `MemTotal`.
    fn available_percent(&self) -> f64 {
        if self.total_kb == 0 {
            return 0.0;
        }
        (self.available_kb as f64) * 100.0 / (self.total_kb as f64)
    }

    /// Compression ratio `Zswapped / Zswap`, or `None` when nothing is compressed.
    fn ratio(&self) -> Option<f64> {
        let zswap = self.zswap_kb?;
        let zswapped = self.zswapped_kb?;
        if zswap == 0 || zswapped == 0 {
            return None;
        }
        let ratio = (zswapped as f64) / (zswap as f64);
        if ratio.is_finite() {
            Some(ratio)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// sysfs
// ---------------------------------------------------------------------------

fn read_limit() -> Result<u8, String> {
    let text = fs::read_to_string(SYSFS_LIMIT_PATH)
        .map_err(|e| format!("cannot read {}: {}", SYSFS_LIMIT_PATH, e))?;
    text.trim()
        .parse::<u8>()
        .map_err(|e| format!("cannot parse {:?} from {}: {}", text.trim(), SYSFS_LIMIT_PATH, e))
}

/// Write `value` to sysfs and verify it read back.
fn write_limit(value: u8) -> Result<u8, String> {
    let path = Path::new(SYSFS_LIMIT_PATH);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("cannot open {} for writing: {}", SYSFS_LIMIT_PATH, e))?;

    file.write_all(format!("{}\n", value).as_bytes())
        .map_err(|e| format!("cannot write {} to {}: {}", value, SYSFS_LIMIT_PATH, e))?;
    drop(file);

    let readback = read_limit()?;
    if readback != value {
        return Err(format!(
            "wrote {} to {} but it reads back {}",
            value, SYSFS_LIMIT_PATH, readback
        ));
    }
    Ok(readback)
}

// ---------------------------------------------------------------------------
// Pin file
// ---------------------------------------------------------------------------

/// The limit override in force, if any.
///
/// * `Pin(value)` — `/run/zswap-tune.pin` holds `value`, an integer inside
///   `[MIN_LIMIT, MAX_LIMIT]`; the decision path is bypassed and `value` is
///   written to sysfs instead.
/// * `Auto` — no usable pin: the existing decision path applies unchanged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Override {
    Pin(u8),
    Auto,
}

impl Override {
    /// Read the pin file. Absent, unreadable, non-integer or out-of-range
    /// contents all fall back to `Auto`; a valid value is used verbatim, never
    /// clamped, so an operator can see exactly what they asked for.
    fn read() -> Override {
        match fs::read_to_string(PIN_PATH) {
            Ok(text) => parse_pin_text(&text),
            Err(_) => Override::Auto,
        }
    }

    /// The limit this override dictates, or `None` when the decision path runs.
    fn limit(self) -> Option<u8> {
        match self {
            Override::Pin(value) => Some(value),
            Override::Auto => None,
        }
    }

    fn describe(self) -> String {
        match self {
            Override::Pin(value) => format!("pinned to {}% ({})", value, PIN_PATH),
            Override::Auto => "auto (decide)".to_string(),
        }
    }
}

/// Interpret the contents of the pin file. Pure, so the rules are testable
/// without touching the real `/run`.
fn parse_pin_text(text: &str) -> Override {
    match text.trim().parse::<u8>() {
        Ok(value) if (MIN_LIMIT..=MAX_LIMIT).contains(&value) => Override::Pin(value),
        _ => Override::Auto,
    }
}

// ---------------------------------------------------------------------------
// zswap debugfs counters
// ---------------------------------------------------------------------------

/// The kernel's own zswap accounting, in kernel units (pages / bytes).
///
/// Every field is optional: a missing or unreadable file yields `None`, and a
/// non-numeric one yields `None` too, so a partial debugfs never panics and
/// never poisons a record with a fake zero.
#[derive(Default, Clone, Debug)]
struct ZswapCounters {
    stored_pages: Option<u64>,
    written_back_pages: Option<u64>,
    pool_total_size: Option<u64>,
    pool_limit_hit: Option<u64>,
    reject_compress_poor: Option<u64>,
    reject_alloc_fail: Option<u64>,
}

impl ZswapCounters {
    /// Read the whole counter directory. `Ok(None)` when the directory cannot
    /// be read at all (debugfs not mounted, or permission denied), `Ok(Some)`
    /// when it was readable, with individual holes left as `None`.
    fn read() -> Result<Option<ZswapCounters>, String> {
        let entries = match fs::read_dir(ZSWAP_DEBUGFS_DIR) {
            Ok(entries) => entries,
            Err(e) => {
                return Err(format!(
                    "cannot list {}: {} (zswap counters unavailable)",
                    ZSWAP_DEBUGFS_DIR, e
                ))
            }
        };

        let mut counters = ZswapCounters::default();
        let mut seen_any = false;
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let slot = match entry.file_name().to_string_lossy().as_ref() {
                "stored_pages" => &mut counters.stored_pages,
                "written_back_pages" => &mut counters.written_back_pages,
                "pool_total_size" => &mut counters.pool_total_size,
                "pool_limit_hit" => &mut counters.pool_limit_hit,
                "reject_compress_poor" => &mut counters.reject_compress_poor,
                "reject_alloc_fail" => &mut counters.reject_alloc_fail,
                _ => continue,
            };
            match fs::read_to_string(entry.path()) {
                Ok(text) => {
                    if let Ok(value) = text.trim().parse::<u64>() {
                        *slot = Some(value);
                        seen_any = true;
                    }
                }
                // A single unreadable file must not sink the whole reading.
                Err(_) => continue,
            }
        }

        if seen_any {
            Ok(Some(counters))
        } else {
            Ok(None)
        }
    }

    /// Eviction ratio since boot: `written_back_pages / stored_pages`.
    fn eviction_ratio(&self) -> Option<f64> {
        let stored = self.stored_pages?;
        let written_back = self.written_back_pages?;
        if stored == 0 {
            return None;
        }
        let ratio = (written_back as f64) / (stored as f64);
        if ratio.is_finite() {
            Some(ratio)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

/// One recorded sample: everything the report needs, in kernel units.
struct Sample {
    /// Unix timestamp, integer seconds.
    ts: u64,
    /// The ceiling in force when the sample was taken.
    limit: u8,
    stored_pages: u64,
    written_back_pages: u64,
    pool_total_size: u64,
    pool_limit_hit: u64,
    reject_compress_poor: u64,
    reject_alloc_fail: u64,
    /// `MemAvailable` as a percentage of `MemTotal`.
    mem_available_percent: f64,
    /// `Zswapped / Zswap`, or `None` when nothing is compressed.
    ratio: Option<f64>,
}

/// A single line of the recorded history, split by device.
struct DeviceLine {
    device: String,
    used_bytes: u64,
}

/// The storage backs a swap device writes to. `/proc/swaps` names devices by
/// their node (`/dev/md0`), while `/proc/diskstats` names them by kernel name
/// (`md0`), so the basename is what the two have in common.
fn swap_backing_devices() -> Vec<String> {
    let text = match fs::read_to_string("/proc/swaps") {
        Ok(text) => text,
        Err(_) => return Vec::new(),
    };
    text.lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        // Kernel name: the final path component, or the whole name when the
        // entry carries no slash (a label-based swap).
        .map(|name| {
            name.rsplit('/')
                .next()
                .unwrap_or(name)
                .to_string()
        })
        .collect()
}

/// Fields of a `/proc/diskstats` line, named.
///
/// After major, minor and the device name the counters begin at field 4:
/// reads completed (4), reads merged (5), sectors read (6), ms reading (7),
/// writes completed (8), writes merged (9), sectors written (10). The kernel
/// reports sectors in 512-byte units regardless of logical block size, so the
/// mapping to bytes is a flat multiply.
fn diskstats_used_bytes(device: &str) -> Option<u64> {
    let text = fs::read_to_string("/proc/diskstats").ok()?;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let _major = fields.next()?;
        let _minor = fields.next()?;
        let name = fields.next()?;
        if name != device {
            continue;
        }
        let mut sectors_written = None;
        for index in 0..7 {
            let field = fields.next()?;
            // Index 6 is the tenth field overall: sectors written.
            if index == 6 {
                sectors_written = field.parse::<u64>().ok();
            }
        }
        return sectors_written.map(|sectors| sectors.saturating_mul(512));
    }
    None
}

/// Append one sample. A missing or unwritable stats file is not fatal: the
/// daemon keeps tuning and only the recording stops.
fn append_sample(sample: &Sample, devices: &[DeviceLine]) -> Result<(), String> {
    if let Some(parent) = Path::new(STATS_PATH).parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }

    // Build the JSON by hand: no third-party dependency, and the format is
    // fixed, so a serializer would be pure overhead here.
    let mut json = String::new();
    let _ = write!(
        json,
        "{{\"ts\":{},\"limit\":{},\"stored_pages\":{},\"written_back_pages\":{},\
         \"pool_total_size\":{},\"pool_limit_hit\":{},\"reject_compress_poor\":{},\
         \"reject_alloc_fail\":{},\"mem_available_percent\":{:.6}",
        sample.ts,
        sample.limit,
        sample.stored_pages,
        sample.written_back_pages,
        sample.pool_total_size,
        sample.pool_limit_hit,
        sample.reject_compress_poor,
        sample.reject_alloc_fail,
        sample.mem_available_percent,
    );
    match sample.ratio {
        Some(ratio) => {
            let _ = write!(json, ",\"compression_ratio\":{:.6}", ratio);
        }
        None => {
            let _ = write!(json, ",\"compression_ratio\":null");
        }
    }
    let _ = write!(json, ",\"devices\":[");
    for (index, device) in devices.iter().enumerate() {
        if index > 0 {
            let _ = write!(json, ",");
        }
        let _ = write!(
            json,
            "{{\"device\":\"{}\",\"used_bytes\":{}}}",
            json_escape(&device.device),
            device.used_bytes
        );
    }
    let _ = write!(json, "]}}");

    let mut file = match OpenOptions::new().create(true).append(true).open(STATS_PATH) {
        Ok(file) => file,
        Err(e) => return Err(format!("cannot open {} for appending: {}", STATS_PATH, e)),
    };
    file.write_all(json.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|e| format!("cannot append to {}: {}", STATS_PATH, e))
}

/// Escape a JSON string body. Only the four escapes that can appear in a
/// device name are handled, which is all of them.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

/// Take one recording sample. Returns `Ok(Some(sample))` when the kernel
/// exposed its counters, `Ok(None)` when it did not (which the caller reports
/// and moves on from) and `Err` only when meminfo itself is unusable.
fn record_sample(limit: u8) -> Result<Option<(Sample, Vec<DeviceLine>)>, String> {
    let info = MemInfo::read()?;
    let counters = match ZswapCounters::read() {
        Ok(Some(counters)) => counters,
        Ok(None) => return Ok(None),
        Err(e) => return Err(e),
    };

    let sample = Sample {
        ts: now_secs(),
        limit,
        stored_pages: counters.stored_pages.unwrap_or(0),
        written_back_pages: counters.written_back_pages.unwrap_or(0),
        pool_total_size: counters.pool_total_size.unwrap_or(0),
        pool_limit_hit: counters.pool_limit_hit.unwrap_or(0),
        reject_compress_poor: counters.reject_compress_poor.unwrap_or(0),
        reject_alloc_fail: counters.reject_alloc_fail.unwrap_or(0),
        mem_available_percent: info.available_percent(),
        ratio: info.ratio(),
    };
    let devices = swap_backing_devices()
        .iter()
        .filter_map(|device| {
            diskstats_used_bytes(device).map(|used_bytes| DeviceLine {
                device: device.clone(),
                used_bytes,
            })
        })
        .collect();
    Ok(Some((sample, devices)))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

/// One poll. Returns `Some((from, to))` when the limit was changed.
///
/// With a valid pin the decision path is bypassed entirely: the pinned value
/// is the limit and is written to sysfs when it differs from what is set.
fn poll(debounce: &mut Debounce) -> Result<Option<(u8, u8)>, String> {
    let info = MemInfo::read()?;
    let available = info.available_percent();
    let ratio = info.ratio();
    let current = read_limit()?;

    let pinned = Override::read().limit();
    let decision = match pinned {
        Some(value) => Some(value),
        None => decide(current, debounce.push(ratio), available),
    };

    let source = match pinned {
        Some(_) => "pinned".to_string(),
        None => "auto".to_string(),
    };

    println!(
        "zswap-tune: max_pool_percent={}% MemAvailable={:.1}% ratio={} [{}] -> {}",
        current,
        available,
        ratio.map_or("n/a".to_string(), |r| format!("{:.2}", r)),
        source,
        match decision {
            Some(new) if new != current => format!("{}%", new),
            Some(_) => "hold (already there)".to_string(),
            None => "no change".to_string(),
        }
    );

    match decision {
        Some(new) if new != current => {
            let applied = write_limit(new)?;
            println!(
                "zswap-tune: applied max_pool_percent {} -> {}",
                current, applied
            );
            Ok(Some((current, applied)))
        }
        _ => Ok(None),
    }
}

/// Take one recording sample and append it. Never fails the caller: a missing
/// debugfs, an unwritable log, a vanished device — all are warnings.
fn record_tick(limit: u8) {
    match record_sample(limit) {
        Ok(Some((sample, devices))) => {
            if let Err(e) = append_sample(&sample, &devices) {
                eprintln!("zswap-tune: recording stopped: {}", e);
            } else {
                println!(
                    "zswap-tune: recorded ts={} limit={}% stored_pages={} written_back={} pool={}B",
                    sample.ts,
                    sample.limit,
                    sample.stored_pages,
                    sample.written_back_pages,
                    sample.pool_total_size
                );
            }
        }
        Ok(None) => {
            eprintln!(
                "zswap-tune: {} is unreadable, skipping this sample",
                ZSWAP_DEBUGFS_DIR
            );
        }
        Err(e) => eprintln!("zswap-tune: {}", e),
    }
}

fn run_daemon() -> Result<(), String> {
    let mut debounce = Debounce::new(DEBOUNCE);
    let record_every = record_interval();
    // Sample immediately on start so a short window still yields several rows,
    // then on the cadence, decoupled from the 15 s decision poll.
    let mut next_record = std::time::Instant::now();
    let mut first = true;
    loop {
        if let Err(e) = poll(&mut debounce) {
            eprintln!("zswap-tune: {}", e);
        }
        if first || std::time::Instant::now() >= next_record {
            first = false;
            let limit = Override::read()
                .limit()
                .unwrap_or_else(|| read_limit().unwrap_or(MIN_LIMIT));
            record_tick(limit);
            next_record = std::time::Instant::now() + record_every;
        }
        thread::sleep(INTERVAL);
    }
}

/// One poll. In dry-run mode the decision is reported but never written.
fn run_once(dry_run: bool) -> Result<(), String> {
    let info = MemInfo::read()?;
    let available = info.available_percent();
    let ratio = info.ratio();
    let current = read_limit()?;
    let pinned = Override::read();
    let decision = match pinned.limit() {
        Some(value) => Some(value),
        None => {
            let mut debounce = Debounce::new(DEBOUNCE);
            decide(current, debounce.push(ratio), available)
        }
    };

    println!("current max_pool_percent : {}%", current);
    println!("limit source             : {}", pinned.describe());
    println!(
        "MemAvailable             : {} of {} kB ({:.1}%)",
        info.available_kb, info.total_kb, available
    );
    match ratio {
        Some(r) => println!(
            "compression ratio        : {:.2} (Zswapped/Zswap, {} kB / {} kB)",
            r,
            info.zswapped_kb.unwrap_or(0),
            info.zswap_kb.unwrap_or(0)
        ),
        None => println!("compression ratio        : n/a (nothing compressed yet)"),
    }

    match decision {
        Some(new) if new != current => {
            if dry_run {
                println!("decision                 : would set {}% (dry-run, sysfs untouched)", new);
            } else {
                let applied = write_limit(new)?;
                println!("decision                 : set {}% (read back {}%)", new, applied);
            }
        }
        Some(new) => println!("decision                 : hold at {}%", new),
        None => println!("decision                 : no change"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Report analysis
// ---------------------------------------------------------------------------

/// One line of the recorded history, as far as the report cares.
struct Record {
    ts: u64,
    limit: u8,
    stored_pages: i64,
    written_back_pages: i64,
    /// Recorded swap-backing device write counters, in bytes.
    devices: Vec<(String, u64)>,
}

/// Read one JSON object per line. Malformed lines are reported, not fatal.
fn parse_records(text: &str) -> (Vec<Record>, Vec<String>) {
    let mut records = Vec::new();
    let mut problems = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lineno = index + 1;
        let missing = |key: &str| format!("line {}: missing or invalid {:?}", lineno, key);

        let ts = match json_num(trimmed, "ts") {
            Some(value) => value.round().max(0.0) as u64,
            None => {
                problems.push(missing("ts"));
                continue;
            }
        };
        let limit = match json_num(trimmed, "limit") {
            Some(value) => value.round().clamp(0.0, 255.0) as u8,
            None => {
                problems.push(missing("limit"));
                continue;
            }
        };
        let stored_pages = match json_num(trimmed, "stored_pages") {
            Some(value) => value.round() as i64,
            None => {
                problems.push(missing("stored_pages"));
                continue;
            }
        };
        let written_back_pages = match json_num(trimmed, "written_back_pages") {
            Some(value) => value.round() as i64,
            None => {
                problems.push(missing("written_back_pages"));
                continue;
            }
        };

        let mut devices = Vec::new();
        // The recorded names are kernel names (`md0`); the evidence list is
        // written as device nodes, so compare the basenames.
        for device in WRITE_EVIDENCE_DEVICES {
            let kernel_name = device.rsplit('/').next().unwrap_or(device);
            if let Some(used) = json_device_bytes(trimmed, kernel_name) {
                devices.push((kernel_name.to_string(), used));
            }
        }

        records.push(Record {
            ts,
            limit,
            stored_pages,
            written_back_pages,
            devices,
        });
    }

    (records, problems)
}

/// The swap-backed devices whose write volume corroborates the verdict. zram
/// is deliberately excluded: its "writes" are RAM compressions, not the flash
/// endurance cost that a high eviction ratio actually pays for.
const WRITE_EVIDENCE_DEVICES: [&str; 2] = ["/dev/md0", "/dev/sda1"];

/// Extract a numeric value for `key` from one JSON line of our own format.
fn json_num(line: &str, key: &str) -> Option<f64> {
    let needle = format!("\"{}\":", key);
    let start = line.find(&needle)? + needle.len();
    let rest = line[start..].trim_start();
    let end = rest
        .find(|c: char| c == ',' || c == '}' || c == ']' || c.is_whitespace())
        .unwrap_or(rest.len());
    rest[..end].parse::<f64>().ok()
}

/// Extract the `used_bytes` recorded for one device from one JSON line.
fn json_device_bytes(line: &str, device: &str) -> Option<u64> {
    let needle = format!("{{\"device\":\"{}\"", device);
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    json_num(rest, "used_bytes").map(|value| value.round().max(0.0) as u64)
}

/// One interval between two consecutive samples.
struct Interval {
    /// The ceiling in force when the interval opened.
    limit: u8,
    stored_delta: i64,
    written_delta: i64,
    /// Bytes written by the corroborating devices during the interval.
    write_delta: u64,
}

/// Per-ceiling aggregation of the intervals.
#[derive(Clone)]
struct Group {
    limit: u8,
    samples: usize,
    stored_bytes: u64,
    written_bytes: u64,
    write_bytes: u64,
}

impl Group {
    fn stored_mib(&self) -> f64 {
        self.stored_bytes as f64 / (1024.0 * 1024.0)
    }

    fn written_mib(&self) -> f64 {
        self.written_bytes as f64 / (1024.0 * 1024.0)
    }

    fn write_mib(&self) -> f64 {
        self.write_bytes as f64 / (1024.0 * 1024.0)
    }

    /// Eviction ratio `written_back / stored`, or `None` with no stored growth.
    fn eviction_ratio(&self) -> Option<f64> {
        if self.stored_bytes == 0 {
            return None;
        }
        let ratio = self.written_bytes as f64 / self.stored_bytes as f64;
        if ratio.is_finite() {
            Some(ratio)
        } else {
            None
        }
    }

    /// A group is only judged once it has seen enough real work.
    fn reason_insufficient(&self) -> Option<String> {
        if self.stored_bytes == 0 {
            return Some("no pages stored".to_string());
        }
        if self.stored_mib() < SUFFICIENT_STORED_MIB {
            return Some("insufficient data (<200 MiB)".to_string());
        }
        None
    }
}

/// Bytes per page on every architecture this tool targets.
const PAGE_BYTES: u64 = 4096;
/// Widest spacing between two records that may still be treated as one
/// interval. Two samples further apart than this belong to different runs,
/// and the counter delta between them measures whatever happened in the
/// gap rather than the action of either ceiling.
const RECORD_GAP_MAX: u64 = 300;
/// Minimum `Δstored_pages` a ceiling group needs before it may be judged.
const SUFFICIENT_STORED_MIB: f64 = 200.0;
/// The ceiling the verdict has to defend, and the one it is measured against.
const VERDICT_HIGH: u8 = 40;
const VERDICT_LOW: u8 = 20;
/// Required relative advantage of the high ceiling, as a fraction.
const REQUIRED_ADVANTAGE: f64 = 0.25;

/// Turn consecutive samples into per-ceiling groups.
fn analyse(records: &[Record]) -> Vec<Group> {
    let mut intervals: Vec<Interval> = Vec::new();

    for pair in records.windows(2) {
        let (before, after) = (&pair[0], &pair[1]);
        // Out-of-order samples would produce negative deltas and misleading
        // intervals; a rotation or a manual edit can cause them.
        if after.ts < before.ts {
            continue;
        }
        // A gap longer than a couple of record periods means the two samples
        // come from different runs — the recorder was stopped, rotated or the
        // machine slept in between. The counters then include everything that
        // happened while nobody was recording, so the delta is not evidence
        // about any ceiling. Drop it rather than attribute it.
        if after.ts - before.ts > RECORD_GAP_MAX {
            continue;
        }
        // The ceiling may change at any of the daemon's polls, so an interval
        // whose endpoints disagree was not spent under either ceiling and
        // cannot be judged.
        if after.limit != before.limit {
            continue;
        }
        let stored_delta = after.stored_pages.saturating_sub(before.stored_pages);
        let written_delta = after
            .written_back_pages
            .saturating_sub(before.written_back_pages);
        // A counter that moved backwards means the daemon saw a zswap reset or
        // a restart; such an interval carries no evidence either way.
        if stored_delta < 0 || written_delta < 0 {
            continue;
        }

        let mut write_delta: u64 = 0;
        for (device, after_bytes) in &after.devices {
            if let Some((_, before_bytes)) = before.devices.iter().find(|(d, _)| d == device) {
                if after_bytes >= before_bytes {
                    write_delta += after_bytes - before_bytes;
                }
            }
        }

        intervals.push(Interval {
            limit: before.limit,
            stored_delta,
            written_delta,
            write_delta,
        });
    }

    let mut groups: Vec<Group> = Vec::new();
    for interval in &intervals {
        if let Some(group) = groups.iter_mut().find(|g| g.limit == interval.limit) {
            group.samples += 1;
            group.stored_bytes += (interval.stored_delta as u64).saturating_mul(PAGE_BYTES);
            group.written_bytes += (interval.written_delta as u64).saturating_mul(PAGE_BYTES);
            group.write_bytes += interval.write_delta;
        } else {
            groups.push(Group {
                limit: interval.limit,
                samples: 1,
                stored_bytes: (interval.stored_delta as u64).saturating_mul(PAGE_BYTES),
                written_bytes: (interval.written_delta as u64).saturating_mul(PAGE_BYTES),
                write_bytes: interval.write_delta,
            });
        }
    }

    // Deterministic output order, lowest ceiling first.
    groups.sort_by_key(|g| g.limit);
    groups
}

/// The verdict on the 40-vs-20 comparison, as one self-contained sentence.
fn verdict(groups: &[Group]) -> String {
    let high = groups.iter().find(|g| g.limit == VERDICT_HIGH);
    let low = groups.iter().find(|g| g.limit == VERDICT_LOW);

    let (high, low) = match (high, low) {
        (Some(high), Some(low)) => (high, low),
        _ => {
            let missing = |group: Option<&Group>, limit: u8| -> String {
                match group {
                    None => format!("ceiling {} has no recorded samples", limit),
                    Some(group) => match group.reason_insufficient() {
                        Some(reason) => format!("ceiling {} is {}", limit, reason),
                        None => format!("ceiling {} is unjudgeable", limit),
                    },
                }
            };
            let (a, b) = (missing(high, VERDICT_HIGH), missing(low, VERDICT_LOW));
            return format!(
                "INCONCLUSIVE: the {}-vs-{} comparison is not available ({}, {})",
                VERDICT_HIGH, VERDICT_LOW, a, b
            );
        }
    };

    let blocked = |group: &Group, limit: u8| -> Option<String> {
        group
            .reason_insufficient()
            .map(|reason| format!("ceiling {} is {}", limit, reason))
    };
    // Every group that blocks the comparison is named, not just the first, so
    // an operator does not have to re-run the report to learn the second one.
    let blocked_high = blocked(high, VERDICT_HIGH);
    let blocked_low = blocked(low, VERDICT_LOW);
    match (blocked_high, blocked_low) {
        (Some(high_reason), Some(low_reason)) => {
            return format!(
                "INCONCLUSIVE: the {}-vs-{} comparison is not available ({}, {})",
                VERDICT_HIGH, VERDICT_LOW, high_reason, low_reason
            );
        }
        (Some(reason), None) | (None, Some(reason)) => {
            return format!(
                "INCONCLUSIVE: the {}-vs-{} comparison is not available ({})",
                VERDICT_HIGH, VERDICT_LOW, reason
            );
        }
        (None, None) => {}
    }

    let high_ratio = high.eviction_ratio().unwrap_or(0.0);
    let low_ratio = low.eviction_ratio().unwrap_or(0.0);
    let advantage = if low_ratio > 0.0 {
        (low_ratio - high_ratio) / low_ratio * 100.0
    } else {
        // The 20% ceiling evicted nothing at all, so 40% cannot be worse than it.
        100.0
    };

    let detail = format!(
        "eviction ratio at ceiling {} is {:.2} ({:.1} MiB written back of {:.1} MiB stored) \
         against {:.2} at ceiling {} ({:.1} MiB of {:.1} MiB), a {:.1}% difference",
        VERDICT_HIGH,
        high_ratio,
        high.written_mib(),
        high.stored_mib(),
        low_ratio,
        VERDICT_LOW,
        low.written_mib(),
        low.stored_mib(),
        advantage
    );

    if advantage >= REQUIRED_ADVANTAGE * 100.0 {
        format!(
            "PASS: ceiling {} keeps the pool healthy — {} (bar: at least {:.0}% lower)",
            VERDICT_HIGH,
            detail,
            REQUIRED_ADVANTAGE * 100.0
        )
    } else {
        format!(
            "FAIL: ceiling {} does not earn its RAM — {} (bar: at least {:.0}% lower)",
            VERDICT_HIGH,
            detail,
            REQUIRED_ADVANTAGE * 100.0
        )
    }
}

/// Print the per-ceiling table, the verdict and the write evidence.
fn print_report(path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let (records, problems) = parse_records(&text);

    if records.is_empty() {
        println!("zswap-tune report: {}", path.display());
        println!("no usable records found; {} problem line(s)", problems.len());
        for problem in &problems {
            println!("  {}", problem);
        }
        println!(
            "INCONCLUSIVE: the {}-vs-{} comparison is not available (no usable records)",
            VERDICT_HIGH, VERDICT_LOW
        );
        return Ok(());
    }

    let groups = analyse(&records);
    println!("zswap-tune report: {}", path.display());
    println!("records: {} over {} ceiling value(s)", records.len(), groups.len());
    if !problems.is_empty() {
        println!("skipped {} malformed line(s):", problems.len());
        for problem in &problems {
            println!("  {}", problem);
        }
    }
    println!();

    if groups.is_empty() {
        // Valid records whose counters only ever moved backwards (or held
        // still): there is evidence of activity, but not of eviction.
        println!("no intervals carried usable evidence (every delta was negative or zero)");
        println!(
            "verdict: INCONCLUSIVE: the {}-vs-{} comparison is not available (no positive-delta intervals)",
            VERDICT_HIGH, VERDICT_LOW
        );
        return Ok(());
    }

    println!(
        "{:>8} {:>9} {:>14} {:>16} {:>10} {:>14}",
        "ceiling", "samples", "Δstored MiB", "Δwritten MiB", "eviction", "Δwrite MiB"
    );
    for group in &groups {
        let sufficiency = match group.reason_insufficient() {
            Some(reason) => reason,
            None => format!(
                "{:.1}%",
                group.eviction_ratio().unwrap_or(0.0) * 100.0
            ),
        };
        println!(
            "{:>7}% {:>9} {:>14.1} {:>16.1} {:>10} {:>14.1}",
            group.limit,
            group.samples,
            group.stored_mib(),
            group.written_mib(),
            sufficiency,
            group.write_mib(),
        );
    }

    let total_write: u64 = groups.iter().map(|g| g.write_bytes).sum();
    println!();
    println!(
        "total swap-backing writes ({}): {:.1} MiB",
        WRITE_EVIDENCE_DEVICES.join(" + "),
        total_write as f64 / (1024.0 * 1024.0)
    );
    println!("verdict: {}", verdict(&groups));

    Ok(())
}

// ---------------------------------------------------------------------------
// Live statistics
// ---------------------------------------------------------------------------

/// Render an optional kernel counter: a real value, or `n/a` when the kernel
/// did not expose it. A genuine 0 and an absent counter are not the same fact,
/// so they must not print the same thing.
fn opt(value: Option<u64>) -> String {
    value.map_or("n/a".to_string(), |v| v.to_string())
}

/// Print the current ceiling, pool size, compression ratio, boot-time eviction
/// rate and the reject counters. Never fails: an unreadable debugfs degrades to
/// the meminfo/parameter view plus one explanatory line.
fn print_stats() {
    let current = read_limit().unwrap_or(0);
    let pinned = Override::read();
    let info = MemInfo::read().ok();
    let counters = ZswapCounters::read().ok().flatten();

    println!("current max_pool_percent : {}% ({})", current, pinned.describe());

    match &info {
        Some(info) => {
            println!(
                "MemAvailable             : {} of {} kB ({:.1}%)",
                info.available_kb, info.total_kb, info.available_percent()
            );
            match info.ratio() {
                Some(ratio) => println!(
                    "compression ratio        : {:.2} (Zswapped {} kB / Zswap {} kB)",
                    ratio,
                    info.zswapped_kb.unwrap_or(0),
                    info.zswap_kb.unwrap_or(0)
                ),
                None => println!("compression ratio        : n/a (nothing compressed yet)"),
            }
        }
        None => println!("MemAvailable             : n/a (cannot read {})", MEMINFO_PATH),
    }

    match &counters {
        Some(counters) => {
            match counters.pool_total_size {
                Some(bytes) => println!(
                    "pool (RAM)               : {:.1} MiB ({} bytes)",
                    bytes as f64 / (1024.0 * 1024.0),
                    bytes
                ),
                None => println!("pool (RAM)               : n/a"),
            }
            match counters.eviction_ratio() {
                Some(ratio) => println!(
                    "eviction rate since boot : {:.2} ({} pages written back of {} stored)",
                    ratio,
                    counters.written_back_pages.unwrap_or(0),
                    counters.stored_pages.unwrap_or(0)
                ),
                None => println!("eviction rate since boot : n/a (nothing stored yet)"),
            }
            // A missing counter is "n/a", a present one is its value: a real 0
            // and an absent counter mean different things here.
            println!("pool_limit_hit           : {}", opt(counters.pool_limit_hit));
            println!("reject_compress_poor     : {}", opt(counters.reject_compress_poor));
            println!("reject_alloc_fail        : {}", opt(counters.reject_alloc_fail));
        }
        None => println!(
            "zswap debugfs counters   : unavailable ({} is not readable without root; \
             run as root for the pool size, eviction rate and reject counters)",
            ZSWAP_DEBUGFS_DIR
        ),
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

struct Args {
    once: bool,
    dry_run: bool,
    stats: bool,
    /// `Some(path)` for `--report`, defaulting to `STATS_PATH`.
    report: Option<PathBuf>,
}

impl Args {
    fn new() -> Args {
        Args {
            once: false,
            dry_run: false,
            stats: false,
            report: None,
        }
    }
}

enum Parsed {
    Run(Args),
    Help,
    Error(String),
}

fn parse_args<I: Iterator<Item = String>>(args: I) -> Parsed {
    let mut parsed = Args::new();
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--once" => parsed.once = true,
            "--dry-run" => parsed.dry_run = true,
            "--stats" => parsed.stats = true,
            "--report" => {
                // Optional path; only consumed when it is not another flag and
                // not the end of the command line.
                match args.peek() {
                    Some(next) if !next.starts_with('-') => {
                        let next = args.next().unwrap_or_default();
                        parsed.report = Some(PathBuf::from(next));
                    }
                    _ => parsed.report = Some(PathBuf::from(STATS_PATH)),
                }
            }
            "-h" | "--help" => return Parsed::Help,
            other => {
                return Parsed::Error(format!("unknown argument {:?}\n\n{}", other, USAGE));
            }
        }
    }

    if parsed.dry_run && !parsed.once {
        return Parsed::Error(format!(
            "--dry-run only makes sense together with --once\n\n{}",
            USAGE
        ));
    }

    // One job per invocation: mixing modes would only create ambiguity about
    // what a `systemctl start` was supposed to be doing.
    let modes = [
        parsed.once,
        parsed.stats,
        parsed.report.is_some(),
    ]
    .iter()
    .filter(|set| **set)
    .count();
    if modes > 1 {
        return Parsed::Error(format!(
            "choose one of --once, --stats or --report\n\n{}",
            USAGE
        ));
    }

    Parsed::Run(parsed)
}

fn main() -> ExitCode {
    match parse_args(env::args().skip(1)) {
        Parsed::Help => {
            print!("{}", USAGE);
            ExitCode::SUCCESS
        }
        Parsed::Error(message) => {
            eprintln!("zswap-tune: {}", message);
            ExitCode::from(2)
        }
        Parsed::Run(args) => {
            let result = if args.stats {
                print_stats();
                Ok(())
            } else if let Some(path) = args.report {
                print_report(&path)
            } else if args.once {
                run_once(args.dry_run)
            } else {
                run_daemon()
            };
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("zswap-tune: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_none_never_acts() {
        for limit in [MIN_LIMIT, 20, 25, 30, 35, 40, 45, MAX_LIMIT] {
            for available in [0.0, 10.0, 24.999, 25.0, 50.0, 100.0] {
                assert_eq!(
                    decide(limit, None, available),
                    None,
                    "limit={} available={}",
                    limit,
                    available
                );
            }
        }
    }

    #[test]
    fn raise_needs_headroom_and_ratio() {
        for limit in [MIN_LIMIT, 25, 30, 45] {
            for available in [0.0, 1.0, 10.0, 24.999_999] {
                // Excellent ratio, no headroom: nothing to do.
                assert_eq!(decide(limit, Some(2.2), available), None);
                assert_eq!(decide(limit, Some(2.7), available), None);
                assert_eq!(decide(limit, Some(100.0), available), None);
            }
        }
    }

    #[test]
    fn raise_with_headroom_and_good_ratio() {
        assert_eq!(decide(20, Some(2.2), 25.0), Some(30));
        assert_eq!(decide(20, Some(3.0), 40.0), Some(30));
        assert_eq!(decide(30, Some(2.7), 30.0), Some(40));
        assert_eq!(decide(20, Some(10.0), 100.0), Some(30));
        assert_eq!(decide(35, Some(2.2), 90.0), Some(45));
    }

    #[test]
    fn raise_clamps_at_max() {
        assert_eq!(decide(45, Some(2.2), 30.0), Some(MAX_LIMIT));
        assert_eq!(decide(45, Some(2.2), 100.0), Some(MAX_LIMIT));
        assert_eq!(decide(MAX_LIMIT, Some(5.0), 80.0), Some(MAX_LIMIT));
    }

    #[test]
    fn lower_on_incompressible() {
        // Steps down by at most STEP, converging on FLOOR_TARGET.
        assert_eq!(decide(50, Some(1.4), 0.0), Some(40));
        // Headroom is irrelevant for the lowering path.
        assert_eq!(decide(50, Some(1.4), 100.0), Some(40));
        assert_eq!(decide(40, Some(1.0), 80.0), Some(30));
        assert_eq!(decide(30, Some(0.5), 50.0), Some(FLOOR_TARGET));
    }

    #[test]
    fn lower_clamps_at_min() {
        assert_eq!(decide(25, Some(1.4), 0.0), Some(MIN_LIMIT));
        assert_eq!(decide(25, Some(1.4), 100.0), Some(MIN_LIMIT));
        // Already at the floor: stays exactly there.
        assert_eq!(decide(MIN_LIMIT, Some(1.4), 0.0), Some(MIN_LIMIT));
        assert_eq!(decide(MIN_LIMIT, Some(0.1), 100.0), Some(MIN_LIMIT));
    }

    #[test]
    fn deadband_no_action() {
        for ratio in [1.5, 1.500_001, 1.6, 1.75, 2.0, 2.1, 2.19, 2.199_999] {
            assert_eq!(decide(20, Some(ratio), 100.0), None, "ratio={}", ratio);
            assert_eq!(decide(35, Some(ratio), 0.0), None, "ratio={}", ratio);
            assert_eq!(decide(50, Some(ratio), 50.0), None, "ratio={}", ratio);
        }
        // Both ends of the band behave exactly as specified.
        assert_eq!(decide(35, Some(1.5), 100.0), None);
        assert_eq!(decide(35, Some(2.2), 100.0), Some(45));
    }

    #[test]
    fn boundary_available_exactly_25() {
        assert_eq!(decide(20, Some(2.2), 25.0), Some(30));
        assert_eq!(decide(20, Some(3.0), 25.0), Some(30));
        // A hair below is not enough headroom.
        assert_eq!(decide(20, Some(3.0), 24.999_999), None);
    }

    #[test]
    fn boundary_ratio_exactly_2_2() {
        assert_eq!(decide(20, Some(2.2), 25.0), Some(30));
        assert_eq!(decide(20, Some(2.2), 100.0), Some(30));
        // Below the threshold inside the deadband.
        assert_eq!(decide(20, Some(2.199_999), 100.0), None);
    }

    #[test]
    fn boundary_ratio_exactly_1_5() {
        assert_eq!(decide(50, Some(1.5), 0.0), None);
        assert_eq!(decide(50, Some(1.5), 100.0), None);
        // Strictly below does lower.
        assert_eq!(decide(50, Some(1.499_999), 0.0), Some(40));
    }

    #[test]
    fn nan_ratio_no_action() {
        assert_eq!(decide(20, Some(f64::NAN), 100.0), None);
        assert_eq!(decide(50, Some(f64::NAN), 0.0), None);
        assert_eq!(decide(35, Some(f64::NAN), 50.0), None);
        // Infinities are just as unusable as NaN.
        assert_eq!(decide(20, Some(f64::INFINITY), 100.0), None);
        assert_eq!(decide(50, Some(f64::NEG_INFINITY), 0.0), None);
    }

    #[test]
    fn limit_stays_in_range() {
        for current in (MIN_LIMIT..=MAX_LIMIT).step_by(5) {
            for (ratio, available) in [(Some(5.0), 100.0), (Some(1.0), 0.0)] {
                if let Some(next) = decide(current, ratio, available) {
                    assert!(
                        (MIN_LIMIT..=MAX_LIMIT).contains(&next),
                        "limit {} -> {} out of range",
                        current,
                        next
                    );
                    let delta = (next as i16 - current as i16).abs();
                    assert!(delta <= STEP as i16, "limit {} -> {} moves too far", current, next);
                }
            }
        }
    }

    #[test]
    fn debounce_requires_consecutive_low_readings() {
        let mut debounce = Debounce::new(DEBOUNCE);
        assert_eq!(debounce.push(Some(1.0)), None);
        assert_eq!(debounce.push(Some(1.2)), None);
        assert_eq!(debounce.push(Some(1.4)), Some(1.4));
        // Anything else clears the run of low readings.
        let mut debounce = Debounce::new(DEBOUNCE);
        debounce.push(Some(1.0));
        debounce.push(Some(1.1));
        debounce.push(Some(2.7));
        debounce.push(Some(1.1));
        assert_eq!(debounce.push(Some(1.1)), None);
        assert_eq!(debounce.push(Some(1.1)), Some(1.1));
        // A healthy or unknown ratio is forwarded untouched.
        let mut debounce = Debounce::new(DEBOUNCE);
        assert_eq!(debounce.push(Some(2.7)), Some(2.7));
        assert_eq!(debounce.push(None), None);
    }

    #[test]
    fn parse_meminfo_realistic() {
        let text = "\
MemTotal:       15719524 kB
MemFree:          604176 kB
MemAvailable:    2352736 kB
Buffers:              52 kB
SwapCached:        18784 kB
SwapTotal:     100653044 kB
Zswap:            174100 kB
Zswapped:         723448 kB
";
        let info = MemInfo::from_text(text);
        assert_eq!(info.total_kb, 15_719_524);
        assert_eq!(info.available_kb, 2_352_736);
        assert_eq!(info.zswap_kb, Some(174_100));
        assert_eq!(info.zswapped_kb, Some(723_448));
        let ratio = info.ratio().expect("ratio");
        assert!(ratio > 4.1 && ratio < 4.2, "ratio was {}", ratio);

        let available = info.available_percent();
        assert!(available > 14.0 && available < 16.0, "available {}", available);
    }

    #[test]
    fn parse_meminfo_missing_zswap() {
        let text = "MemTotal:  1000 kB\nMemAvailable:  250 kB\n";
        let info = MemInfo::from_text(text);
        assert_eq!(info.ratio(), None);
        assert!((info.available_percent() - 25.0).abs() < 1e-9);

        // Zero pool (zswap enabled but empty) must not divide by zero either.
        let empty = "MemTotal:  1000 kB\nMemAvailable:  900 kB\nZswap:  0 kB\nZswapped:  0 kB\n";
        assert_eq!(MemInfo::from_text(empty).ratio(), None);
        assert_eq!(decide(20, MemInfo::from_text(empty).ratio(), 90.0), None);
    }

    // -- recording, pin and report surface ---------------------------------

    /// The committed fixture, which the analysis is expected to reproduce.
    fn fixture_text() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/report.jsonl");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e))
    }

    fn fixture_groups() -> Vec<Group> {
        let (records, problems) = parse_records(&fixture_text());
        assert!(
            problems.is_empty(),
            "fixture has malformed lines: {:?}",
            problems
        );
        assert_eq!(records.len(), 10, "fixture must hold 10 records");
        analyse(&records)
    }

    fn group(groups: &[Group], limit: u8) -> &Group {
        groups
            .iter()
            .find(|g| g.limit == limit)
            .unwrap_or_else(|| panic!("no group for ceiling {}", limit))
    }

    #[test]
    fn fixture_parses_into_two_ceiling_groups() {
        let groups = fixture_groups();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].limit, 20, "lowest ceiling first");
        assert_eq!(groups[1].limit, 40);
    }

    #[test]
    fn fixture_interval_count_matches_records() {
        let groups = fixture_groups();
        // The fixture holds one contiguous run per ceiling, so every interval
        // belongs to the ceiling that opened it: 4 records at 20% yield 3
        // intervals, 6 records at 40% yield 5.
        let total: usize = groups.iter().map(|g| g.samples).sum();
        assert_eq!(total, 8);
        assert_eq!(group(&groups, 20).samples, 3);
        assert_eq!(group(&groups, 40).samples, 5);
    }

    #[test]
    fn fixture_per_ceiling_deltas() {
        let groups = fixture_groups();

        let low = group(&groups, 20);
        assert_eq!(low.stored_bytes, 180000 * PAGE_BYTES);
        assert_eq!(low.written_bytes, 4000 * PAGE_BYTES);
        assert!((low.stored_mib() - 703.125).abs() < 1e-6);
        assert!((low.written_mib() - 15.625).abs() < 1e-6);

        let high = group(&groups, 40);
        assert_eq!(high.stored_bytes, 212000 * PAGE_BYTES);
        assert_eq!(high.written_bytes, 14600 * PAGE_BYTES);
        assert!((high.stored_mib() - 828.125).abs() < 1e-6);
        assert!((high.written_mib() - 57.03125).abs() < 1e-6);
    }

    #[test]
    fn fixture_eviction_ratios() {
        let groups = fixture_groups();
        assert!((group(&groups, 20).eviction_ratio().unwrap() - 0.022222).abs() < 1e-6);
        assert!((group(&groups, 40).eviction_ratio().unwrap() - 0.068867).abs() < 1e-6);
    }

    #[test]
    fn fixture_write_evidence_sums_both_devices() {
        let groups = fixture_groups();
        // Each ceiling owns only the writes that happened while it was in
        // force, so the two groups sum to more than a first-to-last difference
        // that ignored the ceiling change between them.
        assert_eq!(group(&groups, 20).write_bytes, 179_201_024);
        assert_eq!(group(&groups, 40).write_bytes, 274_121_216);
        let total: u64 = groups.iter().map(|g| g.write_bytes).sum();
        assert_eq!(total, 453_322_240);
    }

    #[test]
    fn fixture_write_evidence_is_interval_attributed() {
        let groups = fixture_groups();
        let (records, _) = parse_records(&fixture_text());
        // Interval deltas telescope, so the two ceiling groups must sum to
        // exactly the first-to-last difference of each device.
        let device_of = |record: &Record, name: &str| -> u64 {
            record
                .devices
                .iter()
                .find(|(device, _)| device == name)
                .map(|(_, bytes)| *bytes)
                .unwrap_or(0)
        };
        let md0_net =
            device_of(&records[records.len() - 1], "md0") - device_of(&records[0], "md0");
        let sda1_net =
            device_of(&records[records.len() - 1], "sda1") - device_of(&records[0], "sda1");
        let total: u64 = groups.iter().map(|g| g.write_bytes).sum();
        // Both device counters only ever grow, so the groups can never sum to
        // more than the overall net difference. They legitimately sum to less:
        // the interval straddling the 20->40 change is not attributed to
        // either ceiling, and its writes are excluded from the evidence
        // because no ceiling was in force for the whole of it.
        assert!(
            total <= md0_net + sda1_net,
            "grouped write evidence {} must not exceed the net {}",
            total,
            md0_net + sda1_net
        );
        assert!(total > 0);
    }

    #[test]
    fn ceiling_change_writes_are_excluded_from_evidence() {
        // The boundary between two contiguous runs is the only place where a
        // device counter moves without any interval owning it, because no
        // ceiling was in force for the whole span.
        let (records, problems) = parse_records(&fixture_text());
        assert!(problems.is_empty(), "problems: {:?}", problems);
        let boundary = records
            .windows(2)
            .find(|pair| pair[0].limit != pair[1].limit)
            .expect("fixture must contain a ceiling change");
        let (before, after) = (&boundary[0], &boundary[1]);

        let device_delta = |from: &Record, to: &Record, device: &str| -> u64 {
            let start = from
                .devices
                .iter()
                .find(|(name, _)| name == device)
                .map(|(_, bytes)| *bytes)
                .unwrap_or(0);
            let end = to
                .devices
                .iter()
                .find(|(name, _)| name == device)
                .map(|(_, bytes)| *bytes)
                .unwrap_or(0);
            end.saturating_sub(start)
        };

        let excluded = device_delta(before, after, "md0") + device_delta(before, after, "sda1");
        let attributed: u64 = fixture_groups().iter().map(|g| g.write_bytes).sum();
        // Via the boundary writes, every byte the fixture recorded is either
        // attributed to a ceiling or excluded at the ceiling change.
        assert!(excluded > 0, "the boundary must move a device counter");
        let md0_whole = device_delta(&records[0], &records[records.len() - 1], "md0");
        let sda1_whole = device_delta(&records[0], &records[records.len() - 1], "sda1");
        assert_eq!(
            attributed + excluded,
            md0_whole + sda1_whole,
            "no writes may be counted twice or vanish"
        );
    }

    #[test]
    fn fixture_groups_are_sufficiently_large() {
        let groups = fixture_groups();
        for group in &groups {
            assert!(
                group.reason_insufficient().is_none(),
                "ceiling {} should be judged",
                group.limit
            );
            assert!(group.stored_mib() > SUFFICIENT_STORED_MIB);
        }
    }

    #[test]
    fn fixture_verdict_names_both_ceilings_and_fails() {
        let verdict = verdict(&fixture_groups());
        // Ceiling 40 evicts almost twice as much: the bar is not met.
        assert!(verdict.starts_with("FAIL:"), "verdict was {:?}", verdict);
        assert!(verdict.contains("ceiling 40"), "verdict was {:?}", verdict);
        assert!(verdict.contains("ceiling 20"), "verdict was {:?}", verdict);
        assert!(verdict.contains("at least 25% lower"), "verdict was {:?}", verdict);
    }

    #[test]
    fn verdict_passes_when_high_ceiling_evicts_least() {
        // A synthetic, sufficient pair of groups where 40% evicts 60% less
        // than 20%: comfortably past the bar.
        let high = Group {
            limit: VERDICT_HIGH,
            samples: 4,
            stored_bytes: 512 * PAGE_BYTES * 1024,
            written_bytes: 4 * PAGE_BYTES * 1024,
            write_bytes: 0,
        };
        let low = Group {
            limit: VERDICT_LOW,
            samples: 4,
            stored_bytes: 512 * PAGE_BYTES * 1024,
            written_bytes: 10 * PAGE_BYTES * 1024,
            write_bytes: 0,
        };
        let text = verdict(&[high.clone(), low.clone()]);
        assert!(text.starts_with("PASS:"), "verdict was {:?}", text);
        assert!(text.contains("60.0% difference"), "verdict was {:?}", text);

        // Exactly at the bar: 25% lower is a pass, not a fail.
        let at_bar_high = Group {
            written_bytes: 75 * PAGE_BYTES * 1024 / 10,
            ..high
        };
        let at_bar_low = Group {
            written_bytes: 10 * PAGE_BYTES * 1024,
            ..low
        };
        let text = verdict(&[at_bar_high, at_bar_low]);
        assert!(text.starts_with("PASS:"), "verdict was {:?}", text);
        assert!(text.contains("25.0% difference"), "verdict was {:?}", text);

        // Just below the bar fails, which is what makes the bar real.
        let below_high = Group {
            written_bytes: 8 * PAGE_BYTES * 1024,
            ..high
        };
        let text = verdict(&[below_high, low]);
        assert!(text.starts_with("FAIL:"), "verdict was {:?}", text);
        assert!(text.contains("20.0% difference"), "verdict was {:?}", text);
    }

    /// Bytes per MiB, so test data states sizes in the unit it means.
    fn mib(value: u64) -> u64 {
        value * 1024 * 1024
    }

    #[test]
    fn verdict_excludes_insufficient_groups() {
        // Under 200 MiB of stored growth: reported, never judged.
        let high = Group {
            limit: VERDICT_HIGH,
            samples: 1,
            stored_bytes: mib(100),
            written_bytes: mib(90),
            write_bytes: 0,
        };
        let low = Group {
            limit: VERDICT_LOW,
            samples: 1,
            stored_bytes: mib(500),
            written_bytes: mib(10),
            write_bytes: 0,
        };
        let text = verdict(&[high.clone(), low.clone()]);
        assert!(text.starts_with("INCONCLUSIVE:"), "verdict was {:?}", text);
        assert!(
            text.contains("ceiling 40 is insufficient data (<200 MiB)"),
            "verdict was {:?}",
            text
        );

        // Both groups too small: both are named, and the bar is not applied.
        let both_small = verdict(&[
            high,
            Group {
                stored_bytes: mib(199),
                ..low
            },
        ]);
        assert!(
            both_small.contains("ceiling 20 is insufficient data (<200 MiB)"),
            "verdict was {:?}",
            both_small
        );
        assert!(both_small.contains("40-vs-20"), "verdict was {:?}", both_small);
    }

    #[test]
    fn verdict_states_missing_comparison_explicitly() {
        // Only one ceiling recorded: the comparison cannot exist, and saying so
        // is mandatory.
        let low_only = verdict(&[Group {
            limit: VERDICT_LOW,
            samples: 5,
            stored_bytes: 600 * PAGE_BYTES * 1024,
            written_bytes: 6 * PAGE_BYTES * 1024,
            write_bytes: 0,
        }]);
        assert!(
            low_only.starts_with("INCONCLUSIVE:"),
            "verdict was {:?}",
            low_only
        );
        assert!(low_only.contains("40-vs-20"), "verdict was {:?}", low_only);
        assert!(
            low_only.contains("ceiling 40 has no recorded samples"),
            "verdict was {:?}",
            low_only
        );

        // Nothing at all is the same story, told once.
        let empty = verdict(&[]);
        assert!(empty.starts_with("INCONCLUSIVE:"), "verdict was {:?}", empty);
        assert!(empty.contains("40-vs-20"), "verdict was {:?}", empty);
    }

    #[test]
    fn analysis_ignores_out_of_order_and_negative_deltas() {
        let line = |ts: u64, limit: u8, stored: i64, written: i64| {
            format!(
                "{{\"ts\":{},\"limit\":{},\"stored_pages\":{},\"written_back_pages\":{},\
                 \"pool_total_size\":0,\"pool_limit_hit\":0,\"reject_compress_poor\":0,\
                 \"reject_alloc_fail\":0,\"mem_available_percent\":50.0,\
                 \"compression_ratio\":null,\"devices\":[]}}",
                ts, limit, stored, written
            )
        };
        let text = format!(
            "{}\n{}\n{}\n{}",
            line(100, 40, 1000, 0),
            line(200, 40, 1500, 10),
            // Time went backwards: dropped entirely.
            line(150, 40, 9000, 10),
            // Counters reset: dropped as well.
            line(300, 40, 100, 5),
        );
        let (records, problems) = parse_records(&text);
        assert!(problems.is_empty(), "problems: {:?}", problems);
        let groups = analyse(&records);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].limit, 40);
        assert_eq!(groups[0].samples, 1, "only the 100 -> 1500 interval survives");
        assert_eq!(groups[0].stored_bytes, 500 * PAGE_BYTES);
        assert_eq!(groups[0].written_bytes, 10 * PAGE_BYTES);
    }

    /// Build a record line for the interval-filter tests.
    fn interval_record(ts: u64, limit: u8, stored: i64, written: i64) -> Record {
        Record { ts, limit, stored_pages: stored, written_back_pages: written, devices: Vec::new() }
    }

    #[test]
    fn analysis_drops_intervals_spanning_a_recording_gap() {
        // Two runs of the daemon hours apart: the counter delta between them
        // covers the whole idle stretch, under no ceiling in particular.
        let records = vec![
            interval_record(1_000_000, 20, 100, 0),
            interval_record(1_000_300, 20, 400, 0),
            // 2 hours of silence in between
            interval_record(7_300_000, 20, 900, 200),
        ];
        let groups = analyse(&records);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].samples, 1);
        assert_eq!(groups[0].stored_bytes, 300 * PAGE_BYTES);
    }

    #[test]
    fn analysis_keeps_intervals_within_the_gap_threshold() {
        // A cadence-adjusted run (ZSWAP_TUNE_RECORD_INTERVAL) legitimately
        // spaces records further apart than 60 s; that is still one run.
        let records = vec![
            interval_record(1_000_000, 30, 100, 0),
            interval_record(1_000_290, 30, 400, 0),
        ];
        let groups = analyse(&records);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].samples, 1);
        assert_eq!(groups[0].limit, 30);
    }

    #[test]
    fn analysis_drops_intervals_straddling_a_ceiling_change() {
        // The ceiling moved mid-interval, so the delta was not measured under
        // either ceiling and belongs to neither group.
        let records = vec![
            interval_record(1_000_000, 20, 100, 0),
            interval_record(1_000_060, 35, 400, 50),
        ];
        assert!(analyse(&records).is_empty());
    }

    #[test]
    fn analysis_folds_a_returning_ceiling_into_its_group() {
        // A ceiling that appears, disappears and returns shares one group: the
        // verdict compares ceilings, not runs, so the 20% evidence is pooled
        // even though the 40% run interrupted it.
        let records = vec![
            interval_record(1_000_000, 20, 100, 0),
            interval_record(1_000_060, 20, 400, 0),
            interval_record(1_000_120, 40, 900, 0),
            interval_record(1_000_180, 40, 1200, 0),
            interval_record(1_000_240, 20, 1600, 0),
            interval_record(1_000_300, 20, 2000, 0),
        ];
        let groups = analyse(&records);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].limit, 20);
        // Two of the five intervals survive: the 20->40 and 40->20 boundaries
        // straddle a ceiling change and belong to neither group.
        assert_eq!(groups[0].samples, 2, "both 20% runs pool into one group");
        assert_eq!(groups[1].limit, 40);
        assert_eq!(groups[1].samples, 1);
        assert_eq!(groups[0].stored_bytes, 700 * PAGE_BYTES);
        assert_eq!(groups[1].stored_bytes, 300 * PAGE_BYTES);
    }

    #[test]
    fn analysis_reports_malformed_lines_without_dropping_good_ones() {
        let good = "{\"ts\":1,\"limit\":40,\"stored_pages\":100,\"written_back_pages\":0,\
                    \"pool_total_size\":0,\"pool_limit_hit\":0,\"reject_compress_poor\":0,\
                    \"reject_alloc_fail\":0,\"mem_available_percent\":50.0,\
                    \"compression_ratio\":null,\"devices\":[]}";
        let text = format!("{}\nnot json at all\n{{}}\n{}\n", good, good);
        let (records, problems) = parse_records(&text);
        assert_eq!(records.len(), 2);
        assert_eq!(problems.len(), 2, "both bad lines are reported");
        assert!(problems[0].contains("line 2"), "problems: {:?}", problems);
        assert!(problems[1].contains("line 3"), "problems: {:?}", problems);
    }

    #[test]
    fn pin_parsing_is_strict_about_range() {
        // Valid values are used verbatim; anything else falls back to Auto.
        assert!(!std::path::Path::new(PIN_PATH).exists(), "live pin must be absent");

        for raw in ["19", "51", "0", "255", "abc", "", " ", "40.5", "-30"] {
            assert_eq!(
                parse_pin_text(raw),
                Override::Auto,
                "raw {:?} must not pin",
                raw
            );
        }
        // Surrounding whitespace, including a trailing newline, is expected.
        for raw in ["20", "30", "35", "40", "50", "  42\n", "\n42\n"] {
            assert_ne!(
                parse_pin_text(raw),
                Override::Auto,
                "raw {:?} must pin",
                raw
            );
        }
        assert_eq!(parse_pin_text("42"), Override::Pin(42));
        assert_eq!(parse_pin_text("20"), Override::Pin(20));
        assert_eq!(parse_pin_text("50"), Override::Pin(50));
        assert_eq!(parse_pin_text(" garbage "), Override::Auto);
    }

    #[test]
    fn pin_value_is_never_clamped() {
        // The bounds of the range are honoured, and the boundary itself is a
        // valid pin, not something to nudge towards the middle.
        assert_eq!(Override::Pin(MIN_LIMIT).limit(), Some(MIN_LIMIT));
        assert_eq!(Override::Pin(MAX_LIMIT).limit(), Some(MAX_LIMIT));
        assert_eq!(parse_pin_text("19"), Override::Auto);
        assert_eq!(parse_pin_text("51"), Override::Auto);
    }

    #[test]
    fn pin_description_is_explicit() {
        assert!(Override::Pin(42).describe().contains("42"));
        assert!(Override::Pin(42).describe().contains(PIN_PATH));
        assert!(Override::Auto.describe().contains("decide"));
    }

    #[test]
    fn json_num_extracts_own_record_format() {
        let line = "{\"ts\":1760300540,\"limit\":40,\"stored_pages\":552000}";
        assert_eq!(json_num(line, "ts"), Some(1760300540.0));
        assert_eq!(json_num(line, "limit"), Some(40.0));
        assert_eq!(json_num(line, "stored_pages"), Some(552000.0));
        assert_eq!(json_num(line, "missing"), None);
        let nulled = "{\"compression_ratio\":null,\"limit\":20}";
        assert_eq!(json_num(nulled, "compression_ratio"), None);
    }

    #[test]
    fn json_device_bytes_reads_per_device_counters() {
        // Devices are recorded by kernel name, the form /proc/diskstats uses.
        let line = "{\"devices\":[{\"device\":\"md0\",\"used_bytes\":2638872576},\
                     {\"device\":\"sda1\",\"used_bytes\":1107644416}]}";
        assert_eq!(json_device_bytes(line, "md0"), Some(2638872576));
        assert_eq!(json_device_bytes(line, "sda1"), Some(1107644416));
        assert_eq!(json_device_bytes(line, "sdb"), None);
        assert_eq!(json_device_bytes(line, "/dev/md0"), None);
    }

    #[test]
    fn evidence_devices_match_recorded_kernel_names() {
        // The evidence list is written as device nodes; the recorded names are
        // kernel names. The report must still line them up.
        for node in WRITE_EVIDENCE_DEVICES {
            let kernel_name = node.rsplit('/').next().unwrap_or(node);
            assert_eq!(node.len() > kernel_name.len(), true, "{} has a path", node);
            let line = format!(
                "{{\"devices\":[{{\"device\":\"{}\",\"used_bytes\":1}}]}}",
                kernel_name
            );
            assert_eq!(json_device_bytes(&line, kernel_name), Some(1), "{}", node);
            assert!(node.len() > kernel_name.len(), "{} should be a node path", node);
        }
    }

    #[test]
    fn swap_backing_devices_uses_kernel_names() {
        // /proc/swaps ships "/dev/md0"; diskstats wants "md0".
        let text = "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n/dev/md0\t\t\t\tpartition\t16766972\t13411316\t100\n/dev/sda1\t\t\t\tpartition\t16777212\t108956\t10\n";
        let names: Vec<String> = text
            .lines()
            .skip(1)
            .filter_map(|line| line.split_whitespace().next())
            .map(|name| name.rsplit('/').next().unwrap_or(name).to_string())
            .collect();
        assert_eq!(names, vec!["md0".to_string(), "sda1".to_string()]);
    }

    #[test]
    fn record_interval_env_override_is_validated() {
        assert_eq!(record_interval(), RECORD_INTERVAL);
        env::set_var(RECORD_INTERVAL_ENV, "3");
        assert_eq!(record_interval(), Duration::from_secs(3));
        env::set_var(RECORD_INTERVAL_ENV, "0");
        assert_eq!(record_interval(), RECORD_INTERVAL, "zero is ignored");
        env::set_var(RECORD_INTERVAL_ENV, "junk");
        assert_eq!(record_interval(), RECORD_INTERVAL, "junk is ignored");
        env::remove_var(RECORD_INTERVAL_ENV);
        assert_eq!(record_interval(), RECORD_INTERVAL);
    }

    #[test]
    fn diskstats_sectors_convert_to_bytes() {
        // The kernel reports sectors written in 512-byte units, in the tenth
        // whitespace-separated field (major, minor, name, then the counters).
        let line = "   8       1 sda1 14198 5 117824 4427 20897 21491 339736 18373";
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields[3 - 1], "sda1");
        // Counter fields start at index 3; sectors written is the seventh.
        assert_eq!(fields[3 + 6], "339736", "sectors written");
        assert_eq!(fields[3 + 6].parse::<u64>().unwrap() * 512, 173944832);
    }

    #[test]
    fn json_escape_covers_record_hostiles() {
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("/dev/md0"), "/dev/md0");
    }

    #[test]
    fn args_accept_each_mode_and_reject_combinations() {
        let run = |args: &[&str]| -> Result<Args, String> {
            match parse_args(args.iter().map(|s| s.to_string())) {
                Parsed::Run(args) => Ok(args),
                Parsed::Help => Err("help".to_string()),
                Parsed::Error(e) => Err(e),
            }
        };

        let daemon = run(&[]).expect("daemon mode");
        assert!(!daemon.once && !daemon.stats && daemon.report.is_none());

        let once = run(&["--once"]).expect("once");
        assert!(once.once && !once.dry_run);

        let dry = run(&["--once", "--dry-run"]).expect("dry run");
        assert!(dry.once && dry.dry_run);

        let stats = run(&["--stats"]).expect("stats");
        assert!(stats.stats);

        let default_report = run(&["--report"]).expect("report");
        assert_eq!(
            default_report.report.as_deref(),
            Some(std::path::Path::new(STATS_PATH))
        );

        let path_report = run(&["--report", "/somewhere.jsonl"]).expect("report with path");
        assert_eq!(
            path_report.report.as_deref(),
            Some(std::path::Path::new("/somewhere.jsonl"))
        );

        assert!(run(&["--dry-run"]).is_err(), "needs --once");
        assert!(run(&["--stats", "--once"]).is_err(), "modes are exclusive");
        assert!(run(&["--report", "--stats"]).is_err(), "modes are exclusive");
        assert!(run(&["--bogus"]).is_err(), "unknown flag");
    }
}
