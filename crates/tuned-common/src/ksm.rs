//! KSM (Kernel Same-page Merging) sysfs controller.
//!
//! Provides a safe abstraction over /sys/kernel/mm/ksm/ with
//! validated writes, snapshot/restore, and rate limiting.

use crate::error::{Result, TunedError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Minimum interval between KSM parameter updates.
const MIN_UPDATE_INTERVAL_MS: u64 = 500;

/// Snapshot file name within state directory.
const SNAPSHOT_FILENAME: &str = "ksm-snapshot.json";

/// Safe parameter ranges for KSM tunables.
const PARAM_RANGES: &[(&str, u64, u64)] = &[
    ("run", 0, 2),
    ("pages_to_scan", 100, 30000),
    ("sleep_millisecs", 5, 10000),
    ("max_page_sharing", 16, 4096),
    ("advisor_target_scan_time", 10, 3600),
    ("advisor_max_cpu", 10, 100),
    ("advisor_min_pages_to_scan", 100, 5000),
    ("advisor_max_pages_to_scan", 1000, 100000),
];

/// Current KSM runtime statistics read from sysfs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KsmStats {
    pub pages_shared: u64,
    pub pages_sharing: u64,
    pub pages_unshared: u64,
    pub pages_volatile: u64,
    pub pages_scanned: u64,
    pub pages_skipped: u64,
    pub full_scans: u64,
    pub general_profit: i64,
    pub ksm_zero_pages: u64,
    pub stable_node_chains: u64,
    pub stable_node_dups: u64,
}

/// KSM configuration state (the writable parameters).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KsmConfig {
    pub run: u64,
    pub pages_to_scan: u64,
    pub sleep_millisecs: u64,
    pub max_page_sharing: u64,
    pub smart_scan: u64,
    pub advisor_mode: String,
    pub advisor_target_scan_time: u64,
    pub advisor_max_cpu: u64,
    pub advisor_min_pages_to_scan: u64,
    pub advisor_max_pages_to_scan: u64,
}

/// Snapshot of KSM state for restore on shutdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KsmSnapshot {
    pub config: KsmConfig,
    pub timestamp: String,
}

/// KSM sysfs controller with validated writes and rate limiting.
pub struct KsmController {
    base_path: PathBuf,
    last_update: Instant,
    dry_run: bool,
}

impl KsmController {
    /// Create a new controller pointing at the KSM sysfs directory.
    pub fn new(ksm_path: &str) -> Result<Self> {
        let base_path = PathBuf::from(ksm_path);
        if !base_path.exists() {
            return Err(TunedError::Sysfs {
                path: base_path,
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "KSM path not found"),
            });
        }
        Ok(Self {
            base_path,
            last_update: Instant::now() - std::time::Duration::from_millis(MIN_UPDATE_INTERVAL_MS),
            dry_run: false,
        })
    }

    /// Enable dry-run mode (log writes without executing).
    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }

    /// Read all KSM statistics.
    pub fn read_stats(&self) -> Result<KsmStats> {
        Ok(KsmStats {
            pages_shared: self.read_u64("pages_shared")?,
            pages_sharing: self.read_u64("pages_sharing")?,
            pages_unshared: self.read_u64("pages_unshared")?,
            pages_volatile: self.read_u64("pages_volatile")?,
            pages_scanned: self.read_u64("pages_scanned")?,
            pages_skipped: self.read_u64("pages_skipped")?,
            full_scans: self.read_u64("full_scans")?,
            general_profit: self.read_i64("general_profit")?,
            ksm_zero_pages: self.read_u64("ksm_zero_pages").unwrap_or(0),
            stable_node_chains: self.read_u64("stable_node_chains").unwrap_or(0),
            stable_node_dups: self.read_u64("stable_node_dups").unwrap_or(0),
        })
    }

    /// Read all KSM configuration parameters.
    pub fn read_config(&self) -> Result<KsmConfig> {
        Ok(KsmConfig {
            run: self.read_u64("run")?,
            pages_to_scan: self.read_u64("pages_to_scan")?,
            sleep_millisecs: self.read_u64("sleep_millisecs")?,
            max_page_sharing: self.read_u64("max_page_sharing")?,
            smart_scan: self.read_u64("smart_scan").unwrap_or(1),
            advisor_mode: self.read_string("advisor_mode").unwrap_or_default(),
            advisor_target_scan_time: self.read_u64("advisor_target_scan_time").unwrap_or(200),
            advisor_max_cpu: self.read_u64("advisor_max_cpu").unwrap_or(70),
            advisor_min_pages_to_scan: self.read_u64("advisor_min_pages_to_scan").unwrap_or(500),
            advisor_max_pages_to_scan: self.read_u64("advisor_max_pages_to_scan").unwrap_or(30000),
        })
    }

    /// Snapshot current KSM config to a JSON file for later restore.
    ///
    /// Uses atomic write (temp file + rename) to prevent crash corruption.
    pub fn snapshot(&self, state_dir: &Path) -> Result<()> {
        let config = self.read_config()?;
        let snapshot = KsmSnapshot {
            config,
            timestamp: chrono_now(),
        };
        let json = serde_json::to_string_pretty(&snapshot)
            .map_err(|e| TunedError::Snapshot(e.to_string()))?;

        fs::create_dir_all(state_dir)?;
        let path = state_dir.join(SNAPSHOT_FILENAME);
        let tmp_path = state_dir.join(format!("{SNAPSHOT_FILENAME}.tmp"));

        // Write to temp file first, then atomic rename.
        // This prevents a crash mid-write from corrupting the snapshot.
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, &path)?;

        tracing::info!(path = %path.display(), "KSM state snapshotted (atomic write)");
        Ok(())
    }

    /// Restore KSM config from a previously saved snapshot.
    pub fn restore(&mut self, state_dir: &Path) -> Result<()> {
        let path = state_dir.join(SNAPSHOT_FILENAME);
        if !path.exists() {
            tracing::warn!(path = %path.display(), "No KSM snapshot found, skipping restore");
            return Ok(());
        }

        let json = fs::read_to_string(&path)?;
        let snapshot: KsmSnapshot =
            serde_json::from_str(&json).map_err(|e| TunedError::Snapshot(e.to_string()))?;

        tracing::info!(
            timestamp = %snapshot.timestamp,
            "Restoring KSM state from snapshot"
        );

        // Restore advisor mode FIRST so we can write pages_to_scan (kernel rejects
        // direct writes to pages_to_scan while a scan-time advisor is active —
        // unconditionally, regardless of whether KSM is running).
        if snapshot.config.advisor_mode != "scan-time" {
            // Safe to set advisor mode to the snapshot value before writing pages_to_scan
            let _ = self.set_advisor_mode(&snapshot.config.advisor_mode);
        } else {
            // Temporarily disable the advisor so we can write pages_to_scan.
            // We'll re-enable it below after restoring all other parameters.
            let _ = self.set_advisor_mode("none");
        }

        self.set_run(snapshot.config.run)?;
        self.set_pages_to_scan(snapshot.config.pages_to_scan)?;
        self.set_sleep_millisecs(snapshot.config.sleep_millisecs)?;
        self.set_max_page_sharing(snapshot.config.max_page_sharing)?;

        // Restore advisor settings if available (re-enable if we disabled it above)
        let _ = self.set_advisor_mode(&snapshot.config.advisor_mode);
        let _ = self.set_advisor_target_scan_time(snapshot.config.advisor_target_scan_time);
        let _ = self.set_advisor_max_cpu(snapshot.config.advisor_max_cpu);

        Ok(())
    }

    /// Set KSM run mode (0=stop, 1=run, 2=unmerge).
    pub fn set_run(&self, value: u64) -> Result<()> {
        self.write_validated("run", value)
    }

    pub fn set_pages_to_scan(&self, value: u64) -> Result<()> {
        self.write_validated("pages_to_scan", value)
    }

    pub fn set_sleep_millisecs(&self, value: u64) -> Result<()> {
        self.write_validated("sleep_millisecs", value)
    }

    pub fn set_max_page_sharing(&self, value: u64) -> Result<()> {
        self.write_validated("max_page_sharing", value)
    }

    pub fn set_advisor_mode(&self, mode: &str) -> Result<()> {
        self.write_string("advisor_mode", mode)
    }

    pub fn set_advisor_target_scan_time(&self, value: u64) -> Result<()> {
        self.write_validated("advisor_target_scan_time", value)
    }

    pub fn set_advisor_max_cpu(&self, value: u64) -> Result<()> {
        self.write_validated("advisor_max_cpu", value)
    }

    /// Write a validated integer parameter to sysfs.
    fn write_validated(&self, param: &str, value: u64) -> Result<()> {
        let clamped = self.clamp_value(param, value);
        if clamped != value {
            tracing::warn!(
                param,
                requested = value,
                clamped_to = clamped,
                "KSM parameter clamped to safe range"
            );
        }

        self.write_param(param, &clamped.to_string())
    }

    /// Write a string parameter to sysfs.
    fn write_string(&self, param: &str, value: &str) -> Result<()> {
        self.write_param(param, value)
    }

    fn write_param(&self, param: &str, value: &str) -> Result<()> {
        // Rate limit
        let elapsed = self.last_update.elapsed();
        if elapsed.as_millis() < MIN_UPDATE_INTERVAL_MS as u128 {
            tracing::trace!(
                param,
                "Skipping KSM write (rate limited, {:.0}ms since last update)",
                elapsed.as_millis()
            );
            return Ok(());
        }

        let path = self.base_path.join(param);

        if self.dry_run {
            tracing::info!(param, value, "[DRY RUN] Would write KSM parameter");
            return Ok(());
        }

        fs::write(&path, value).map_err(|e| TunedError::Sysfs {
            path: path.clone(),
            source: e,
        })?;

        // Verify write
        let readback = fs::read_to_string(&path)
            .unwrap_or_default()
            .trim()
            .to_string();

        // For advisor_mode the kernel may add brackets around the active mode
        if !readback.contains(value) {
            tracing::warn!(
                param,
                expected = value,
                actual = readback,
                "KSM parameter write verification mismatch"
            );
        }

        tracing::debug!(param, value, readback = %readback, "KSM parameter written");
        Ok(())
    }

    fn clamp_value(&self, param: &str, value: u64) -> u64 {
        for &(name, min, max) in PARAM_RANGES {
            if name == param {
                return value.clamp(min, max);
            }
        }
        value // Unknown param, pass through
    }

    fn read_u64(&self, param: &str) -> Result<u64> {
        let path = self.base_path.join(param);
        let content =
            fs::read_to_string(&path).map_err(|e| TunedError::Sysfs { path, source: e })?;
        // Handle advisor_mode style values like "[none] scan-time"
        let trimmed = content.trim();
        // Strip brackets if present (for enum-style values)
        let cleaned = trimmed
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(trimmed);
        cleaned.parse::<u64>().map_err(|_| TunedError::Sysfs {
            path: self.base_path.join(param),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("cannot parse '{trimmed}' as u64"),
            ),
        })
    }

    fn read_i64(&self, param: &str) -> Result<i64> {
        let path = self.base_path.join(param);
        let content =
            fs::read_to_string(&path).map_err(|e| TunedError::Sysfs { path, source: e })?;
        content
            .trim()
            .parse::<i64>()
            .map_err(|_| TunedError::Sysfs {
                path: self.base_path.join(param),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("cannot parse '{}' as i64", content.trim()),
                ),
            })
    }

    fn read_string(&self, param: &str) -> Result<String> {
        let path = self.base_path.join(param);
        let content =
            fs::read_to_string(&path).map_err(|e| TunedError::Sysfs { path, source: e })?;
        // Extract the active value from bracket notation.
        // Kernel advisor_mode outputs either "[none] scan-time" or "none [scan-time]"
        // In both cases, the active mode is the one inside brackets.
        let trimmed = content.trim();
        if let Some(bracket_start) = trimmed.find('[') {
            if let Some(bracket_end) = trimmed[bracket_start..].find(']') {
                let active = &trimmed[bracket_start + 1..bracket_start + bracket_end];
                return Ok(active.trim().to_string());
            }
        }
        // Fallback: no brackets found, return trimmed content
        Ok(trimmed.to_string())
    }

    /// Read all sysfs files in the KSM directory into a map (for diagnostics).
    pub fn read_all_raw(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(entries) = fs::read_dir(&self.base_path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    map.insert(name, content.trim().to_string());
                }
            }
        }
        map
    }
}

/// Simple ISO-like timestamp without pulling in chrono.
fn chrono_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clamp_value() {
        let ctrl = KsmController {
            base_path: PathBuf::from("/tmp"),
            last_update: Instant::now(),
            dry_run: true,
        };
        assert_eq!(ctrl.clamp_value("run", 5), 2);
        assert_eq!(ctrl.clamp_value("pages_to_scan", 50), 100);
        assert_eq!(ctrl.clamp_value("pages_to_scan", 50000), 30000);
        assert_eq!(ctrl.clamp_value("sleep_millisecs", 3), 5);
        assert_eq!(ctrl.clamp_value("unknown_param", 42), 42);
    }

    // ── Helper: create a KsmController pointing at a temp dir with seed files ─

    struct TempKsm {
        dir: tempfile::TempDir,
        ctrl: KsmController,
    }

    macro_rules! seeded {
        ($(($name:expr, $content:expr)),+ $(,)?) => {
            TempKsm::with_seeded(vec![$(($name, $content)),+])
        };
        () => {
            TempKsm::with_seeded(vec![])
        };
    }

    impl TempKsm {
        /// Create a temp directory with the given (filename → content) seed
        /// files and return a KsmController pointed at it.
        fn with_seeded(seeded: Vec<(&str, &str)>) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            for (name, content) in seeded {
                let path = dir.path().join(name);
                std::fs::write(&path, content).expect("seed write");
            }
            let ctrl = KsmController {
                base_path: dir.path().to_path_buf(),
                last_update: Instant::now() - std::time::Duration::from_secs(60),
                dry_run: false,
            };
            Self { dir, ctrl }
        }

        fn read(&self, name: &str) -> String {
            let path = self.dir.path().join(name);
            std::fs::read_to_string(&path).unwrap_or_default()
        }
    }

    // ── read_u64 / read_i64 / read_string ────────────────────────────────

    #[test]
    fn test_read_u64() {
        let t = seeded![("pages_shared", "12345")];
        assert_eq!(t.ctrl.read_u64("pages_shared").unwrap(), 12345);
    }

    #[test]
    fn test_read_u64_bracket_format() {
        let t = seeded![("run", "[1] 0")];
        assert_eq!(t.ctrl.read_u64("run").unwrap(), 1);
    }

    #[test]
    fn test_read_u64_not_found() {
        let t = seeded![];
        assert!(t.ctrl.read_u64("nonexistent").is_err());
    }

    #[test]
    fn test_read_i64() {
        let t = seeded![("general_profit", "-42")];
        assert_eq!(t.ctrl.read_i64("general_profit").unwrap(), -42);
    }

    #[test]
    fn test_read_i64_invalid() {
        let t = seeded![("general_profit", "not_a_number")];
        assert!(t.ctrl.read_i64("general_profit").is_err());
    }

    #[test]
    fn test_read_string() {
        let t = seeded![("advisor_mode", "none")];
        assert_eq!(t.ctrl.read_string("advisor_mode").unwrap(), "none");
    }

    #[test]
    fn test_read_string_bracket_active() {
        // Kernel format when scan-time is active: "none [scan-time]"
        let t = seeded![("advisor_mode", "none [scan-time]")];
        assert_eq!(t.ctrl.read_string("advisor_mode").unwrap(), "scan-time");
    }

    #[test]
    fn test_read_string_bracket_options() {
        // Kernel format when none is active: "[none] scan-time"
        // Kernel format when scan-time is active: "none [scan-time]"
        let t = seeded![("advisor_mode", "[none] scan-time")];
        assert_eq!(t.ctrl.read_string("advisor_mode").unwrap(), "none");
        let t2 = seeded![("advisor_mode", "none [scan-time]")];
        assert_eq!(t2.ctrl.read_string("advisor_mode").unwrap(), "scan-time");
    }

    #[test]
    fn test_read_string_trim_whitespace() {
        let t = seeded![("advisor_mode", "  none  ")];
        assert_eq!(t.ctrl.read_string("advisor_mode").unwrap(), "none");
    }

    // ── write_param ─────────────────────────────────────────────────────

    #[test]
    fn test_write_param_writes_value() {
        let t = seeded![("run", "0")];
        t.ctrl.write_param("run", "1").unwrap();
        assert_eq!(t.read("run"), "1");
    }

    #[test]
    fn test_write_param_dry_run_does_not_write() {
        let t = seeded![("run", "0")];
        let dry = KsmController {
            base_path: t.dir.path().to_path_buf(),
            last_update: Instant::now() - std::time::Duration::from_secs(60),
            dry_run: true,
        };
        dry.write_param("run", "2").unwrap();
        assert_eq!(t.read("run"), "0");
    }

    #[test]
    fn test_write_param_rate_limited_skips_write() {
        let t = seeded![("run", "0")];
        let rate_limited = KsmController {
            base_path: t.dir.path().to_path_buf(),
            last_update: Instant::now(),
            dry_run: false,
        };
        rate_limited.write_param("run", "1").unwrap();
        assert_eq!(t.read("run"), "0");
    }

    #[test]
    fn test_write_param_directory_returns_error() {
        let t = seeded![];
        std::fs::create_dir(t.dir.path().join("directory")).unwrap();
        let err = t.ctrl.write_param("directory", "1").unwrap_err();
        assert!(err.to_string().contains("directory"));
    }

    // ── write_validated ─────────────────────────────────────────────────

    #[test]
    fn test_write_validated_clamps_value() {
        let t = seeded![("run", "0")];
        t.ctrl.write_validated("run", 5).unwrap();
        assert_eq!(t.read("run"), "2");
    }

    #[test]
    fn test_write_validated_in_range() {
        let t = seeded![("sleep_millisecs", "100")];
        t.ctrl.write_validated("sleep_millisecs", 50).unwrap();
        assert_eq!(t.read("sleep_millisecs"), "50");
    }

    // ── read_stats ──────────────────────────────────────────────────────

    #[test]
    fn test_read_stats_all_fields() {
        let t = seeded![
            ("pages_shared", "100"),
            ("pages_sharing", "200"),
            ("pages_unshared", "50"),
            ("pages_volatile", "10"),
            ("pages_scanned", "9999"),
            ("pages_skipped", "5"),
            ("full_scans", "42"),
            ("general_profit", "123456"),
            ("ksm_zero_pages", "7"),
            ("stable_node_chains", "3"),
            ("stable_node_dups", "1"),
        ];
        let stats = t.ctrl.read_stats().unwrap();
        assert_eq!(stats.pages_shared, 100);
        assert_eq!(stats.pages_sharing, 200);
        assert_eq!(stats.pages_unshared, 50);
        assert_eq!(stats.pages_volatile, 10);
        assert_eq!(stats.pages_scanned, 9999);
        assert_eq!(stats.pages_skipped, 5);
        assert_eq!(stats.full_scans, 42);
        assert_eq!(stats.general_profit, 123456);
        assert_eq!(stats.ksm_zero_pages, 7);
        assert_eq!(stats.stable_node_chains, 3);
        assert_eq!(stats.stable_node_dups, 1);
    }

    #[test]
    fn test_read_stats_optional_fields_default_zero() {
        let t = seeded![
            ("pages_shared", "10"),
            ("pages_sharing", "20"),
            ("pages_unshared", "5"),
            ("pages_volatile", "2"),
            ("pages_scanned", "100"),
            ("pages_skipped", "1"),
            ("full_scans", "7"),
            ("general_profit", "500"),
        ];
        let stats = t.ctrl.read_stats().unwrap();
        assert_eq!(stats.ksm_zero_pages, 0);
        assert_eq!(stats.stable_node_chains, 0);
        assert_eq!(stats.stable_node_dups, 0);
    }

    // ── read_config ─────────────────────────────────────────────────────

    #[test]
    fn test_read_config_all_fields() {
        let t = seeded![
            ("run", "1"),
            ("pages_to_scan", "500"),
            ("sleep_millisecs", "20"),
            ("max_page_sharing", "256"),
            ("smart_scan", "1"),
            ("advisor_mode", "scan-time"),
            ("advisor_target_scan_time", "200"),
            ("advisor_max_cpu", "70"),
            ("advisor_min_pages_to_scan", "500"),
            ("advisor_max_pages_to_scan", "30000"),
        ];
        let cfg = t.ctrl.read_config().unwrap();
        assert_eq!(cfg.run, 1);
        assert_eq!(cfg.pages_to_scan, 500);
        assert_eq!(cfg.sleep_millisecs, 20);
        assert_eq!(cfg.max_page_sharing, 256);
        assert_eq!(cfg.smart_scan, 1);
        assert_eq!(cfg.advisor_mode, "scan-time");
        assert_eq!(cfg.advisor_target_scan_time, 200);
        assert_eq!(cfg.advisor_max_cpu, 70);
        assert_eq!(cfg.advisor_min_pages_to_scan, 500);
        assert_eq!(cfg.advisor_max_pages_to_scan, 30000);
    }

    #[test]
    fn test_read_config_missing_optionals_default() {
        let t = seeded![
            ("run", "0"),
            ("pages_to_scan", "100"),
            ("sleep_millisecs", "100"),
            ("max_page_sharing", "256"),
        ];
        let cfg = t.ctrl.read_config().unwrap();
        assert_eq!(cfg.smart_scan, 1);
        assert_eq!(cfg.advisor_mode, "");
        assert_eq!(cfg.advisor_target_scan_time, 200);
        assert_eq!(cfg.advisor_max_cpu, 70);
    }

    // ── set_* convenience methods ───────────────────────────────────────

    #[test]
    fn test_set_run_writes_clamped() {
        let t = seeded![("run", "0")];
        t.ctrl.set_run(1).unwrap();
        assert_eq!(t.read("run"), "1");
    }

    #[test]
    fn test_set_pages_to_scan() {
        let t = seeded![("pages_to_scan", "100")];
        t.ctrl.set_pages_to_scan(1000).unwrap();
        assert_eq!(t.read("pages_to_scan"), "1000");
    }

    #[test]
    fn test_set_advisor_mode_writes_string() {
        let t = seeded![("advisor_mode", "none")];
        t.ctrl.set_advisor_mode("scan-time").unwrap();
        assert_eq!(t.read("advisor_mode"), "scan-time");
    }

    // ── snapshot / restore ──────────────────────────────────────────────

    #[test]
    fn test_snapshot_and_restore_roundtrip() {
        let t = seeded![
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
        ];
        let state_dir = t.dir.path().join("state");

        t.ctrl.snapshot(&state_dir).unwrap();
        let snap_path = state_dir.join("ksm-snapshot.json");
        assert!(snap_path.exists());

        std::fs::write(t.dir.path().join("run"), "0").unwrap();
        std::fs::write(t.dir.path().join("pages_to_scan"), "100").unwrap();

        let mut ctrl = KsmController {
            base_path: t.dir.path().to_path_buf(),
            last_update: Instant::now() - std::time::Duration::from_secs(60),
            dry_run: false,
        };
        ctrl.restore(&state_dir).unwrap();

        assert_eq!(ctrl.read_u64("run").unwrap(), 1);
        assert_eq!(ctrl.read_u64("pages_to_scan").unwrap(), 500);
    }

    #[test]
    fn test_restore_no_snapshot_skips_gracefully() {
        let t = seeded![("run", "1")];
        let state_dir = t.dir.path().join("nonexistent-state");
        let mut ctrl = KsmController {
            base_path: t.dir.path().to_path_buf(),
            last_update: Instant::now() - std::time::Duration::from_secs(60),
            dry_run: false,
        };
        ctrl.restore(&state_dir).unwrap();
        assert_eq!(ctrl.read_u64("run").unwrap(), 1);
    }

    #[test]
    fn test_snapshot_errors_when_state_dir_is_file() {
        let t = seeded![
            ("run", "1"),
            ("pages_to_scan", "500"),
            ("sleep_millisecs", "20"),
            ("max_page_sharing", "256"),
        ];
        let state_dir = t.dir.path().join("state-file");
        std::fs::write(&state_dir, "not a directory").unwrap();

        assert!(t.ctrl.snapshot(&state_dir).is_err());
    }

    #[test]
    fn test_restore_advisor_branch_reenables_scan_time_advisor() {
        // The `advisor_mode == "scan-time"` branch of `restore`. The kernel
        // rejects direct writes to `pages_to_scan` while a scan-time advisor is
        // active, so `restore` must first disable the advisor, write the
        // parameters, and then RE-ENABLE it — a controller that leaves the
        // advisor off has silently dropped the operator's configuration, and
        // the governor would then be the only controller of `pages_to_scan`,
        // which is exactly the two-controllers fight Option B exists to avoid.
        //
        // Every sysfs file is seeded with a value different from the snapshot,
        // so every assertion below distinguishes a write from a coincidence.
        let t = seeded![
            ("run", "0"),
            ("pages_to_scan", "100"),
            ("sleep_millisecs", "5000"),
            ("max_page_sharing", "4096"),
            ("advisor_mode", "none"),
            ("advisor_target_scan_time", "10"),
            ("advisor_max_cpu", "10"),
            ("advisor_min_pages_to_scan", "5000"),
            ("advisor_max_pages_to_scan", "1000"),
        ];
        let state_dir = t.dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        // All snapshot values are inside `PARAM_RANGES`, so nothing is clamped
        // and each write lands verbatim: run 1 (0-2), pages_to_scan 700
        // (100-30000), sleep_millisecs 11 (5-10000), max_page_sharing 2048
        // (16-4096), advisor_target_scan_time 250 (10-3600), advisor_max_cpu 90
        // (10-100).
        let snapshot = KsmSnapshot {
            config: KsmConfig {
                run: 1,
                pages_to_scan: 700,
                sleep_millisecs: 11,
                max_page_sharing: 2048,
                smart_scan: 1,
                advisor_mode: "scan-time".to_string(),
                advisor_target_scan_time: 250,
                advisor_max_cpu: 90,
                advisor_min_pages_to_scan: 400,
                advisor_max_pages_to_scan: 9000,
            },
            timestamp: chrono_now(),
        };
        std::fs::write(
            state_dir.join(SNAPSHOT_FILENAME),
            serde_json::to_string_pretty(&snapshot).unwrap(),
        )
        .unwrap();

        let mut ctrl = KsmController {
            base_path: t.dir.path().to_path_buf(),
            last_update: Instant::now() - std::time::Duration::from_secs(60),
            dry_run: false,
        };
        ctrl.restore(&state_dir).unwrap();

        // Every parameter `restore` is documented to write, restored exactly.
        assert_eq!(ctrl.read_string("advisor_mode").unwrap(), "scan-time");
        assert_eq!(ctrl.read_u64("run").unwrap(), 1);
        assert_eq!(ctrl.read_u64("pages_to_scan").unwrap(), 700);
        assert_eq!(ctrl.read_u64("sleep_millisecs").unwrap(), 11);
        assert_eq!(ctrl.read_u64("max_page_sharing").unwrap(), 2048);
        assert_eq!(ctrl.read_u64("advisor_target_scan_time").unwrap(), 250);
        assert_eq!(ctrl.read_u64("advisor_max_cpu").unwrap(), 90);
    }

    #[test]
    fn test_restore_advisor_branch_leaves_advisor_page_bounds_untouched() {
        // Companion to the test above: `restore` never writes
        // `advisor_min_pages_to_scan` / `advisor_max_pages_to_scan`, so the
        // two page-bound tunables survive on disk with whatever the kernel
        // already had. Asserting the *seeded* values proves those two code
        // paths are genuinely absent rather than merely unwritten by accident.
        let t = seeded![
            ("run", "0"),
            ("pages_to_scan", "100"),
            ("sleep_millisecs", "5000"),
            ("max_page_sharing", "4096"),
            ("advisor_mode", "none"),
            ("advisor_target_scan_time", "10"),
            ("advisor_max_cpu", "10"),
            ("advisor_min_pages_to_scan", "5000"),
            ("advisor_max_pages_to_scan", "1000"),
        ];
        let state_dir = t.dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let snapshot = KsmSnapshot {
            config: KsmConfig {
                run: 1,
                pages_to_scan: 700,
                sleep_millisecs: 11,
                max_page_sharing: 2048,
                smart_scan: 1,
                advisor_mode: "scan-time".to_string(),
                advisor_target_scan_time: 250,
                advisor_max_cpu: 90,
                advisor_min_pages_to_scan: 400,
                advisor_max_pages_to_scan: 9000,
            },
            timestamp: chrono_now(),
        };
        std::fs::write(
            state_dir.join(SNAPSHOT_FILENAME),
            serde_json::to_string_pretty(&snapshot).unwrap(),
        )
        .unwrap();

        let mut ctrl = KsmController {
            base_path: t.dir.path().to_path_buf(),
            last_update: Instant::now() - std::time::Duration::from_secs(60),
            dry_run: false,
        };
        ctrl.restore(&state_dir).unwrap();

        // The snapshot's 400 / 9000 must NOT reach sysfs: only the on-disk
        // kernel values survive.
        assert_eq!(ctrl.read_u64("advisor_min_pages_to_scan").unwrap(), 5000);
        assert_eq!(ctrl.read_u64("advisor_max_pages_to_scan").unwrap(), 1000);
        // And a parameter that IS written proves this restore actually ran,
        // so the two untouched values above are not a vacuous early return.
        assert_eq!(ctrl.read_u64("sleep_millisecs").unwrap(), 11);
    }

    #[test]
    fn test_restore_non_scan_time_advisor_branch_restores_advisor_off() {
        // The other half of the advisor branch: the snapshot recorded the
        // advisor as `none`, so `restore` must take the direct path (write the
        // advisor mode first, then the parameters) and end with the advisor off.
        // The live kernel only ever has `advisor_mode == "scan-time"` under the
        // governor, so this branch is weak in the round-trip test above.
        let t = seeded![
            ("run", "0"),
            ("pages_to_scan", "100"),
            ("sleep_millisecs", "5000"),
            ("max_page_sharing", "4096"),
            ("advisor_mode", "scan-time"),
            ("advisor_target_scan_time", "10"),
            ("advisor_max_cpu", "10"),
            ("advisor_min_pages_to_scan", "5000"),
            ("advisor_max_pages_to_scan", "1000"),
        ];
        let state_dir = t.dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let snapshot = KsmSnapshot {
            config: KsmConfig {
                run: 0,
                pages_to_scan: 700,
                sleep_millisecs: 11,
                max_page_sharing: 2048,
                smart_scan: 1,
                advisor_mode: "none".to_string(),
                advisor_target_scan_time: 250,
                advisor_max_cpu: 90,
                advisor_min_pages_to_scan: 400,
                advisor_max_pages_to_scan: 9000,
            },
            timestamp: chrono_now(),
        };
        std::fs::write(
            state_dir.join(SNAPSHOT_FILENAME),
            serde_json::to_string_pretty(&snapshot).unwrap(),
        )
        .unwrap();

        let mut ctrl = KsmController {
            base_path: t.dir.path().to_path_buf(),
            last_update: Instant::now() - std::time::Duration::from_secs(60),
            dry_run: false,
        };
        ctrl.restore(&state_dir).unwrap();

        assert_eq!(ctrl.read_string("advisor_mode").unwrap(), "none");
        assert_eq!(ctrl.read_u64("run").unwrap(), 0);
        assert_eq!(ctrl.read_u64("pages_to_scan").unwrap(), 700);
        assert_eq!(ctrl.read_u64("sleep_millisecs").unwrap(), 11);
        assert_eq!(ctrl.read_u64("max_page_sharing").unwrap(), 2048);
        assert_eq!(ctrl.read_u64("advisor_target_scan_time").unwrap(), 250);
        assert_eq!(ctrl.read_u64("advisor_max_cpu").unwrap(), 90);
    }

    #[test]
    fn test_restore_invalid_snapshot_json_returns_error() {
        let t = seeded![("run", "1")];
        let state_dir = t.dir.path().join("state");
        std::fs::create_dir(&state_dir).unwrap();
        std::fs::write(state_dir.join("ksm-snapshot.json"), "not json").unwrap();

        let mut ctrl = KsmController {
            base_path: t.dir.path().to_path_buf(),
            last_update: Instant::now() - std::time::Duration::from_secs(60),
            dry_run: false,
        };
        let err = ctrl.restore(&state_dir).unwrap_err();
        assert!(err.to_string().contains("snapshot"));
    }

    // ── read_all_raw ────────────────────────────────────────────────────

    #[test]
    fn test_read_all_raw() {
        let t = seeded![("run", "1"), ("pages_to_scan", "100")];
        let map = t.ctrl.read_all_raw();
        assert_eq!(map.get("run").map(|s| s.as_str()), Some("1"));
        assert_eq!(map.get("pages_to_scan").map(|s| s.as_str()), Some("100"));
    }

    #[test]
    fn test_read_all_raw_empty_dir() {
        let t = seeded![];
        let map = t.ctrl.read_all_raw();
        assert!(map.is_empty());
    }

    #[test]
    fn test_read_all_raw_skips_unreadable_directory_entries() {
        let t = seeded![("run", "1")];
        std::fs::create_dir(t.dir.path().join("nested")).unwrap();

        let map = t.ctrl.read_all_raw();
        assert_eq!(map.get("run").map(|s| s.as_str()), Some("1"));
        assert!(!map.contains_key("nested"));
    }

    // ── new() ───────────────────────────────────────────────────────────

    #[test]
    fn test_new_returns_error_for_nonexistent_path() {
        let result = KsmController::new("/nonexistent/ksm/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_new_succeeds_for_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let result = KsmController::new(dir.path().to_str().unwrap());
        assert!(result.is_ok());
    }

    // ── set_dry_run ─────────────────────────────────────────────────────

    #[test]
    fn test_set_dry_run_toggle() {
        let mut ctrl = KsmController {
            base_path: PathBuf::from("/tmp"),
            last_update: Instant::now(),
            dry_run: false,
        };
        assert!(!ctrl.dry_run);
        ctrl.set_dry_run(true);
        assert!(ctrl.dry_run);
        ctrl.set_dry_run(false);
        assert!(!ctrl.dry_run);
    }

    // ── chrono_now format ───────────────────────────────────────────────

    #[test]
    fn test_chrono_now_format() {
        let result = chrono_now();
        assert!(!result.is_empty());
        assert!(result.chars().all(|c| c.is_ascii_digit()));
    }

    // ════════════════════════════════════════════════════════════════════
    // Fault injection: what happens when the sysfs / snapshot boundaries FAIL
    //
    // Every test below drives a real failure at a kernel or filesystem
    // boundary inside a tempdir and asserts on the *observable decision* the
    // controller makes: an Err (never a silently Default-filled struct), an
    // Err that names the offending path, or an abort before any write lands.
    // Each assertion is written so that breaking the production error
    // handling (`?` → `unwrap_or_default`, `map_err` → `.ok()`, dropping the
    // clamp, etc.) turns the test red.
    // ════════════════════════════════════════════════════════════════════

    /// Set a POSIX mode on `path`. Test-only, so failures are ignored by the
    /// caller (probe paths always restore permissions before returning).
    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }

    /// Probe whether this uid actually has its permission bits enforced.
    ///
    /// Root bypasses file permission checks, so a chmod-based fault injection
    /// is simply unreachable under root. The probe writes a file, removes its
    /// write bit and tries to write again; it restores the mode afterwards so
    /// the tempdir can still be unlinked. Callers branch on this answer rather
    /// than assuming an unprivileged uid.
    fn permission_bits_are_enforced() -> bool {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("probe");
        std::fs::write(&file, "x").expect("probe write");
        set_mode(&file, 0o444);
        let write_refused = std::fs::write(&file, "y").is_err();
        set_mode(&file, 0o644);
        let read_refused = {
            let nested = dir.path().join("nested");
            std::fs::create_dir(&nested).expect("nested dir");
            std::fs::write(nested.join("run"), "1").expect("nested write");
            set_mode(&nested, 0o000);
            let refused = std::fs::read_to_string(nested.join("run")).is_err();
            set_mode(&nested, 0o755);
            refused
        };
        write_refused || read_refused
    }

    /// The eight stats files `read_stats` treats as required.
    const REQUIRED_STATS: [&str; 8] = [
        "pages_shared",
        "pages_sharing",
        "pages_unshared",
        "pages_volatile",
        "pages_scanned",
        "pages_skipped",
        "full_scans",
        "general_profit",
    ];

    /// Full path of a seeded file, used to assert the error names the file.
    fn path_in(dir: &Path, name: &str) -> String {
        dir.join(name).display().to_string()
    }

    /// A controller over `base_path` with the rate limiter already primed, so
    /// writes land on the first attempt instead of being skipped.
    fn controller_at(base_path: &Path) -> KsmController {
        KsmController {
            base_path: base_path.to_path_buf(),
            last_update: Instant::now() - std::time::Duration::from_secs(60),
            dry_run: false,
        }
    }

    /// Seed a snapshot file with *raw* content (corrupt or otherwise).
    fn write_raw_snapshot(state_dir: &Path, content: &str) {
        std::fs::create_dir_all(state_dir).unwrap();
        std::fs::write(state_dir.join(SNAPSHOT_FILENAME), content).unwrap();
    }

    /// A snapshot JSON whose every field is in range and differs from the
    /// seeded sysfs values, so each assertion distinguishes a real write.
    const VALID_SNAPSHOT_JSON: &str = r#"{
      "config": {
        "run": 1,
        "pages_to_scan": 700,
        "sleep_millisecs": 11,
        "max_page_sharing": 2048,
        "smart_scan": 1,
        "advisor_mode": "none",
        "advisor_target_scan_time": 250,
        "advisor_max_cpu": 90,
        "advisor_min_pages_to_scan": 400,
        "advisor_max_pages_to_scan": 9000
      },
      "timestamp": "2026-10-15T00:00:00Z"
    }"#;

    // ── (a) unreadable sysfs directory ─────────────────────────────────

    #[test]
    fn fault_read_stats_unreadable_directory_errors_and_is_not_zeroed() {
        if !permission_bits_are_enforced() {
            eprintln!(
                "skipped: running with permission bits unenforced (root), \
                 the chmod-000 sysfs directory fault is unreachable"
            );
            return;
        }

        // Every required field is present and non-zero, so an Ok would be the
        // only way this test could pass by fabrication: the failure has to come
        // from the unreadable file, not from a missing seed.
        let t = seeded![
            ("pages_shared", "100"),
            ("pages_sharing", "200"),
            ("pages_unshared", "50"),
            ("pages_volatile", "10"),
            ("pages_scanned", "9999"),
            ("pages_skipped", "5"),
            ("full_scans", "42"),
            ("general_profit", "123456"),
        ];
        set_mode(t.dir.path(), 0o000);
        let result = t.ctrl.read_stats();
        set_mode(t.dir.path(), 0o755);

        let err = result.expect_err(
            "read_stats over a chmod-000 sysfs directory must fail, \
             never hand back a KsmStats struct full of zeros",
        );
        // The error names the exact file that could not be read.
        let expected = path_in(t.dir.path(), "pages_shared");
        assert!(
            matches!(err, TunedError::Sysfs { .. }),
            "expected a Sysfs error, got {err:?}"
        );
        assert!(
            err.to_string().contains(&expected),
            "error must name the unreadable file: {err} does not contain {expected}"
        );

        // And the whole struct is unreachable — the first required read alone
        // is enough to abort, so nothing downstream is fabricated.
        assert!(
            err.to_string().contains("pages_shared"),
            "error must name the failing parameter: {err}"
        );
    }

    #[test]
    fn fault_read_stats_deleted_base_directory_errors_naming_the_missing_file() {
        // EPERM-independent: ENOENT happens under root too. This is the
        // root-proof equivalent of the unreadable-directory fault above.
        let dir = tempfile::tempdir().expect("tempdir");
        let gone = dir.path().to_path_buf();
        dir.close().unwrap();
        assert!(!gone.exists(), "precondition: base path must be gone");

        let ctrl = controller_at(&gone);
        let err = ctrl
            .read_stats()
            .expect_err("read_stats over a deleted sysfs directory must fail");

        assert!(
            matches!(err, TunedError::Sysfs { .. }),
            "expected a Sysfs error, got {err:?}"
        );
        let missing = gone.join("pages_shared").display().to_string();
        assert!(
            err.to_string().contains(&missing),
            "error must name the missing file {missing}: {err}"
        );
        // The failing read is the FIRST required field, so a Default-filled
        // struct is impossible: every one of the 11 reads would have to have
        // been mutated away for this to be Ok.
        assert!(
            err.to_string().contains("os error 2") || err.to_string().contains("No such file"),
            "deleted directory must surface as NotFound, got: {err}"
        );
    }

    // ── (b) individual required file missing ───────────────────────────

    #[test]
    fn fault_read_stats_missing_required_file_errors_naming_that_file() {
        // Seven of the eight required stats files exist (and the optional
        // three too); `full_scans` is the hole.
        let mut seeds: Vec<(&str, &str)> = vec![
            ("pages_shared", "100"),
            ("pages_sharing", "200"),
            ("pages_unshared", "50"),
            ("pages_volatile", "10"),
            ("pages_scanned", "9999"),
            ("pages_skipped", "5"),
            ("general_profit", "123456"),
            ("ksm_zero_pages", "7"),
            ("stable_node_chains", "3"),
            ("stable_node_dups", "1"),
        ];
        seeds.retain(|(name, _)| *name != "full_scans");
        let t = TempKsm::with_seeded(seeds);

        let err = t
            .ctrl
            .read_stats()
            .expect_err("a missing required stats file must fail the whole read");

        assert!(
            matches!(err, TunedError::Sysfs { .. }),
            "expected a Sysfs error, got {err:?}"
        );
        let expected = path_in(t.dir.path(), "full_scans");
        assert!(
            err.to_string().contains(&expected),
            "error must name the missing file {expected}: {err}"
        );
    }

    #[test]
    fn fault_read_stats_missing_required_file_leaves_nothing_for_other_fields() {
        // Same hole, different angle: the Err must not be a per-field
        // defaulting decision that could be "fixed later" — every other
        // required file must still be a read that can fail, so the same
        // mutation on any single field is caught.
        let names = REQUIRED_STATS;
        for missing in names {
            let mut seeds: Vec<(&str, &str)> = vec![
                ("pages_shared", "100"),
                ("pages_sharing", "200"),
                ("pages_unshared", "50"),
                ("pages_volatile", "10"),
                ("pages_scanned", "9999"),
                ("pages_skipped", "5"),
                ("full_scans", "42"),
                ("general_profit", "123456"),
            ];
            seeds.retain(|(name, _)| *name != missing);
            let t = TempKsm::with_seeded(seeds);
            let err = t.ctrl.read_stats().expect_err("missing required file");
            let expected = t.dir.path().join(missing).display().to_string();
            assert!(
                err.to_string().contains(&expected),
                "removing {missing} must produce an error naming it: {err}"
            );
        }
    }

    // ── (c) garbage in a required file ─────────────────────────────────

    #[test]
    fn fault_read_u64_garbage_values_error_and_name_the_file() {
        for garbage in ["abc", "", "-1", "12x", "[none] scan-time"] {
            let t = seeded![("pages_shared", garbage)];
            let err = t
                .ctrl
                .read_u64("pages_shared")
                .expect_err(&format!("read_u64({garbage:?}) must fail"));
            let expected = path_in(t.dir.path(), "pages_shared");
            assert!(
                err.to_string().contains(&expected),
                "error for {garbage:?} must name the file {expected}: {err}"
            );
            assert!(
                err.to_string()
                    .contains(&format!("cannot parse '{garbage}' as u64")),
                "error for {garbage:?} must report the unparsable content: {err}"
            );
        }
    }

    #[test]
    fn fault_read_stats_garbage_required_field_errors_naming_that_field() {
        // All ten other files hold good values; only `general_profit` is
        // garbage, so the only way to Ok is to default it to zero.
        let t = seeded![
            ("pages_shared", "100"),
            ("pages_sharing", "200"),
            ("pages_unshared", "50"),
            ("pages_volatile", "10"),
            ("pages_scanned", "9999"),
            ("pages_skipped", "5"),
            ("full_scans", "42"),
            ("general_profit", "abc"),
            ("ksm_zero_pages", "7"),
            ("stable_node_chains", "3"),
            ("stable_node_dups", "1"),
        ];
        let err = t
            .ctrl
            .read_stats()
            .expect_err("garbage in a required stats file must fail the whole read");
        let expected = path_in(t.dir.path(), "general_profit");
        assert!(
            err.to_string().contains(&expected),
            "error must name the garbage file {expected}: {err}"
        );
        assert!(
            err.to_string().contains("cannot parse 'abc' as i64"),
            "error must report the unparsable content: {err}"
        );
    }

    #[test]
    fn fault_read_i64_garbage_values_error_and_name_the_file() {
        for garbage in ["abc", "", "1.5", "0x10"] {
            let t = seeded![("general_profit", garbage)];
            let err = t.ctrl.read_i64("general_profit").expect_err(&format!(
                "read_i64({garbage:?}) must fail, never fall back to 0"
            ));
            let expected = path_in(t.dir.path(), "general_profit");
            assert!(
                err.to_string().contains(&expected),
                "error for {garbage:?} must name the file {expected}: {err}"
            );
            assert!(
                err.to_string()
                    .contains(&format!("cannot parse '{garbage}' as i64")),
                "error for {garbage:?} must report the unparsable content: {err}"
            );
        }
    }

    #[test]
    fn fault_garbage_knob_file_blocks_only_the_read_path() {
        // A knob file holding garbage is a READ failure, but it must not stop
        // the WRITE path: `set_run` overwrites the file, so the operator's
        // recovery write still lands with valid content.
        let t = seeded![("run", "abc")];

        let err = t
            .ctrl
            .read_u64("run")
            .expect_err("garbage 'run' must not parse");
        assert!(
            err.to_string().contains("cannot parse 'abc' as u64"),
            "read error must name the garbage: {err}"
        );

        t.ctrl.set_run(1).unwrap();
        assert_eq!(
            t.read("run"),
            "1",
            "the write path must replace garbage with the clamped value"
        );
        // And the replacement is genuinely readable now.
        assert_eq!(t.ctrl.read_u64("run").unwrap(), 1);
    }

    // ── (d) write failure ──────────────────────────────────────────────

    #[test]
    fn fault_write_param_to_read_only_file_errors_naming_the_path() {
        if !permission_bits_are_enforced() {
            eprintln!(
                "skipped: running with permission bits unenforced (root), \
                 a chmod-444 knob file is still writable"
            );
            return;
        }
        let t = seeded![("run", "0")];
        let knob = t.dir.path().join("run");
        set_mode(&knob, 0o444);

        let err = t
            .ctrl
            .write_param("run", "1")
            .expect_err("writing to a read-only knob file must fail");
        let expected = knob.display().to_string();
        assert!(
            matches!(err, TunedError::Sysfs { .. }),
            "expected a Sysfs error, got {err:?}"
        );
        assert!(
            err.to_string().contains(&expected),
            "error must name the unwritable path {expected}: {err}"
        );
        // The refused write must not be reported as success: the file still
        // holds its old value, which is what makes the write failure visible.
        set_mode(&knob, 0o644);
        assert_eq!(t.read("run"), "0", "no value may be written on failure");
    }

    #[test]
    fn fault_set_run_to_read_only_file_errors_naming_the_path() {
        if !permission_bits_are_enforced() {
            eprintln!("skipped: permission bits unenforced (root)");
            return;
        }
        let t = seeded![("pages_to_scan", "100"), ("run", "0")];
        let knob = t.dir.path().join("run");
        set_mode(&knob, 0o444);

        let err = t
            .ctrl
            .set_run(1)
            .expect_err("set_run on a read-only knob file must fail");
        let expected = knob.display().to_string();
        assert!(
            err.to_string().contains(&expected),
            "error must name the unwritable path {expected}: {err}"
        );
        set_mode(&knob, 0o644);
        assert_eq!(t.read("run"), "0");
    }

    #[test]
    fn fault_write_new_param_to_read_only_directory_errors_naming_the_path() {
        if !permission_bits_are_enforced() {
            eprintln!("skipped: permission bits unenforced (root)");
            return;
        }
        // A parameter that does not exist yet: creating it needs write
        // permission on the directory itself.
        let t = seeded![];
        set_mode(t.dir.path(), 0o555);

        let err = t
            .ctrl
            .write_param("future_knob", "1")
            .expect_err("creating a new entry in a read-only directory must fail");
        let expected = path_in(t.dir.path(), "future_knob");
        assert!(
            matches!(err, TunedError::Sysfs { .. }),
            "expected a Sysfs error, got {err:?}"
        );
        assert!(
            err.to_string().contains(&expected),
            "error must name the path {expected}: {err}"
        );
        set_mode(t.dir.path(), 0o755);
        assert!(
            !t.dir.path().join("future_knob").exists(),
            "a failed write must not leave a file behind"
        );
    }

    #[test]
    fn fault_write_param_to_deleted_directory_errors_naming_the_path() {
        // EPERM-independent, so it exercises the write-failure arm under root.
        let dir = tempfile::tempdir().expect("tempdir");
        let gone = dir.path().to_path_buf();
        dir.close().unwrap();

        let ctrl = controller_at(&gone);
        let err = ctrl
            .write_param("pages_to_scan", "100")
            .expect_err("writing into a deleted directory must fail");
        let expected = gone.join("pages_to_scan").display().to_string();
        assert!(
            matches!(err, TunedError::Sysfs { .. }),
            "expected a Sysfs error, got {err:?}"
        );
        assert!(
            err.to_string().contains(&expected),
            "error must name the path {expected}: {err}"
        );
    }

    #[test]
    fn fault_set_pages_to_scan_to_deleted_directory_errors_naming_the_path() {
        // Same universal failure through the validated setter, so the clamp
        // arithmetic cannot swallow the write error either.
        let dir = tempfile::tempdir().expect("tempdir");
        let gone = dir.path().to_path_buf();
        dir.close().unwrap();

        let ctrl = controller_at(&gone);
        let err = ctrl
            .set_pages_to_scan(500)
            .expect_err("set_pages_to_scan into a deleted directory must fail");
        let expected = gone.join("pages_to_scan").display().to_string();
        assert!(
            err.to_string().contains(&expected),
            "error must name the path {expected}: {err}"
        );
        assert_eq!(ctrl.clamp_value("pages_to_scan", 500), 500);
    }

    // ── (e) corrupt snapshot at restore time ───────────────────────────

    #[test]
    fn fault_restore_truncated_snapshot_errors_and_writes_nothing() {
        let t = seeded![
            ("run", "1"),
            ("pages_to_scan", "100"),
            ("sleep_millisecs", "5000"),
            ("max_page_sharing", "4096"),
            ("advisor_mode", "scan-time"),
            ("advisor_target_scan_time", "10"),
            ("advisor_max_cpu", "10"),
        ];
        let state_dir = t.dir.path().join("state");
        write_raw_snapshot(&state_dir, "{\"config\":{");

        let mut ctrl = controller_at(t.dir.path());
        let err = ctrl
            .restore(&state_dir)
            .expect_err("truncated snapshot JSON must abort restore");

        assert!(
            err.to_string().contains("snapshot"),
            "the error must identify the snapshot: {err}"
        );
        // No partial write: every sysfs file keeps its pre-restore value.
        assert_eq!(t.read("run"), "1");
        assert_eq!(t.read("pages_to_scan"), "100");
        assert_eq!(t.read("sleep_millisecs"), "5000");
        assert_eq!(t.read("max_page_sharing"), "4096");
        assert_eq!(t.read("advisor_mode"), "scan-time");
        assert_eq!(t.read("advisor_target_scan_time"), "10");
        assert_eq!(t.read("advisor_max_cpu"), "10");
    }

    #[test]
    fn fault_restore_empty_snapshot_file_errors_and_writes_nothing() {
        let t = seeded![
            ("run", "1"),
            ("pages_to_scan", "100"),
            ("sleep_millisecs", "5000"),
            ("max_page_sharing", "4096"),
            ("advisor_mode", "scan-time"),
            ("advisor_target_scan_time", "10"),
            ("advisor_max_cpu", "10"),
        ];
        let state_dir = t.dir.path().join("state");
        write_raw_snapshot(&state_dir, "");

        let mut ctrl = controller_at(t.dir.path());
        let err = ctrl
            .restore(&state_dir)
            .expect_err("an empty snapshot file must abort restore");

        assert!(
            err.to_string().contains("snapshot"),
            "the error must identify the snapshot: {err}"
        );
        assert_eq!(t.read("run"), "1");
        assert_eq!(t.read("pages_to_scan"), "100");
        assert_eq!(t.read("advisor_mode"), "scan-time");
    }

    #[test]
    fn fault_restore_unterminated_snapshot_errors_and_writes_nothing() {
        // Valid prefix, no closing brace: this is the shape a crash mid-write
        // leaves behind if the atomic rename is ever bypassed.
        let t = seeded![
            ("run", "1"),
            ("pages_to_scan", "100"),
            ("sleep_millisecs", "5000"),
            ("max_page_sharing", "4096"),
            ("advisor_mode", "scan-time"),
            ("advisor_target_scan_time", "10"),
            ("advisor_max_cu", "10"),
            ("advisor_max_cpu", "10"),
        ];
        let state_dir = t.dir.path().join("state");
        write_raw_snapshot(&state_dir, "{\"config\":{\"run\":1");

        let mut ctrl = controller_at(t.dir.path());
        let err = ctrl
            .restore(&state_dir)
            .expect_err("an unterminated snapshot must abort restore");

        assert!(
            err.to_string().contains("snapshot"),
            "the error must identify the snapshot: {err}"
        );
        assert_eq!(t.read("run"), "1");
        assert_eq!(t.read("pages_to_scan"), "100");
        assert_eq!(t.read("advisor_mode"), "scan-time");
    }

    #[test]
    fn fault_restore_unreadable_snapshot_file_errors_and_writes_nothing() {
        if !permission_bits_are_enforced() {
            eprintln!("skipped: permission bits unenforced (root)");
            return;
        }
        let t = seeded![
            ("run", "1"),
            ("pages_to_scan", "100"),
            ("advisor_mode", "scan-time"),
        ];
        let state_dir = t.dir.path().join("state");
        write_raw_snapshot(&state_dir, VALID_SNAPSHOT_JSON);
        set_mode(&state_dir.join(SNAPSHOT_FILENAME), 0o000);

        let mut ctrl = controller_at(t.dir.path());
        let result = ctrl.restore(&state_dir);
        set_mode(&state_dir.join(SNAPSHOT_FILENAME), 0o644);

        // An unreadable snapshot surfaces as an I/O error, NOT as a Snapshot
        // error, and it must still be an Err: nothing is written on a restore
        // that cannot even read its own state.
        let err = result.expect_err("an unreadable snapshot must abort restore");
        assert!(
            matches!(err, TunedError::Io(_)),
            "expected an I/O error, got {err:?}"
        );
        assert_eq!(t.read("run"), "1");
        assert_eq!(t.read("pages_to_scan"), "100");
        assert_eq!(t.read("advisor_mode"), "scan-time");
    }

    // ── (f) snapshot from a different kernel version ───────────────────

    #[test]
    fn fault_restore_ignores_unknown_snapshot_parameter() {
        // A snapshot taken on a kernel with an extra tunable: `future_knob` is
        // unknown to this build. `KsmConfig` is `#[serde(default)]` over a
        // FIXED field set, so the unknown key must be dropped by serde rather
        // than written into sysfs.
        let t = seeded![
            ("run", "0"),
            ("pages_to_scan", "100"),
            ("sleep_millisecs", "5000"),
            ("max_page_sharing", "4096"),
            ("advisor_mode", "scan-time"),
            ("advisor_target_scan_time", "10"),
            ("advisor_max_cpu", "10"),
            ("advisor_min_pages_to_scan", "5000"),
            ("advisor_max_pages_to_scan", "1000"),
        ];
        let state_dir = t.dir.path().join("state");

        let snapshot = serde_json::json!({
            "config": {
                "run": 1,
                "pages_to_scan": 700,
                "sleep_millisecs": 11,
                "max_page_sharing": 2048,
                "smart_scan": 1,
                "advisor_mode": "none",
                "advisor_target_scan_time": 250,
                "advisor_max_cpu": 90,
                "advisor_min_pages_to_scan": 400,
                "advisor_max_pages_to_scan": 9000,
                "future_knob": 42
            },
            "timestamp": "2026-10-15T00:00:00Z"
        });
        write_raw_snapshot(&state_dir, &snapshot.to_string());

        let mut ctrl = controller_at(t.dir.path());
        ctrl.restore(&state_dir)
            .expect("an unknown snapshot key must not fail the restore");

        // The unknown key never reaches sysfs.
        assert!(
            !t.dir.path().join("future_knob").exists(),
            "unknown parameter must never be written to sysfs"
        );
        let entries: Vec<String> = std::fs::read_dir(t.dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            !entries.iter().any(|n| n.contains("future_knob")),
            "no sysfs entry may be created for an unknown parameter: {entries:?}"
        );

        // Every KNOWN parameter restore is documented to write, restored.
        assert_eq!(t.ctrl.read_u64("run").unwrap(), 1);
        assert_eq!(t.ctrl.read_u64("pages_to_scan").unwrap(), 700);
        assert_eq!(t.ctrl.read_u64("sleep_millisecs").unwrap(), 11);
        assert_eq!(t.ctrl.read_u64("max_page_sharing").unwrap(), 2048);
        assert_eq!(t.ctrl.read_string("advisor_mode").unwrap(), "none");
        assert_eq!(t.ctrl.read_u64("advisor_target_scan_time").unwrap(), 250);
        assert_eq!(t.ctrl.read_u64("advisor_max_cpu").unwrap(), 90);
        // The two advisor page bounds are not written by restore, so they keep
        // the seeded kernel values — which proves the unknown key did not
        // silently widen the restore's parameter set.
        assert_eq!(t.read("advisor_min_pages_to_scan"), "5000");
        assert_eq!(t.read("advisor_max_pages_to_scan"), "1000");
    }

    #[test]
    fn fault_restore_aborts_on_first_failing_write_and_leaves_partial_state_visible() {
        // A snapshot whose `run` cannot be written (the sysfs entry is
        // missing, so the create fails with ENOENT) must ABORT restore with
        // an Err that names the path — not silently continue and leave the
        // operator believing the kernel still holds the old configuration.
        // This is the write-path twin of the corrupt-JSON tests: the abort
        // has to come from the write decision, not from a parse.
        let t = seeded![
            ("pages_to_scan", "100"),
            ("sleep_millisecs", "5000"),
            ("max_page_sharing", "4096"),
            ("advisor_mode", "none"),
            ("advisor_target_scan_time", "10"),
            ("advisor_max_cpu", "10"),
        ];
        let state_dir = t.dir.path().join("state");

        let snapshot = serde_json::json!({
            "config": {
                "run": 1,
                "pages_to_scan": 700,
                "sleep_millisecs": 11,
                "max_page_sharing": 2048,
                "smart_scan": 1,
                "advisor_mode": "none",
                "advisor_target_scan_time": 250,
                "advisor_max_cpu": 90,
                "advisor_min_pages_to_scan": 400,
                "advisor_max_pages_to_scan": 9000
            },
            "timestamp": "2026-10-15T00:00:00Z"
        });
        write_raw_snapshot(&state_dir, &snapshot.to_string());

        // Without write access to the directory, the very first restore write
        // (`run`) cannot be created; every later parameter would fail too, so
        // the abort point is what is under test.
        if !permission_bits_are_enforced() {
            eprintln!(
                "skipped: permission bits unenforced (root), \
                 the read-only-directory fault is unreachable"
            );
            return;
        }
        set_mode(t.dir.path(), 0o555);

        let mut ctrl = controller_at(t.dir.path());
        let result = ctrl.restore(&state_dir);
        set_mode(t.dir.path(), 0o755);

        let err = result.expect_err("a restore whose first write fails must abort");
        let expected = path_in(t.dir.path(), "run");
        assert!(
            err.to_string().contains(&expected),
            "the abort must name the parameter it could not write: {err}"
        );

        // The abort is real, not a partial success dressed up as an error:
        // the parameters that would have been written are still at their
        // pre-restore values.
        assert_eq!(
            t.read("pages_to_scan"),
            "100",
            "no later parameter may be written after the abort"
        );
        assert_eq!(t.read("sleep_millisecs"), "5000");
        assert_eq!(t.read("max_page_sharing"), "4096");
    }

    // ── (g) PARAM_RANGES clamping on restore ───────────────────────────
    #[test]
    fn fault_restore_clamps_out_of_range_snapshot_values() {
        let t = seeded![
            ("run", "0"),
            ("pages_to_scan", "100"),
            ("sleep_millisecs", "20"),
            ("max_page_sharing", "256"),
            ("advisor_mode", "none"),
            ("advisor_target_scan_time", "200"),
            ("advisor_max_cpu", "70"),
        ];
        let state_dir = t.dir.path().join("state");

        let snapshot = serde_json::json!({
            "config": {
                "run": 9,
                "pages_to_scan": 10_000_000,
                "sleep_millisecs": 999_999,
                "max_page_sharing": 999_999,
                "smart_scan": 1,
                "advisor_mode": "none",
                "advisor_target_scan_time": 999_999,
                "advisor_max_cpu": 250,
                "advisor_min_pages_to_scan": 1,
                "advisor_max_pages_to_scan": 10_000_000
            },
            "timestamp": "2026-10-15T00:00:00Z"
        });
        write_raw_snapshot(&state_dir, &snapshot.to_string());

        let mut ctrl = controller_at(t.dir.path());
        ctrl.restore(&state_dir).unwrap();

        // The requested values must NOT land; the PARAM_RANGES ceilings do.
        assert_eq!(t.read("pages_to_scan"), "30000");
        assert_eq!(t.read("sleep_millisecs"), "10000");
        assert_eq!(t.read("max_page_sharing"), "4096");
        assert_eq!(t.read("run"), "2");
        assert_eq!(t.read("advisor_target_scan_time"), "3600");
        assert_eq!(t.read("advisor_max_cpu"), "100");
        // And the clamped values are read back as numbers, not raw clobber.
        assert_eq!(t.ctrl.read_u64("pages_to_scan").unwrap(), 30000);
        assert_ne!(t.ctrl.read_u64("pages_to_scan").unwrap(), 10_000_000);
    }
}
