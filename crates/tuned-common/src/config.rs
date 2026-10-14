//! Configuration schema for tuned, deserialized from TOML.

use serde::Deserialize;
use std::path::Path;

/// Where the daemon looks for its configuration when `--config` is not given.
///
/// The fused daemon and the `tuned-zswap` binary must agree, so this is one
/// constant rather than a repeated string literal.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/tuned.toml";

/// Top-level configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TunedConfig {
    pub general: GeneralConfig,
    pub governor: GovernorConfig,
    pub scanner: ScannerConfig,
    pub zswap: ZswapConfig,
}

impl TunedConfig {
    /// Load configuration from a TOML file path.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values are within safe ranges.
    pub fn validate(&self) -> anyhow::Result<()> {
        // Governor validation
        if self.governor.psi_some_threshold < 0.0 || self.governor.psi_some_threshold > 100.0 {
            anyhow::bail!("governor.psi_some_threshold must be between 0 and 100");
        }
        if self.governor.psi_full_threshold < 0.0 || self.governor.psi_full_threshold > 100.0 {
            anyhow::bail!("governor.psi_full_threshold must be between 0 and 100");
        }
        if self.governor.advisor_scan_time_range.0 >= self.governor.advisor_scan_time_range.1 {
            anyhow::bail!("governor.advisor_scan_time_range: min must be < max");
        }
        if self.governor.max_page_sharing_range.0 >= self.governor.max_page_sharing_range.1 {
            anyhow::bail!("governor.max_page_sharing_range: min must be < max");
        }

        // Scanner validation
        if self.scanner.min_anon_rss_mb == 0 {
            anyhow::bail!("scanner.min_anon_rss_mb must be > 0");
        }
        if self.scanner.duplicate_ratio_threshold <= 0.0
            || self.scanner.duplicate_ratio_threshold > 1.0
        {
            anyhow::bail!("scanner.duplicate_ratio_threshold must be in (0, 1]");
        }

        // A zero stats_path would make every recording attempt fail; the
        // default path is always valid, so only reject an explicitly empty one.
        if self.zswap.enabled && self.zswap.stats_path.trim().is_empty() {
            anyhow::bail!("zswap.stats_path must not be empty when zswap.enabled");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub log_level: String,
    pub poll_interval_ms: u64,
    pub state_dir: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            poll_interval_ms: 2000,
            state_dir: "/var/lib/tuned".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GovernorConfig {
    pub enabled: bool,
    /// When true, kernel advisor controls scan rate; governor only biases
    /// max_page_sharing and sleep bounds (Option B — avoids fighting the advisor).
    /// When false, governor has full manual control over all KSM parameters.
    pub use_advisor: bool,
    pub psi_some_threshold: f32,
    pub psi_full_threshold: f32,
    pub advisor_scan_time_range: (u64, u64),
    pub max_page_sharing_range: (u32, u32),
    pub hysteresis_readings: u32,
    pub min_level_duration_secs: u64,
    /// Stabilization window (seconds): minimum time between repeated actions
    /// within the same tier. Governor and scanner keep separate timestamps so
    /// one tier cannot starve another.
    pub stabilization_secs: u64,
    /// Path to KSM sysfs directory.
    pub ksm_path: String,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            use_advisor: true,
            psi_some_threshold: 5.0,
            psi_full_threshold: 2.0,
            advisor_scan_time_range: (30, 600),
            max_page_sharing_range: (256, 1024),
            hysteresis_readings: 4,
            min_level_duration_secs: 30,
            stabilization_secs: 30,
            ksm_path: "/sys/kernel/mm/ksm".to_string(),
        }
    }
}

/// The zswap subsystem, driven by the `tuned_zswap` library.
///
/// These are the *operational* switches only. The decision policy itself —
/// the 15 s poll, the 10 pp step, the `[25, 50]` clamp, the 2.2/1.5 ratio
/// thresholds and the 3-reading debounce — deliberately lives in
/// `tuned_zswap`'s frozen constants. Making thresholds configurable here would
/// create a second place to change behaviour and a config file that could
/// silently disable the tuning; the reason those values are pinned is
/// documented in the crate's own README.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ZswapConfig {
    /// Run the zswap tuning task at all. False leaves `max_pool_percent`
    /// untouched and records nothing.
    pub enabled: bool,
    /// Override the decision poll cadence. 0 means "use the library default"
    /// (15 s); the value is not clamped, so a deliberately short test cadence
    /// is expressible without a second mechanism.
    pub interval_secs: u64,
    /// Override the JSONL recording cadence. 0 means the library default
    /// (60 s), which the `TUNED_ZSWAP_RECORD_INTERVAL` environment variable can
    /// override at runtime for testing.
    pub record_interval_secs: u64,
    /// Where the JSONL history is written. The daemon's own logrotate unit
    /// targets this path by default.
    pub stats_path: String,
}

impl Default for ZswapConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 0,
            record_interval_secs: 0,
            stats_path: "/var/log/tuned-zswap/stats.jsonl".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScannerConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub min_anon_rss_mb: u64,
    pub duplicate_ratio_threshold: f32,
    pub blocklist: Vec<String>,
    pub target_cgroups: Vec<String>,
    /// Maximum number of processes to enable cross-process KSM eligibility on
    /// per scan cycle. Bounds the cost of a ptrace burst.
    pub max_candidates_per_cycle: usize,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            min_anon_rss_mb: 100,
            duplicate_ratio_threshold: 0.15,
            blocklist: vec![
                "tuned".to_string(),
                "ksmd".to_string(),
                "systemd".to_string(),
                "sshd".to_string(),
                // Browsers are blocked by default, not by configuration. Their
                // anonymous memory is dominated by JIT-compiled code that is
                // mapped, written, and re-forked far faster than any userspace
                // guard can track, and merging executable pages across
                // renderer processes crashes them with SIGILL. Chromium's
                // kernel comm is `chrome` (PR_SET_NAME truncates to 15 chars);
                // the names below cover Chromium builds under other comms and
                // the Firefox family.
                "chrome".to_string(),
                "chromium".to_string(),
                "firefox".to_string(),
                "msedge".to_string(),
                "brave".to_string(),
                "opera".to_string(),
                "vivaldi".to_string(),
                "electron".to_string(),
            ],
            target_cgroups: vec![],
            max_candidates_per_cycle: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validates() {
        let cfg = TunedConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_parse_toml() {
        let toml_str = r#"
[general]
log_level = "debug"
poll_interval_ms = 1000

[governor]
enabled = true
use_advisor = true

[scanner]
enabled = false
"#;
        let cfg: TunedConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.general.log_level, "debug");
        assert_eq!(cfg.general.poll_interval_ms, 1000);
        assert!(!cfg.scanner.enabled);
    }

    #[test]
    fn test_zswap_defaults_are_tuning_switches_only() {
        let cfg = TunedConfig::default();
        assert!(cfg.zswap.enabled);
        // 0 means "use the library default"; the policy constants are not
        // duplicated into the config schema.
        assert_eq!(cfg.zswap.interval_secs, 0);
        assert_eq!(cfg.zswap.record_interval_secs, 0);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_zswap_section_parses_from_toml() {
        let toml_str = r#"
[zswap]
enabled = false
interval_secs = 5
stats_path = "/tmp/other.jsonl"
"#;
        let cfg: TunedConfig = toml::from_str(toml_str).unwrap();
        assert!(!cfg.zswap.enabled);
        assert_eq!(cfg.zswap.interval_secs, 5);
        assert_eq!(cfg.zswap.stats_path, "/tmp/other.jsonl");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_empty_zswap_stats_path() {
        let mut cfg = TunedConfig::default();
        cfg.zswap.stats_path = "  ".to_string();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("zswap.stats_path"));
    }

    #[test]
    fn test_empty_stats_path_is_fine_when_zswap_is_off() {
        // The path is only read when the subsystem runs; an operator who
        // disabled zswap should not be forced to pick a path.
        let mut cfg = TunedConfig::default();
        cfg.zswap.enabled = false;
        cfg.zswap.stats_path = String::new();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_invalid_governor_thresholds() {
        let mut cfg = TunedConfig::default();
        cfg.governor.psi_some_threshold = -0.1;
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("psi_some_threshold"));

        cfg = TunedConfig::default();
        cfg.governor.psi_full_threshold = 101.0;
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("psi_full_threshold"));
    }

    #[test]
    fn test_validate_rejects_invalid_governor_ranges() {
        let mut cfg = TunedConfig::default();
        cfg.governor.advisor_scan_time_range = (10, 10);
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("advisor_scan_time_range"));

        cfg = TunedConfig::default();
        cfg.governor.max_page_sharing_range = (1024, 256);
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_page_sharing_range"));
    }

    #[test]
    fn test_validate_rejects_invalid_scanner_values() {
        let mut cfg = TunedConfig::default();
        cfg.scanner.min_anon_rss_mb = 0;
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("min_anon_rss_mb"));

        cfg = TunedConfig::default();
        cfg.scanner.duplicate_ratio_threshold = 0.0;
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate_ratio_threshold"));
    }
}
