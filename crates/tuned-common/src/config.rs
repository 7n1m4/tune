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
                //
                // The shell-scoped entries are the point of the list's size.
                // `comm` holds whatever the process last set via PR_SET_NAME,
                // and both engine families rename their children away from the
                // browser name to a role name — Firefox's content process runs
                // as `Isolated Web Co` or `Web Content`, neither of which is
                // `firefox`, so a `firefox` entry alone catches only the parent
                // process and every renderer it forks. A 2026-10-15 live run
                // proved the gap: 6 Firefox processes were marked and left with
                // 90–154 executable VMAs unprotected, and the only reason
                // nothing crashed is that ksmd never completed a scan in 2m23s.
                // Chromium sets its child comm to `chrome`, so its entries are
                // belt-and-braces, not a fix.
                //
                // Confirm the spellings before adding one: read them off a live
                // process (`cat /proc/PID/comm`), or out of the engine binary
                // (`strings libxul.so | grep -a WebExtensions`). Both are
                // truncated to 15 bytes by the kernel, so `Privileged Cont` is
                // the real value for the process whose full name is
                // `Privileged Content`, and an entry written from the full name
                // would never match.
                "chrome".to_string(),
                "chromium".to_string(),
                "firefox".to_string(),
                "msedge".to_string(),
                "brave".to_string(),
                "opera".to_string(),
                "vivaldi".to_string(),
                "electron".to_string(),
                // Firefox's per-process shell-scoped comms. Observed live on
                // 7.3.0-rc6 on 2026-10-15 alongside `firefox` (pids counted off
                // `/proc/PID/comm` with `readlink /proc/PID/exe` confirming
                // `/usr/lib/firefox/firefox`); the strings are present in
                // libxul.so, so they are not build-local.
                //
                // `Isolated Web Co` and `Web Content` are BOTH real, live,
                // coexisting comms for the *same* `-contentproc -isForBrowser`
                // role — 5 processes run as one and 3 as the other right now,
                // with byte-identical cmdlines. Neither implies the other, so
                // both entries are required:
                //   * `Isolated Web Content` is the libxul string; the kernel
                //     truncates it to 15 bytes as `Isolated Web Co`. There is
                //     no literal `Isolated Web Co` string in the binary — it is
                //     produced by `PR_SET_NAME` + truncation, which is why an
                //     entry spelled from libxul alone would have missed it.
                //   * `Web Content` is a separate, shorter libxul string that is
                //     set verbatim, so it is NOT a truncation of anything.
                // They are stable per process: watching a pid over a minute
                // never observed a switch between the two.
                "Isolated Web Co".to_string(),
                "Web Content".to_string(),
                "WebExtensions".to_string(),
                "Socket Process".to_string(),
                "RDD Process".to_string(),
                "Privileged Cont".to_string(),
                "Utility Process".to_string(),
                // The Firefox crash handler's comm, confirmed as a string in
                // libxul.so. `Utility Process` and this one are the
                // generic-sounding entries, and that is deliberate — they are
                // real, and a name that reads as generic has killed a browser
                // already.
                "Crash Reporter".to_string(),
                // Deliberately NOT `crashpad_handler`: that is Chromium's bare
                // handler binary, but it is 16 bytes, so the kernel truncates
                // the comm to `crashpad_handl` and the full string can never
                // match anything. Chromium's real handler is
                // `chrome_crashpad_handler`, truncated to `chrome_crashpad`,
                // which the `chrome` entry above already covers — live on this
                // host right now. An inert entry is worse than a missing one:
                // it reads as a fix and stops anyone looking.
                //
                // Do NOT add `GMPLauncher` either: no such process was alive to
                // read and the string is not in libxul.so, so it is
                // unconfirmed. Confirm against `<firefox>/libxul.so`
                // (`strings -a libxul.so | grep GMPLauncher`) or a live
                // process before adding it.
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

    // ------------------------------------------------------------------
    // Fault injection: the config file boundary failing
    //
    // `TunedConfig::load` is the daemon's only configuration entry point, and
    // every failure shape below is one an operator can produce: the file is
    // missing, the mode denies the read, the file is a directory, the TOML is
    // syntactically broken, or the types are wrong. The contract under test is
    // that each failure is *reported* — with the offending file or key — and
    // never silently replaced by defaults.
    // ------------------------------------------------------------------

    /// A config file that does not exist must fail rather than fall back to
    /// defaults: `load` is the strict entry point, and the caller decides
    /// whether a missing file is fatal. The fallback itself lives one layer up
    /// in the daemon's `load_config_or_default`.
    #[test]
    fn test_load_missing_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-config.toml");
        assert!(!missing.exists(), "the fixture really is absent");

        let err = TunedConfig::load(&missing).expect_err("a missing config file is not a load");
        assert!(
            err.to_string().contains("No such file or directory"),
            "the error must be the read failure, got: {err}"
        );
    }

    /// A config file the daemon cannot read must fail with the reason. Under
    /// uid 0 the mode bits do not apply, so the test branches on what the host
    /// actually does rather than asserting a fault that does not happen.
    #[test]
    fn test_load_unreadable_file_reports_or_parses_as_root() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tuned.toml");
        std::fs::write(&path, "[general]\nlog_level = \"debug\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        match TunedConfig::load(&path) {
            Err(e) => {
                let message = e.to_string();
                assert!(
                    message.contains("Permission denied") || message.contains("os error"),
                    "the refusal must carry the kernel reason, got: {message}"
                );
            }
            // Root ignores the mode bits, so the load proceeds and must land on
            // the parsed value rather than a default.
            Ok(cfg) => assert_eq!(
                cfg.general.log_level, "debug",
                "a successful load must honour the file's contents"
            ),
        }
    }

    /// A directory is not a config file. `EISDIR` applies to root as well, so
    /// this fault is injectable without a privilege branch and must not be
    /// treated as an empty config.
    #[test]
    fn test_load_a_directory_fails() {
        let dir = tempfile::tempdir().unwrap();
        let as_dir = dir.path().join("tuned.toml");
        std::fs::create_dir(&as_dir).unwrap();

        let err = TunedConfig::load(&as_dir).expect_err("a directory is not a TOML document");
        assert!(
            err.to_string().contains("Is a directory"),
            "the error must be the EISDIR read failure, got: {err}"
        );
    }

    /// Syntactically broken TOML must fail with the offending line. The point
    /// is that the caller sees the syntax error, not a partially-defaulted
    /// config that silently changes tuning behaviour.
    #[test]
    fn test_load_broken_toml_reports_the_syntax_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.toml");
        std::fs::write(&path, "[general\nlog_level = \"debug\"\n").unwrap();

        let err = TunedConfig::load(&path).expect_err("unclosed brackets are not valid TOML");
        let message = err.to_string();
        assert!(
            message.contains("TOML parse error") || message.contains("expected"),
            "the error must be a parse error, got: {message}"
        );
    }

    /// Well-formed TOML with a wrong type is the fault that a hand-edited
    /// config file produces. It must fail, and it must fail naming the key so
    /// the operator can find it.
    #[test]
    fn test_load_wrong_typed_value_reports_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("typed.toml");
        std::fs::write(&path, "[general]\npoll_interval_ms = \"not a number\"\n").unwrap();

        let err = TunedConfig::load(&path).expect_err("a string is not a u64");
        let message = err.to_string();
        assert!(
            message.contains("poll_interval_ms"),
            "the error must name the offending key, got: {message}"
        );
    }

    /// A config that parses but violates a safety invariant must be rejected by
    /// `validate` before the daemon runs with it. This is the one fault TOML
    /// alone cannot catch, so the error must name the field.
    #[test]
    fn test_load_rejects_a_config_that_parses_but_is_unsafe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsafe.toml");
        std::fs::write(
            &path,
            "[scanner]\nmin_anon_rss_mb = 0\n[governor]\npsi_some_threshold = -1.0\n",
        )
        .unwrap();

        let err = TunedConfig::load(&path).expect_err("an out-of-range threshold is unusable");
        assert!(
            err.to_string().contains("psi_some_threshold"),
            "the validation error must name the offending field, got: {err}"
        );
    }

    /// The default config path is shared between the daemon and the zswap
    /// binary, so the two must agree. A divergence would mean the daemon reads
    /// one file while the standalone tool reads another.
    #[test]
    fn test_default_config_path_is_the_documented_location() {
        assert_eq!(DEFAULT_CONFIG_PATH, "/etc/tuned.toml");
        assert!(
            Path::new(DEFAULT_CONFIG_PATH).is_absolute(),
            "a relative default would depend on the daemon's working directory"
        );
    }
}
