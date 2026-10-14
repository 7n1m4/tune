//! PSI (Pressure Stall Information) monitoring module.
//!
//! Supports both polling and event-driven (kernel trigger) modes
//! for monitoring memory pressure via /proc/pressure/memory.

use crate::error::{Result, TunedError};
use std::fs;
use std::path::{Path, PathBuf};

const PSI_MEMORY_PATH: &str = "/proc/pressure/memory";

/// Parsed PSI stats for a single resource.
#[derive(Debug, Clone, Default)]
pub struct PsiStats {
    pub some: PsiLine,
    pub full: PsiLine,
}

/// One line of PSI data (some or full).
#[derive(Debug, Clone, Default)]
pub struct PsiLine {
    pub avg10: f32,
    pub avg60: f32,
    pub avg300: f32,
    pub total: u64,
}

/// Classified pressure level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PressureLevel {
    Idle = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl std::fmt::Display for PressureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl PsiStats {
    /// Read and parse current memory PSI stats.
    pub fn read_memory() -> Result<Self> {
        Self::read_from(Path::new(PSI_MEMORY_PATH))
    }

    /// Read PSI stats from an arbitrary path (useful for cgroup PSI).
    pub fn read_from(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| TunedError::Sysfs {
            path: path.to_path_buf(),
            source: e,
        })?;
        Self::parse(&content)
    }

    /// Parse PSI file content.
    ///
    /// Format:
    /// ```text
    /// some avg10=0.48 avg60=0.75 avg300=0.63 total=352754638
    /// full avg10=0.12 avg60=0.34 avg300=0.45 total=241562312
    /// ```
    pub fn parse(content: &str) -> Result<Self> {
        let mut stats = PsiStats::default();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parsed = Self::parse_line(line)?;

            if line.starts_with("some") {
                stats.some = parsed;
            } else if line.starts_with("full") {
                stats.full = parsed;
            }
        }

        Ok(stats)
    }

    fn parse_line(line: &str) -> Result<PsiLine> {
        let mut psi_line = PsiLine::default();

        // Skip the first word ("some" or "full")
        for token in line.split_whitespace().skip(1) {
            if let Some((key, value)) = token.split_once('=') {
                match key {
                    "avg10" => {
                        psi_line.avg10 = value.parse().unwrap_or(0.0);
                    }
                    "avg60" => {
                        psi_line.avg60 = value.parse().unwrap_or(0.0);
                    }
                    "avg300" => {
                        psi_line.avg300 = value.parse().unwrap_or(0.0);
                    }
                    "total" => {
                        psi_line.total = value.parse().unwrap_or(0);
                    }
                    _ => {}
                }
            }
        }

        Ok(psi_line)
    }

    /// Classify pressure into a level using configurable thresholds.
    pub fn classify(&self, some_threshold: f32, full_threshold: f32) -> PressureLevel {
        let score = 0.7 * self.full.avg10 + 0.3 * self.some.avg10;

        if score >= 20.0 {
            PressureLevel::Critical
        } else if score >= 10.0 || self.full.avg10 >= full_threshold * 2.0 {
            PressureLevel::High
        } else if score >= 5.0 || self.some.avg10 >= some_threshold {
            PressureLevel::Medium
        } else if score >= 0.5 {
            PressureLevel::Low
        } else {
            PressureLevel::Idle
        }
    }
}

/// PSI trigger for event-driven monitoring.
///
/// Owns its own file descriptor to `/proc/pressure/memory` and manages
/// the full lifecycle: open → register trigger → re-arm → close.
///
/// PSI triggers are **edge-triggered**: after each event fires, the
/// trigger must be re-armed by re-writing the trigger string. The
/// `rearm()` method handles this.
pub struct PsiTrigger {
    /// Owned file descriptor (closed on Drop).
    fd: std::os::unix::io::RawFd,
    path: PathBuf,
    pub kind: PsiTriggerKind,
    pub threshold_us: u64,
    pub window_us: u64,
    /// The trigger string (cached for re-arm).
    trigger_str: String,
}

#[derive(Debug, Clone, Copy)]
pub enum PsiTriggerKind {
    Some,
    Full,
}

impl PsiTrigger {
    /// Create a new PSI trigger: opens `/proc/pressure/memory`, writes the
    /// trigger string, and returns a ready-to-epoll trigger.
    ///
    /// Window range: 500_000 to 10_000_000 (500ms to 10s).
    pub fn new(kind: PsiTriggerKind, threshold_us: u64, window_us: u64) -> Result<Self> {
        Self::new_from_path(Path::new(PSI_MEMORY_PATH), kind, threshold_us, window_us)
    }

    /// Create a trigger using an explicit PSI path. This is primarily useful
    /// for tests and cgroup PSI files.
    pub fn new_from_path(
        path: &Path,
        kind: PsiTriggerKind,
        threshold_us: u64,
        window_us: u64,
    ) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;

        // Open our own fd to the PSI file with O_RDWR.
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_RDWR)
            .open(path)
            .map_err(|e| TunedError::Sysfs {
                path: path.to_path_buf(),
                source: e,
            })?;

        use std::os::unix::io::IntoRawFd;
        let fd = file.into_raw_fd();

        let kind_str = match kind {
            PsiTriggerKind::Some => "some",
            PsiTriggerKind::Full => "full",
        };
        let trigger_str = format!("{kind_str} {threshold_us} {window_us}");

        // Write the trigger string to register with the kernel
        Self::write_trigger_to_path(fd, &trigger_str, path)?;

        Ok(Self {
            fd,
            path: path.to_path_buf(),
            kind,
            threshold_us,
            window_us,
            trigger_str,
        })
    }

    /// Re-arm the trigger after an edge event fires.
    ///
    /// PSI triggers are edge-triggered: after epoll returns POLLPRI,
    /// the trigger must be re-written to fire again. This method
    /// re-writes the cached trigger string.
    pub fn rearm(&self) -> Result<()> {
        Self::write_trigger_to_path(self.fd, &self.trigger_str, &self.path)
    }

    /// Get the raw fd for use with epoll/tokio.
    pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.fd
    }

    /// Internal: write trigger string to fd.
    #[cfg(test)]
    fn write_trigger(fd: std::os::unix::io::RawFd, trigger_str: &str) -> Result<()> {
        Self::write_trigger_to_path(fd, trigger_str, Path::new(PSI_MEMORY_PATH))
    }

    fn write_trigger_to_path(
        fd: std::os::unix::io::RawFd,
        trigger_str: &str,
        path: &Path,
    ) -> Result<()> {
        use std::io::Write;
        use std::os::unix::io::FromRawFd;

        // Safety: we borrow the fd temporarily, the caller/PsiTrigger owns it.
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let result = file
            .write_all(trigger_str.as_bytes())
            .map_err(|e| TunedError::Sysfs {
                path: path.to_path_buf(),
                source: e,
            });
        // Don't drop the file — we don't own the fd.
        std::mem::forget(file);

        result
    }
}

impl Drop for PsiTrigger {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_psi_content() {
        let content = "some avg10=1.07 avg60=0.46 avg300=0.49 total=351068534\n\
                        full avg10=0.50 avg60=0.25 avg300=0.30 total=200000000\n";

        let stats = PsiStats::parse(content).unwrap();
        assert!((stats.some.avg10 - 1.07).abs() < 0.001);
        assert!((stats.full.avg10 - 0.50).abs() < 0.001);
        assert_eq!(stats.some.total, 351068534);
        assert_eq!(stats.full.total, 200000000);
    }

    #[test]
    fn test_classify_idle() {
        let stats = PsiStats {
            some: PsiLine {
                avg10: 0.1,
                avg60: 0.05,
                ..Default::default()
            },
            full: PsiLine {
                avg10: 0.0,
                avg60: 0.0,
                ..Default::default()
            },
        };
        assert_eq!(stats.classify(5.0, 2.0), PressureLevel::Idle);
    }

    #[test]
    fn test_classify_high() {
        let stats = PsiStats {
            some: PsiLine {
                avg10: 12.0,
                avg60: 8.0,
                ..Default::default()
            },
            full: PsiLine {
                avg10: 8.0,
                avg60: 5.0,
                ..Default::default()
            },
        };
        let level = stats.classify(5.0, 2.0);
        assert!(level >= PressureLevel::High);
    }

    #[test]
    fn test_display_idle() {
        assert_eq!(PressureLevel::Idle.to_string(), "idle");
        assert_eq!(PressureLevel::Low.to_string(), "low");
        assert_eq!(PressureLevel::Medium.to_string(), "medium");
        assert_eq!(PressureLevel::High.to_string(), "high");
        assert_eq!(PressureLevel::Critical.to_string(), "critical");
    }

    #[test]
    fn test_parse_empty_content() {
        let stats = PsiStats::parse("").unwrap();
        assert!((stats.some.avg10 - 0.0).abs() < 0.001);
        assert!((stats.full.avg10 - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_parse_blank_lines() {
        let content = "\n\nsome avg10=0.50 avg60=0.25 avg300=0.10 total=1000\n\nfull avg10=0.10 avg60=0.05 avg300=0.02 total=500\n\n";
        let stats = PsiStats::parse(content).unwrap();
        assert!((stats.some.avg10 - 0.50).abs() < 0.001);
        assert!((stats.full.avg10 - 0.10).abs() < 0.001);
    }

    #[test]
    fn test_parse_malformed_token_skipped() {
        // token without '=' should be skipped without error
        let content = "some garbage avg10=1.0 avg60=0.5 avg300=0.1 total=100";
        let stats = PsiStats::parse(content).unwrap();
        assert!((stats.some.avg10 - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_parse_unknown_key_skipped() {
        // unknown key=value pairs should be silently skipped
        let content = "some avg10=1.0 avg60=0.5 avg300=0.1 unknown=42 total=100";
        let stats = PsiStats::parse(content).unwrap();
        assert!((stats.some.avg10 - 1.0).abs() < 0.001);
        assert_eq!(stats.some.total, 100);
    }

    #[test]
    fn test_classify_low() {
        // score = 0.7*0.0 + 0.3*2.0 = 0.6 → Low
        let stats_low = PsiStats {
            some: PsiLine {
                avg10: 2.0,
                avg60: 1.0,
                avg300: 0.5,
                total: 100,
            },
            full: PsiLine {
                avg10: 0.0,
                avg60: 0.0,
                avg300: 0.0,
                total: 0,
            },
        };
        // score = 0.7*0.0 + 0.3*2.0 = 0.6 → Low
        assert_eq!(stats_low.classify(5.0, 2.0), PressureLevel::Low);
    }

    #[test]
    fn test_classify_medium() {
        // score >= 5.0 || some.avg10 >= some_threshold (5.0)
        let stats = PsiStats {
            some: PsiLine {
                avg10: 5.0,
                avg60: 2.0,
                avg300: 0.5,
                total: 100,
            },
            full: PsiLine {
                avg10: 0.0,
                avg60: 0.0,
                avg300: 0.0,
                total: 0,
            },
        };
        assert_eq!(stats.classify(5.0, 2.0), PressureLevel::Medium);
    }

    #[test]
    fn test_classify_critical() {
        let stats = PsiStats {
            some: PsiLine {
                avg10: 30.0,
                avg60: 20.0,
                avg300: 10.0,
                total: 500,
            },
            full: PsiLine {
                avg10: 25.0,
                avg60: 15.0,
                avg300: 8.0,
                total: 300,
            },
        };
        // score = 0.7*25 + 0.3*30 = 17.5 + 9 = 26.5 >= 20 → Critical
        assert_eq!(stats.classify(5.0, 2.0), PressureLevel::Critical);
    }

    #[test]
    fn test_classify_high_via_full_threshold() {
        // full.avg10 >= full_threshold * 2.0 (4.0) → High even if score is low
        let stats = PsiStats {
            some: PsiLine {
                avg10: 0.5,
                avg60: 0.3,
                avg300: 0.1,
                total: 10,
            },
            full: PsiLine {
                avg10: 4.0,
                avg60: 2.0,
                avg300: 1.0,
                total: 5,
            },
        };
        assert_eq!(stats.classify(5.0, 2.0), PressureLevel::High);
    }

    #[test]
    fn test_psi_stats_default_zeroes() {
        let stats = PsiStats::default();
        assert!((stats.some.avg10 - 0.0).abs() < 0.001);
        assert_eq!(stats.some.total, 0);
        assert!((stats.full.avg10 - 0.0).abs() < 0.001);
        assert_eq!(stats.full.total, 0);
    }

    #[test]
    fn test_pressure_level_ordering() {
        assert!(PressureLevel::Idle < PressureLevel::Low);
        assert!(PressureLevel::Low < PressureLevel::Medium);
        assert!(PressureLevel::Medium < PressureLevel::High);
        assert!(PressureLevel::High < PressureLevel::Critical);
    }

    #[test]
    fn test_read_from_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.pressure");
        std::fs::write(
            &path,
            "some avg10=2.50 avg60=1.50 avg300=0.50 total=123\n\
             full avg10=0.25 avg60=0.15 avg300=0.05 total=45\n",
        )
        .unwrap();

        let stats = PsiStats::read_from(&path).unwrap();
        assert!((stats.some.avg10 - 2.50).abs() < 0.001);
        assert!((stats.full.avg60 - 0.15).abs() < 0.001);
        assert_eq!(stats.some.total, 123);
        assert_eq!(stats.full.total, 45);
    }

    #[test]
    fn test_read_memory_reads_real_proc_when_available() {
        if !Path::new(PSI_MEMORY_PATH).exists() {
            return;
        }

        let stats = PsiStats::read_memory().unwrap();
        assert!(stats.some.total > 0 || stats.full.total > 0);
    }

    #[test]
    fn test_psi_trigger_new_from_path_writes_and_rearms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.pressure");
        std::fs::write(&path, "").unwrap();

        let trigger =
            PsiTrigger::new_from_path(&path, PsiTriggerKind::Some, 1000, 500_000).expect("trigger");
        assert_eq!(trigger.threshold_us, 1000);
        assert_eq!(trigger.window_us, 500_000);
        assert!(trigger.as_raw_fd() >= 0);

        trigger.rearm().unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("some 1000 500000"));
        assert_eq!(content.matches("some 1000 500000").count(), 2);
    }

    #[test]
    fn test_psi_trigger_full_kind_string() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.pressure");
        std::fs::write(&path, "").unwrap();

        let trigger = PsiTrigger::new_from_path(&path, PsiTriggerKind::Full, 2000, 1_000_000)
            .expect("trigger");
        drop(trigger);

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "full 2000 1000000");
    }

    #[test]
    fn test_psi_trigger_drop_closes_fd() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.pressure");
        std::fs::write(&path, "").unwrap();

        let fd = {
            let trigger =
                PsiTrigger::new_from_path(&path, PsiTriggerKind::Some, 1000, 500_000).unwrap();
            trigger.as_raw_fd()
        };

        let byte = b"x";
        let ret = unsafe { libc::write(fd, byte.as_ptr().cast(), byte.len()) };
        assert_eq!(ret, -1);
        let errno = unsafe { *libc::__errno_location() };
        assert_eq!(errno, libc::EBADF);
    }

    #[test]
    fn test_write_trigger_reports_bad_fd() {
        use std::os::unix::io::IntoRawFd;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.pressure");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let fd = file.into_raw_fd();
        unsafe {
            libc::close(fd);
        }

        let err = PsiTrigger::write_trigger(fd, "some 1 500000").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("Bad file descriptor") || message.contains("os error"));
    }

    #[test]
    fn test_rearm_reports_closed_fd() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.pressure");
        std::fs::write(&path, "").unwrap();

        let trigger = std::mem::ManuallyDrop::new(
            PsiTrigger::new_from_path(&path, PsiTriggerKind::Some, 1000, 500_000).unwrap(),
        );
        unsafe {
            libc::close(trigger.as_raw_fd());
        }

        let err = trigger.rearm().unwrap_err();
        let message = err.to_string();
        assert!(message.contains("Bad file descriptor") || message.contains("os error"));
    }

    // ------------------------------------------------------------------
    // Fault injection: the `/proc/pressure/memory` boundary failing
    //
    // Every case below is a way the kernel can hand the daemon something it
    // cannot use: the file disappears, the inode is not a readable file, the
    // contents are truncated, or a number is not a number. They are driven
    // through the `read_from` seam so the test never has to touch the live
    // `/proc/pressure/memory`.
    // ------------------------------------------------------------------

    /// The PSI file that exists is not guaranteed to be readable. A path whose
    /// `stat` fails — here a directory, which is `EISDIR` for every uid
    /// including root — must produce an error carrying the path, not a
    /// zeroed `PsiStats` that would read as "memory pressure is fine".
    #[test]
    fn test_read_from_a_directory_reports_the_path_not_zero_pressure() {
        let dir = tempfile::tempdir().unwrap();

        let err = PsiStats::read_from(dir.path()).expect_err("a directory is not PSI data");
        let message = err.to_string();
        assert!(
            message.contains(dir.path().to_str().unwrap()),
            "the error must name the path it could not read, got: {message}"
        );
        assert!(
            message.contains("Is a directory") || message.contains("os error"),
            "the error must carry the kernel reason, got: {message}"
        );
    }

    /// A file that cannot be opened at all — here a symlink cycle, which fails
    /// with `ELOOP` for an unprivileged user *and* for root, so this is the one
    /// unreadable-file shape that is not uid-dependent — must also be an error
    /// and not a silent zero.
    #[test]
    fn test_read_from_a_symlink_cycle_reports_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.pressure");
        std::os::unix::fs::symlink(&path, &path).unwrap();

        let err = PsiStats::read_from(&path).expect_err("a symlink cycle has no content");
        assert!(
            err.to_string().contains("memory.pressure"),
            "the error must name the path it could not read, got: {err}"
        );
    }

    /// A file the daemon is allowed to open but whose mode denies reading.
    /// Under uid 0 the read succeeds, so the assertion branches on what the
    /// host actually does rather than pretending the fault happened.
    #[test]
    fn test_read_from_a_mode_000_file_reports_permission_or_succeeds_as_root() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.pressure");
        std::fs::write(&path, "some avg10=1.0 total=1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        match PsiStats::read_from(&path) {
            Err(e) => {
                // Unprivileged: the refusal must be attributed to this file.
                assert!(
                    e.to_string().contains("memory.pressure"),
                    "the refusal must name the file, got: {e}"
                );
            }
            // Root ignores the mode bits, so the read succeeds and the parse
            // must be correct rather than zeroed.
            Ok(stats) => {
                assert!(
                    (stats.some.avg10 - 1.0).abs() < 0.001,
                    "root read the file, so the contents must be parsed, got {}",
                    stats.some.avg10
                );
                assert_eq!(stats.some.total, 1);
            }
        }
    }

    /// Cross-field leakage within one line. A failed `avg10` parse must not
    /// adopt `avg60`'s value: the parser writes each key into its own slot, so
    /// a leak here would make a truncated `avg10=` report the pressure of a
    /// *different* average. Two differing values are what makes this
    /// observable — with `avg10` and `avg60` equal the leak is invisible.
    #[test]
    fn test_a_failed_avg10_does_not_adopt_avg60() {
        let stats = PsiStats::parse("some avg10= avg60=7.25 avg300=0.0 total=0\n").unwrap();
        assert_eq!(
            stats.some.avg10, 0.0,
            "an unparseable avg10 must be 0.0, never avg60's 7.25"
        );
        assert!(
            (stats.some.avg60 - 7.25).abs() < 0.001,
            "avg60 on the same line must survive, got {}",
            stats.some.avg60
        );
    }

    /// Cross-line leakage: a line the parser does not recognise must not be
    /// written into `full`. The kernel can ship a third line (a future stall
    /// metric), and if that landed in `full` the governor would read a
    /// `some`-scale number as a full stall and jump a pressure tier.
    #[test]
    fn test_an_unrecognised_line_does_not_reach_full() {
        let stats = PsiStats::parse(
            "some avg10=1.0 avg60=0.0 avg300=0.0 total=10\n\
             full avg10=0.25 avg60=0.0 avg300=0.0 total=2\n\
             future avg10=99.0 avg60=0.0 avg300=0.0 total=0\n",
        )
        .unwrap();
        assert!(
            (stats.full.avg10 - 0.25).abs() < 0.001,
            "an unrecognised line must not overwrite full, got {}",
            stats.full.avg10
        );
        assert_eq!(stats.full.total, 2);
    }

    /// Cross-CALL leakage: the parser builds a fresh `PsiStats` every call, so
    /// a reading parsed after a heavy one must not inherit its numbers. Two
    /// calls with different inputs is the only way to observe a mutation that
    /// persists state across calls.
    #[test]
    fn test_two_parses_do_not_share_state() {
        // The first parse sets every field, including ones the second parse
        // will not mention at all. Those omissions are the whole point: a
        // carry that seeds `PsiStats::default()` from the previous result can
        // only be observed through a field the second input leaves absent.
        let heavy = PsiStats::parse(
            "some avg10=42.0 avg60=41.0 avg300=40.0 total=999\n\
             full avg10=38.0 avg60=37.0 avg300=36.0 total=998\n",
        )
        .unwrap();
        assert!(
            (heavy.some.avg10 - 42.0).abs() < 0.001,
            "the heavy reading must parse, got {}",
            heavy.some.avg10
        );
        assert!((heavy.full.avg10 - 38.0).abs() < 0.001);

        // A bare `some` line: no `full` line at all, and no `total` on either.
        // Every field the first call set and this one does not must return to
        // its own default, not to the first call's value.
        let light = PsiStats::parse("some avg10=0.1\n").unwrap();
        assert!(
            (light.some.avg10 - 0.1).abs() < 0.001,
            "the light reading's avg10 must parse, got {}",
            light.some.avg10
        );
        assert_eq!(
            light.some.avg60, 0.0,
            "avg60 is absent from the second input, so it must be 0.0, not the \
             first call's 41.0"
        );
        assert_eq!(light.some.avg300, 0.0, "nor the first call's 40.0");
        assert_eq!(
            light.some.total, 0,
            "total is absent too, so it must be 0, not the first call's 999"
        );
        assert_eq!(
            light.full.avg10, 0.0,
            "the second input has no full line at all, so full must be the \
             default 0.0, not the first call's 38.0"
        );
        assert_eq!(light.full.total, 0);

        // And an empty document between the two must reset everything, so a
        // carry cannot be hidden by the intervening call.
        let cleared = PsiStats::parse("").unwrap();
        assert_eq!(cleared.some.total, 0);
        assert_eq!(cleared.full.total, 0);
        assert_eq!(cleared.some.avg60, 0.0);
        assert_eq!(cleared.full.avg60, 0.0);
    }

    /// A PSI line cut off mid-record must parse to zeros — the kernel can ship
    /// a short read, and a partial `avg10=` with no value is not a reading of
    /// "no pressure". The important half is that it does not inherit the
    /// previous line's value.
    #[test]
    fn test_parse_of_a_truncated_line_yields_zeros_not_the_previous_line() {
        // First a full reading, then a truncated one: `parse` builds a fresh
        // `PsiLine`, so state cannot leak from one call into the next.
        let full = PsiStats::parse("some avg10=42.0 avg60=41.0 avg300=40.0 total=99\n").unwrap();
        assert!((full.some.avg10 - 42.0).abs() < 0.001);

        let truncated = PsiStats::parse("some avg10=\n").unwrap();
        assert_eq!(
            truncated.some.avg10, 0.0,
            "a truncated avg10 must read as 0.0, never as the previous value"
        );
        assert_eq!(truncated.some.avg60, 0.0);
        assert_eq!(truncated.some.avg300, 0.0);
        assert_eq!(truncated.some.total, 0);
    }

    /// The parser is deliberately lenient: an unparseable number becomes 0
    /// rather than an error, because a PSI read that errors would abort the
    /// governor tick and stop tuning. Assert that is what actually happens, and
    /// that the surviving values are still parsed — so a parser that dropped
    /// the whole line would fail here.
    #[test]
    fn test_parse_of_non_numeric_values_degrades_to_zeros_without_erroring() {
        let stats =
            PsiStats::parse("some avg10=abc avg60=1.5 total=-7\nfull avg10=? total=1e400\n")
                .expect("unparseable PSI numbers are not a read failure");

        assert_eq!(stats.some.avg10, 0.0, "a non-numeric avg10 must become 0.0");
        assert!(
            (stats.some.avg60 - 1.5).abs() < 0.001,
            "the parseable field on the same line must survive, got {}",
            stats.some.avg60
        );
        assert_eq!(stats.some.total, 0, "a negative total must parse as 0");
        assert!(
            stats.full.avg10.is_finite(),
            "an overflowing total must not produce a non-finite average, got {}",
            stats.full.avg10
        );
        assert_eq!(stats.full.total, 0);
    }

    /// A file that carries only a `some` line leaves `full` at zero. That is
    /// the shape a partial kernel change would produce, and the zero is the
    /// documented default rather than a fabricated reading.
    #[test]
    fn test_a_some_only_file_leaves_full_at_exactly_zero() {
        let stats = PsiStats::parse("some avg10=3.0 total=10\n").unwrap();
        assert!(
            (stats.some.avg10 - 3.0).abs() < 0.001,
            "the present line must be parsed, got {}",
            stats.some.avg10
        );
        assert_eq!(
            stats.full.avg10, 0.0,
            "an absent full line must be exactly 0.0, never NaN or a stale value"
        );
        assert_eq!(stats.full.total, 0);
    }

    /// A trigger registered on a file the daemon cannot open — here a
    /// directory, `EISDIR` for root as well — must fail with the path attached.
    /// The alternative, a trigger left pointing at a closed or overlapping fd,
    /// is what makes a monitoring loop stop noticing pressure.
    #[test]
    fn test_psi_trigger_new_from_path_on_a_directory_fails_naming_the_path() {
        let dir = tempfile::tempdir().unwrap();

        let err = match PsiTrigger::new_from_path(dir.path(), PsiTriggerKind::Some, 1000, 500_000) {
            Err(e @ TunedError::Sysfs { .. }) => e,
            Err(other) => panic!("expected a Sysfs error, got: {other:?}"),
            Ok(_) => panic!("a directory cannot hold a PSI trigger, but one was created"),
        };
        assert!(
            err.to_string().contains(dir.path().to_str().unwrap()),
            "the failed registration must name the path, got: {err}"
        );
    }

    /// A trigger on a path that vanishes before the open — the resurrection
    /// case, where the daemon recreates its monitoring file while another
    /// process removes it — must be an error rather than a dangling fd.
    #[test]
    fn test_psi_trigger_new_from_path_on_a_missing_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("gone").join("memory.pressure");

        let err = match PsiTrigger::new_from_path(&missing, PsiTriggerKind::Full, 1000, 500_000) {
            Err(e @ TunedError::Sysfs { .. }) => e,
            Err(other) => panic!("expected a Sysfs error, got: {other:?}"),
            Ok(_) => panic!("a missing PSI file cannot be monitored, but a trigger was created"),
        };
        assert!(
            err.to_string().contains("memory.pressure"),
            "the error must name the path, got: {err}"
        );
    }

    /// The live `/proc/pressure/memory` read is the one seam with no test
    /// double: on a host with PSI enabled it must return a *finite* average, on
    /// a host without it the error must name the real path. Both arms are
    /// strict — a fabricated `Ok` with NaN would fail the finite check, and a
    /// swallowed `?` would produce an empty message.
    #[test]
    fn test_read_memory_is_finite_or_named() {
        match PsiStats::read_memory() {
            Ok(stats) => {
                assert!(
                    stats.some.avg10.is_finite() && stats.full.avg10.is_finite(),
                    "a real PSI read must be finite, got some={} full={}",
                    stats.some.avg10,
                    stats.full.avg10
                );
                assert!(
                    stats.some.avg10 >= 0.0 && stats.full.avg10 >= 0.0,
                    "a real PSI average cannot be negative, got some={} full={}",
                    stats.some.avg10,
                    stats.full.avg10
                );
            }
            Err(e) => {
                let message = e.to_string();
                assert!(
                    message.contains(PSI_MEMORY_PATH),
                    "the failure must name {PSI_MEMORY_PATH}, got: {message}"
                );
            }
        }
    }
}
