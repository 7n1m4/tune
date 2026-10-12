//! PSI (Pressure Stall Information) monitoring module.
//!
//! Supports both polling and event-driven (kernel trigger) modes
//! for monitoring memory pressure via /proc/pressure/memory.

use crate::error::{AnimaksmError, Result};
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
        let content = fs::read_to_string(path).map_err(|e| AnimaksmError::Sysfs {
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
            .map_err(|e| AnimaksmError::Sysfs {
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
            .map_err(|e| AnimaksmError::Sysfs {
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
}
