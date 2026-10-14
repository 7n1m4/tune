//! Procfs utilities for process discovery and memory analysis.
//!
//! Provides functions to enumerate processes, read their memory maps,
//! and extract KSM-relevant statistics from /proc.

use crate::error::{Result, TunedError};
use std::fs;
use std::path::Path;

/// Process memory status from /proc/PID/status.
#[derive(Debug, Clone, Default)]
pub struct ProcessStatus {
    pub pid: u32,
    pub name: String,
    pub vm_rss_kb: u64,
    pub anon_rss_kb: u64,
}

/// A single entry from /proc/PID/maps.
#[derive(Debug, Clone)]
pub struct MapsEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub pathname: String,
}

impl MapsEntry {
    /// Size of this mapping in bytes.
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Number of pages in this mapping.
    pub fn page_count(&self) -> u64 {
        self.size() / 4096
    }

    /// Whether this is an anonymous read-write private mapping (KSM candidate).
    pub fn is_anon_rw(&self) -> bool {
        self.perms.contains("rw")
            && !self.perms.contains('s') // not shared
            && self.pathname.is_empty()
            && self.inode == 0
    }

    /// Whether this mapping has execute permission (should be skipped).
    pub fn has_exec(&self) -> bool {
        self.perms.contains('x')
    }

    /// Whether this is a special kernel mapping (vdso, vvar, vsyscall).
    pub fn is_special(&self) -> bool {
        self.pathname.starts_with("[vdso]")
            || self.pathname.starts_with("[vvar")
            || self.pathname.starts_with("[vsyscall]")
            || self.pathname.starts_with("[stack")
            || self.pathname.starts_with("[heap]")
    }
}

/// Per-process KSM statistics from /proc/PID/ksm_stat.
#[derive(Debug, Clone, Default)]
pub struct KsmProcStat {
    pub rmap_items: u64,
    pub merging_pages: u64,
    pub process_profit: i64,
    pub merge_any: bool,
    pub mergeable: bool,
}

/// An anonymous memory region scored for KSM merge potential.
/// Kept as public API: the scanner scored candidates before merging moved to
/// a per-process eligibility model, and downstream consumers still read it.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MergeCandidate {
    pub pid: u32,
    pub process_name: String,
    pub start: u64,
    pub end: u64,
    pub size_bytes: u64,
    pub anon_rss_kb: u64,
}

/// List all PIDs in /proc (numeric directory entries).
pub fn list_pids() -> Result<Vec<u32>> {
    list_pids_from(Path::new("/proc"))
}

fn list_pids_from(proc_path: &Path) -> Result<Vec<u32>> {
    let mut pids = Vec::new();
    let entries = fs::read_dir(proc_path).map_err(|e| TunedError::Procfs {
        pid: 0,
        detail: format!("cannot read {}: {e}", proc_path.display()),
    })?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Ok(pid) = name_str.parse::<u32>() {
            pids.push(pid);
        }
    }

    Ok(pids)
}

/// Read process status (VmRSS, RssAnon, etc.) from /proc/PID/status.
pub fn read_process_status(pid: u32) -> Result<ProcessStatus> {
    read_process_status_from(Path::new("/proc"), pid)
}

fn read_process_status_from(proc_path: &Path, pid: u32) -> Result<ProcessStatus> {
    let path = proc_path.join(pid.to_string()).join("status");
    let content = fs::read_to_string(&path).map_err(|e| TunedError::Procfs {
        pid,
        detail: format!("cannot read {}: {e}", path.display()),
    })?;

    let mut status = ProcessStatus {
        pid,
        ..Default::default()
    };

    for line in content.lines() {
        if let Some(value) = line.strip_prefix("Name:") {
            status.name = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("VmRSS:") {
            status.vm_rss_kb = parse_kb_value(value);
        } else if let Some(value) = line.strip_prefix("RssAnon:") {
            status.anon_rss_kb = parse_kb_value(value);
        }
    }

    Ok(status)
}

/// Read and parse /proc/PID/maps.
pub fn read_process_maps(pid: u32) -> Result<Vec<MapsEntry>> {
    read_process_maps_from(Path::new("/proc"), pid)
}

fn read_process_maps_from(proc_path: &Path, pid: u32) -> Result<Vec<MapsEntry>> {
    let path = proc_path.join(pid.to_string()).join("maps");
    let content = fs::read_to_string(&path).map_err(|e| TunedError::Procfs {
        pid,
        detail: format!("cannot read {}: {e}", path.display()),
    })?;

    let mut entries = Vec::new();
    for line in content.lines() {
        if let Some(entry) = parse_maps_line(line) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Read per-process KSM statistics from /proc/PID/ksm_stat.
pub fn read_ksm_stat(pid: u32) -> Result<KsmProcStat> {
    read_ksm_stat_from(Path::new("/proc"), pid)
}

fn read_ksm_stat_from(proc_path: &Path, pid: u32) -> Result<KsmProcStat> {
    let path = proc_path.join(pid.to_string()).join("ksm_stat");
    let content = fs::read_to_string(&path).map_err(|e| TunedError::Procfs {
        pid,
        detail: format!("cannot read {}: {e}", path.display()),
    })?;

    let mut stat = KsmProcStat::default();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0].trim_end_matches(':') {
                "ksm_rmap_items" => stat.rmap_items = parts[1].parse().unwrap_or(0),
                "ksm_merging_pages" => stat.merging_pages = parts[1].parse().unwrap_or(0),
                "ksm_process_profit" => stat.process_profit = parts[1].parse().unwrap_or(0),
                "ksm_merge_any" => stat.merge_any = parse_ksm_bool(parts[1]),
                "ksm_mergeable" => stat.mergeable = parse_ksm_bool(parts[1]),
                _ => {}
            }
        }
    }

    Ok(stat)
}

/// Read PIDs belonging to a specific cgroup (cgroup v2).
pub fn read_cgroup_procs(cgroup_path: &str) -> Result<Vec<u32>> {
    let procs_path = format!("{cgroup_path}/cgroup.procs");
    let content = fs::read_to_string(&procs_path).map_err(|e| TunedError::Procfs {
        pid: 0,
        detail: format!("cannot read {procs_path}: {e}"),
    })?;

    let pids: Vec<u32> = content
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect();

    Ok(pids)
}

/// Read a pagemap entry for a given virtual address.
/// Returns the PFN (page frame number) if the page is present.
pub fn read_pagemap_pfn(pid: u32, vaddr: u64) -> Result<Option<u64>> {
    read_pagemap_pfn_from(Path::new("/proc"), pid, vaddr)
}

fn read_pagemap_pfn_from(proc_path: &Path, pid: u32, vaddr: u64) -> Result<Option<u64>> {
    let path = proc_path.join(pid.to_string()).join("pagemap");
    let offset = (vaddr / 4096) * 8; // 8 bytes per page

    use std::io::{Read, Seek, SeekFrom};
    let mut file = fs::File::open(&path).map_err(|e| TunedError::Procfs {
        pid,
        detail: format!("cannot open {}: {e}", path.display()),
    })?;

    file.seek(SeekFrom::Start(offset))
        .map_err(|e| TunedError::Procfs {
            pid,
            detail: format!("cannot seek pagemap: {e}"),
        })?;

    let mut buf = [0u8; 8];
    file.read_exact(&mut buf).map_err(|e| TunedError::Procfs {
        pid,
        detail: format!("cannot read pagemap entry: {e}"),
    })?;

    let entry = u64::from_ne_bytes(buf);

    // Bit 63: page present
    let present = (entry >> 63) & 1 != 0;
    if !present {
        return Ok(None);
    }

    // Bits 0-54: PFN
    let pfn = entry & 0x7FFFFFFFFFFFFF;
    Ok(Some(pfn))
}

/// Read PFNs for all pages in a memory range.
pub fn read_pagemap_range(pid: u32, start: u64, end: u64) -> Result<Vec<u64>> {
    read_pagemap_range_from(Path::new("/proc"), pid, start, end)
}

fn read_pagemap_range_from(proc_path: &Path, pid: u32, start: u64, end: u64) -> Result<Vec<u64>> {
    let path = proc_path.join(pid.to_string()).join("pagemap");
    let mut pfns = Vec::new();

    use std::io::{Read, Seek, SeekFrom};
    let mut file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            return Err(TunedError::Procfs {
                pid,
                detail: format!("cannot open {}: {e}", path.display()),
            });
        }
    };

    let page_start = start / 4096;
    let page_count = (end - start) / 4096;

    if file.seek(SeekFrom::Start(page_start * 8)).is_err() {
        return Ok(pfns); // Process may have exited
    }

    let mut buf = vec![0u8; (page_count as usize) * 8];
    let bytes_read = file.read(&mut buf).unwrap_or(0);
    let entries_read = bytes_read / 8;

    for i in 0..entries_read {
        let offset = i * 8;
        let entry = u64::from_ne_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);

        // Bit 63: present, Bit 62: swap, Bits 0-54: PFN
        let present = (entry >> 63) & 1 != 0;
        if present {
            let pfn = entry & 0x7FFFFFFFFFFFFF;
            if pfn != 0 {
                pfns.push(pfn);
            }
        }
    }

    Ok(pfns)
}

/// Check if a process name matches any pattern in the blocklist.
pub fn is_blocklisted(name: &str, blocklist: &[String]) -> bool {
    blocklist.iter().any(|pattern| name.contains(pattern))
}

/// Get the comm (short name) of a process.
///
/// Kept as public API: the scanner now reads comm through its own eligibility
/// path, but the name is the natural handle for any per-process report.
#[allow(dead_code)]
pub fn read_process_comm(pid: u32) -> Result<String> {
    read_process_comm_from(Path::new("/proc"), pid)
}

fn read_process_comm_from(proc_path: &Path, pid: u32) -> Result<String> {
    let path = proc_path.join(pid.to_string()).join("comm");
    fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .map_err(|e| TunedError::Procfs {
            pid,
            detail: format!("cannot read {}: {e}", path.display()),
        })
}

// --- Internal helpers ---

fn parse_kb_value(s: &str) -> u64 {
    s.trim()
        .trim_end_matches(" kB")
        .trim()
        .parse::<u64>()
        .unwrap_or(0)
}

fn parse_ksm_bool(s: &str) -> bool {
    matches!(
        s.trim().trim_end_matches(',').to_ascii_lowercase().as_str(),
        "1" | "yes" | "true"
    )
}

fn parse_maps_line(line: &str) -> Option<MapsEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    let range: Vec<&str> = parts[0].split('-').collect();
    if range.len() != 2 {
        return None;
    }

    let start = u64::from_str_radix(range[0], 16).ok()?;
    let end = u64::from_str_radix(range[1], 16).ok()?;
    let perms = parts[1].to_string();
    let offset = u64::from_str_radix(parts[2], 16).unwrap_or(0);
    let dev = parts[3].to_string();
    let inode = parts[4].parse::<u64>().unwrap_or(0);
    let pathname = if parts.len() > 5 {
        parts[5..].join(" ")
    } else {
        String::new()
    };

    Some(MapsEntry {
        start,
        end,
        perms,
        offset,
        dev,
        inode,
        pathname,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_maps_line() {
        let line = "7f8c40000000-7f8c40021000 rw-p 00000000 00:00 0";
        let entry = parse_maps_line(line).unwrap();
        assert_eq!(entry.start, 0x7f8c40000000);
        assert_eq!(entry.end, 0x7f8c40021000);
        assert!(entry.is_anon_rw());
        assert!(!entry.has_exec());
    }

    #[test]
    fn test_parse_maps_line_file_backed() {
        let line = "7f8c3fe00000-7f8c3fe01000 r--p 00000000 08:01 12345 /usr/lib/libc.so";
        let entry = parse_maps_line(line).unwrap();
        assert!(!entry.is_anon_rw());
    }

    #[test]
    fn test_is_blocklisted() {
        let blocklist = vec!["tuned".to_string(), "ksmd".to_string()];
        assert!(is_blocklisted("tuned-daemon", &blocklist));
        assert!(is_blocklisted("ksmd", &blocklist));
        assert!(!is_blocklisted("firefox", &blocklist));
    }

    /// Browsers must be blocked by the shipped defaults, not left to the
    /// operator. This guards the default blocklist against a regression:
    /// marking Chromium's renderers crashed them live with SIGILL at a fixed
    /// `.text` offset (`traps: chrome[...] trap invalid opcode`), twice — once
    /// unguarded and once with the executable-VMA guard demonstrably firing.
    ///
    /// Kernel `comm` is at most 15 chars and Chromium sets it to `chrome`.
    #[test]
    fn test_default_blocklist_excludes_browsers() {
        let defaults = crate::config::ScannerConfig::default();
        for browser in [
            "chrome",
            "chromium",
            "firefox",
            "firefox-nightly",
            "msedge",
            "brave",
            "opera",
            "vivaldi",
            "electron",
        ] {
            assert!(
                is_blocklisted(browser, &defaults.blocklist),
                "{browser} must be in the default scanner blocklist"
            );
        }
    }

    #[test]
    fn test_parse_kb_value() {
        assert_eq!(parse_kb_value("  12345 kB"), 12345);
        assert_eq!(parse_kb_value("0 kB"), 0);
    }

    #[test]
    fn test_parse_kb_value_invalid() {
        // Invalid number → unwrap_or(0)
        assert_eq!(parse_kb_value("not_a_number"), 0);
        assert_eq!(parse_kb_value(""), 0);
    }

    #[test]
    fn test_parse_ksm_bool() {
        assert!(parse_ksm_bool("1"));
        assert!(parse_ksm_bool("yes"));
        assert!(parse_ksm_bool("true"));
        assert!(!parse_ksm_bool("0"));
        assert!(!parse_ksm_bool("no"));
    }

    // ── MapsEntry ───────────────────────────────────────────────────────

    #[test]
    fn test_maps_entry_size() {
        let entry = MapsEntry {
            start: 0x1000,
            end: 0x5000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        };
        assert_eq!(entry.size(), 0x4000);
    }

    #[test]
    fn test_maps_entry_page_count() {
        let entry = MapsEntry {
            start: 0x1000,
            end: 0x5000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        };
        assert_eq!(entry.page_count(), 4);
    }

    #[test]
    fn test_maps_entry_page_count_partial() {
        // A 1-byte range still counts as 1 page (floor division)
        let entry = MapsEntry {
            start: 0x1000,
            end: 0x1001,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        };
        assert_eq!(entry.page_count(), 0); // 1/4096 = 0
    }

    #[test]
    fn test_is_anon_rw_true() {
        let entry = MapsEntry {
            start: 0x1000,
            end: 0x2000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        };
        assert!(entry.is_anon_rw());
    }

    #[test]
    fn test_is_anon_rw_false_shared() {
        let entry = MapsEntry {
            start: 0x1000,
            end: 0x2000,
            perms: "rws-".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        };
        assert!(!entry.is_anon_rw());
    }

    #[test]
    fn test_is_anon_rw_false_file_backed() {
        let entry = MapsEntry {
            start: 0x1000,
            end: 0x2000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 12345,
            pathname: "/usr/lib/libc.so".into(),
        };
        assert!(!entry.is_anon_rw());
    }

    #[test]
    fn test_has_exec() {
        let exec_entry = MapsEntry {
            start: 0x1000,
            end: 0x2000,
            perms: "r-xp".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        };
        assert!(exec_entry.has_exec());

        let no_exec_entry = MapsEntry {
            start: 0x1000,
            end: 0x2000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        };
        assert!(!no_exec_entry.has_exec());
    }

    #[test]
    fn test_is_special() {
        let vdso = MapsEntry {
            start: 0x1000,
            end: 0x2000,
            perms: "r-xp".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: "[vdso]".into(),
        };
        assert!(vdso.is_special());

        let heap = MapsEntry {
            start: 0x1000,
            end: 0x2000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: "[heap]".into(),
        };
        assert!(heap.is_special());

        let normal = MapsEntry {
            start: 0x1000,
            end: 0x2000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        };
        assert!(!normal.is_special());
    }

    // ── parse_maps_line edge cases ──────────────────────────────────────

    #[test]
    fn test_parse_maps_line_too_few_parts() {
        assert!(parse_maps_line("").is_none());
        assert!(parse_maps_line("7f8c40000000-7f8c40021000 rw-p 00000000 00:00").is_none());
    }

    #[test]
    fn test_parse_maps_line_bad_range() {
        // range without '-' separator
        assert!(parse_maps_line("invalid rw-p 00000000 00:00 0").is_none());
    }

    #[test]
    fn test_parse_maps_line_bad_hex_bounds() {
        assert!(parse_maps_line("zz-2000 rw-p 00000000 00:00 0").is_none());
        assert!(parse_maps_line("1000-zz rw-p 00000000 00:00 0").is_none());
    }

    #[test]
    fn test_parse_maps_line_file_backed_path() {
        let line = "7f8c3fe00000-7f8c3fe01000 r--p 00000000 08:01 12345 /usr/lib/libc.so";
        let entry = parse_maps_line(line).unwrap();
        assert_eq!(entry.pathname, "/usr/lib/libc.so");
        assert_eq!(entry.inode, 12345);
    }

    #[test]
    fn test_parse_maps_line_path_with_spaces() {
        let line = "7f8c3fe00000-7f8c3fe01000 rw-p 00000000 00:00 0 /path/with spaces (deleted)";
        let entry = parse_maps_line(line).unwrap();
        assert!(entry.pathname.contains("spaces"));
        assert!(entry.pathname.contains("deleted"));
    }

    #[test]
    fn test_parse_maps_line_non_zero_offset() {
        let line = "7f8c40000000-7f8c40001000 rw-p 00001000 00:00 0";
        let entry = parse_maps_line(line).unwrap();
        assert_eq!(entry.offset, 0x1000);
    }

    #[test]
    fn test_parse_maps_line_vvar() {
        let line = "7fff3fe00000-7fff3fe01000 r--p 00000000 00:00 0 [vvar]";
        let entry = parse_maps_line(line).unwrap();
        assert!(entry.is_special());
    }

    // ── ProcessStatus / parse_kb_value ──────────────────────────────────

    #[test]
    fn test_parse_kb_value_large_number() {
        assert_eq!(parse_kb_value("  1048576 kB"), 1048576);
    }

    // ── read_ksm_stat format ────────────────────────────────────────────

    #[test]
    fn test_parse_ksm_stat_unknown_field_skipped() {
        let content = "ksm_unknown_field 99\nksm_rmap_items 5\n";
        let mut stat = KsmProcStat::default();
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[0] == "ksm_rmap_items" {
                stat.rmap_items = parts[1].parse().unwrap_or(0);
            }
        }
        assert_eq!(stat.rmap_items, 5);
    }

    // ── file-backed /proc helpers ───────────────────────────────────────

    fn proc_pid(root: &Path, pid: u32) -> std::path::PathBuf {
        let path = root.join(pid.to_string());
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn test_list_pids_from_temp_proc_only_numeric_dirs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("1")).unwrap();
        std::fs::create_dir(dir.path().join("42")).unwrap();
        std::fs::create_dir(dir.path().join("self")).unwrap();
        std::fs::write(dir.path().join("meminfo"), "").unwrap();

        let mut pids = list_pids_from(dir.path()).unwrap();
        pids.sort_unstable();
        assert_eq!(pids, vec![1, 42]);
    }

    #[test]
    fn test_list_pids_reads_real_proc() {
        let pids = list_pids().unwrap();
        assert!(pids.contains(&std::process::id()));
    }

    #[test]
    fn test_list_pids_from_missing_root_returns_error() {
        let err = list_pids_from(Path::new("/nonexistent/proc/root")).unwrap_err();
        assert!(err.to_string().contains("cannot read"));
    }

    #[test]
    fn test_read_process_status_from_temp_proc() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = proc_pid(dir.path(), 123);
        std::fs::write(
            pid_dir.join("status"),
            "Name:\tfirefox\nVmRSS:\t  204800 kB\nRssAnon:\t  102400 kB\n",
        )
        .unwrap();

        let status = read_process_status_from(dir.path(), 123).unwrap();
        assert_eq!(status.pid, 123);
        assert_eq!(status.name, "firefox");
        assert_eq!(status.vm_rss_kb, 204800);
        assert_eq!(status.anon_rss_kb, 102400);
    }

    #[test]
    fn test_read_process_status_reads_current_process() {
        let status = read_process_status(std::process::id()).unwrap();
        assert_eq!(status.pid, std::process::id());
        assert!(!status.name.is_empty());
    }

    #[test]
    fn test_read_process_status_from_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        proc_pid(dir.path(), 123);

        let err = read_process_status_from(dir.path(), 123).unwrap_err();
        assert!(err.to_string().contains("cannot read"));
    }

    #[test]
    fn test_read_process_maps_from_temp_proc_skips_bad_lines() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = proc_pid(dir.path(), 123);
        std::fs::write(
            pid_dir.join("maps"),
            "not-enough-fields\n\
             1000-3000 rw-p 00000000 00:00 0\n\
             4000-5000 r--p 00000000 08:01 99 /tmp/file with spaces\n",
        )
        .unwrap();

        let maps = read_process_maps_from(dir.path(), 123).unwrap();
        assert_eq!(maps.len(), 2);
        assert_eq!(maps[0].start, 0x1000);
        assert!(maps[0].is_anon_rw());
        assert_eq!(maps[1].pathname, "/tmp/file with spaces");
    }

    #[test]
    fn test_read_process_maps_reads_current_process() {
        let maps = read_process_maps(std::process::id()).unwrap();
        assert!(!maps.is_empty());
    }

    #[test]
    fn test_read_process_maps_from_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        proc_pid(dir.path(), 123);

        let err = read_process_maps_from(dir.path(), 123).unwrap_err();
        assert!(err.to_string().contains("cannot read"));
    }

    #[test]
    fn test_read_ksm_stat_from_temp_proc() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = proc_pid(dir.path(), 123);
        std::fs::write(
            pid_dir.join("ksm_stat"),
            "ksm_rmap_items 10\n\
             ksm_merging_pages 3\n\
             ksm_process_profit -7\n\
             ksm_merge_any yes\n\
             ksm_mergeable 1\n\
             ignored 999\n",
        )
        .unwrap();

        let stat = read_ksm_stat_from(dir.path(), 123).unwrap();
        assert_eq!(stat.rmap_items, 10);
        assert_eq!(stat.merging_pages, 3);
        assert_eq!(stat.process_profit, -7);
        assert!(stat.merge_any);
        assert!(stat.mergeable);
    }

    #[test]
    fn test_read_ksm_stat_from_temp_proc_colon_format() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = proc_pid(dir.path(), 123);
        std::fs::write(
            pid_dir.join("ksm_stat"),
            "ksm_rmap_items: 10\n\
             ksm_merging_pages: 3\n\
             ksm_process_profit: -7\n\
             ksm_merge_any: no\n\
             ksm_mergeable: yes\n",
        )
        .unwrap();

        let stat = read_ksm_stat_from(dir.path(), 123).unwrap();
        assert_eq!(stat.rmap_items, 10);
        assert_eq!(stat.merging_pages, 3);
        assert_eq!(stat.process_profit, -7);
        assert!(!stat.merge_any);
        assert!(stat.mergeable);
    }

    #[test]
    fn test_read_ksm_stat_from_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        proc_pid(dir.path(), 123);

        let err = read_ksm_stat_from(dir.path(), 123).unwrap_err();
        assert!(err.to_string().contains("cannot read"));
    }

    #[test]
    fn test_read_cgroup_procs_ignores_invalid_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cgroup.procs"), "10\nbad\n20\n\n").unwrap();

        let pids = read_cgroup_procs(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(pids, vec![10, 20]);
    }

    #[test]
    fn test_read_cgroup_procs_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_cgroup_procs(dir.path().to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("cannot read"));
    }

    #[test]
    fn test_read_pagemap_pfn_from_temp_proc_present_and_absent() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = proc_pid(dir.path(), 123);
        let present = (1u64 << 63) | 0x12345;
        let absent = 0x54321u64;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&present.to_ne_bytes());
        bytes.extend_from_slice(&absent.to_ne_bytes());
        std::fs::write(pid_dir.join("pagemap"), bytes).unwrap();

        assert_eq!(
            read_pagemap_pfn_from(dir.path(), 123, 0).unwrap(),
            Some(0x12345)
        );
        assert_eq!(read_pagemap_pfn_from(dir.path(), 123, 4096).unwrap(), None);
    }

    #[test]
    fn test_read_pagemap_pfn_from_short_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = proc_pid(dir.path(), 123);
        std::fs::write(pid_dir.join("pagemap"), [0u8; 4]).unwrap();

        let err = read_pagemap_pfn_from(dir.path(), 123, 0).unwrap_err();
        assert!(err.to_string().contains("cannot read pagemap entry"));
    }

    #[test]
    fn test_read_pagemap_range_from_temp_proc_filters_zero_and_absent() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = proc_pid(dir.path(), 123);
        let entries = [(1u64 << 63) | 0x111, 0, 1u64 << 63, (1u64 << 63) | 0x222];
        let mut bytes = Vec::new();
        for entry in entries {
            bytes.extend_from_slice(&entry.to_ne_bytes());
        }
        std::fs::write(pid_dir.join("pagemap"), bytes).unwrap();

        let pfns = read_pagemap_range_from(dir.path(), 123, 0, 4 * 4096).unwrap();
        assert_eq!(pfns, vec![0x111, 0x222]);
    }

    #[test]
    fn test_read_pagemap_pfn_reports_missing_process() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_pagemap_pfn_from(dir.path(), u32::MAX, 0).unwrap_err();
        assert!(err.to_string().contains("cannot open"));
    }

    #[test]
    fn test_read_pagemap_range_reads_empty_range_for_current_process() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = proc_pid(dir.path(), std::process::id());

        // A zero-length range must not be attempted: `read` on an empty buffer
        // returns 0 bytes, so the PFN list stays empty.
        std::fs::write(pid_dir.join("pagemap"), [0u8; 8]).unwrap();
        let pfns = read_pagemap_range_from(dir.path(), std::process::id(), 0, 0).unwrap();
        assert!(pfns.is_empty());

        // A file shorter than the requested range is read as far as it goes:
        // one entry present, one absent, one page the file never reached.
        let entries = [(1u64 << 63) | 0x111, 0x54321u64];
        let mut bytes = Vec::new();
        for entry in entries {
            bytes.extend_from_slice(&entry.to_ne_bytes());
        }
        std::fs::write(pid_dir.join("pagemap"), bytes).unwrap();
        let pfns = read_pagemap_range_from(dir.path(), std::process::id(), 0, 3 * 4096).unwrap();
        assert_eq!(pfns, vec![0x111]);
    }

    #[test]
    fn test_read_pagemap_range_from_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        proc_pid(dir.path(), 123);

        let err = read_pagemap_range_from(dir.path(), 123, 0, 4096).unwrap_err();
        assert!(err.to_string().contains("cannot open"));
    }

    #[test]
    fn test_read_process_comm_from_temp_proc_trims_newline() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = proc_pid(dir.path(), 123);
        std::fs::write(pid_dir.join("comm"), "worker\n").unwrap();

        assert_eq!(read_process_comm_from(dir.path(), 123).unwrap(), "worker");
    }

    #[test]
    fn test_read_process_comm_from_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        proc_pid(dir.path(), 123);

        let err = read_process_comm_from(dir.path(), 123).unwrap_err();
        assert!(err.to_string().contains("cannot read"));
    }
}
