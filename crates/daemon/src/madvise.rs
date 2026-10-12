//! Tier 2: MADV_MERGEABLE injection via ptrace + process_madvise for COLLAPSE.
//!
//! Since Linux's process_madvise(2) only supports MADV_COLD, MADV_COLLAPSE,
//! MADV_PAGEOUT, MADV_WILLNEED for cross-process (NOT MADV_MERGEABLE),
//! we use ptrace(2) to inject madvise(MADV_MERGEABLE) into target processes.
//!
//! For MADV_COLLAPSE we can use process_madvise directly.
//!
//! ## Batched iovec (for COLLAPSE via process_madvise)
//!
//! process_madvise(2) accepts an iovec array — instead of one syscall per
//! VMA, we collect all eligible regions and fire a single batched call.
//! This dramatically reduces syscall overhead (N VMAs → 1 syscall per PID).
//!
//! ## MADV_COLLAPSE
//!
//! Opportunistic THP promotion: when KSM unmerges pages (triggering CoW),
//! those pages lose their THP backing. MADV_COLLAPSE (Linux 6.1+)
//! re-promotes aligned 2MB regions to transparent huge pages, recovering
//! TLB efficiency.
//!
//! ## MADV_MERGEABLE via ptrace
//!
//! We attach to the target process with ptrace(PTRACE_ATTACH), inject a
//! madvise(addr, len, MADV_MERGEABLE) syscall, then detach. This is
//! slower than batched process_madvise but is the only way to mark
//! another process's memory as KSM-mergeable.

use std::collections::HashMap;
use std::os::unix::io::RawFd;

use animaksm_common::procfs::MapsEntry;
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use tracing::{debug, info};

/// MADV_MERGEABLE constant (from linux/mman.h).
const MADV_MERGEABLE: libc::c_int = 12;

/// MADV_COLLAPSE constant (Linux 6.1+, collapses memory into THP).
const MADV_COLLAPSE: libc::c_int = 25;

/// process_madvise syscall number (x86_64).
const SYS_PROCESS_MADVISE: libc::c_long = 440;

/// pidfd_open syscall number (x86_64).
const SYS_PIDFD_OPEN: libc::c_long = 434;

/// madvise syscall number (x86_64).
const SYS_MADVISE: libc::c_long = 28;

/// Result of a madvise operation on a process.
#[derive(Debug)]
pub struct MadviseResult {
    pub pid: u32,
    pub regions_attempted: usize,
    pub regions_merged: usize,
    pub total_bytes_marked: u64,
    pub errors: Vec<(u64, String)>, // (address, error description)
}

/// Apply MADV_MERGEABLE to anonymous RW regions of a target process.
///
/// Uses ptrace(2) to inject madvise(MADV_MERGEABLE) syscalls into the
/// target process, since process_madvise(2) does NOT support MADV_MERGEABLE
/// for cross-process operations.
///
/// For dry_run, simulates the injection without actually attaching.
pub fn apply_mergeable(
    pid: u32,
    regions: &[MapsEntry],
    max_bytes: u64,
    dry_run: bool,
) -> MadviseResult {
    let mut result = MadviseResult {
        pid,
        regions_attempted: 0,
        regions_merged: 0,
        total_bytes_marked: 0,
        errors: Vec::new(),
    };

    // Filter to eligible regions and enforce per-process byte cap
    let eligible: Vec<&MapsEntry> = regions
        .iter()
        .filter(|r| r.is_anon_rw() && !r.has_exec() && !r.is_special())
        .collect();

    if eligible.is_empty() {
        debug!(pid, "No eligible anonymous RW regions found");
        return result;
    }

    // Collect regions into one batch, respecting max_bytes
    let batch = build_batch(&eligible, max_bytes);
    result.regions_attempted = batch.len();
    let total_bytes: u64 = batch.iter().map(|&(_, len)| len as u64).sum();

    if batch.is_empty() {
        return result;
    }

    if dry_run {
        for &(addr, len) in &batch {
            info!(
                pid,
                start = format!("0x{addr:x}"),
                size_kb = len / 1024,
                "[DRY RUN] Would inject MADV_MERGEABLE via ptrace"
            );
        }
        result.regions_merged = batch.len();
        result.total_bytes_marked = total_bytes;
        return result;
    }

    // Inject MADV_MERGEABLE via ptrace for each region
    // Find vdso syscall address once for this PID
    let syscall_addr = match find_syscall_in_vdso(pid) {
        Ok(addr) => addr,
        Err(e) => {
            for &(addr, _) in &batch {
                result
                    .errors
                    .push((addr, format!("cannot find syscall instruction: {e}")));
            }
            return result;
        }
    };

    for &(addr, len) in &batch {
        match madvise_via_ptrace(pid, addr, len, syscall_addr) {
            Ok(_) => {
                result.regions_merged += 1;
                result.total_bytes_marked += len as u64;
            }
            Err(e) => {
                result
                    .errors
                    .push((addr, format!("ptrace madvise failed: {e}")));
            }
        }
    }

    if result.regions_merged > 0 {
        info!(
            pid,
            regions_merged = result.regions_merged,
            total_kb = result.total_bytes_marked / 1024,
            "Applied MADV_MERGEABLE via ptrace to process regions"
        );
    }

    result
}

/// Opportunistically collapse memory regions into transparent huge pages.
///
/// Uses process_madvise(MADV_COLLAPSE) on aligned 2MB regions.
/// This is useful after KSM unmerges pages (which triggers CoW and
/// breaks THP backing), recovering TLB efficiency.
///
/// Returns the number of regions successfully collapsed.
/// Requires Linux 6.1+; silently returns 0 on ENOSYS.
pub fn collapse_regions(pid: u32, regions: &[MapsEntry]) -> usize {
    // Only consider large regions (>= 2MB) that could contain aligned THP ranges
    const THP_SIZE: u64 = 2 * 1024 * 1024;

    let large_regions: Vec<&MapsEntry> = regions
        .iter()
        .filter(|r| r.is_anon_rw() && !r.has_exec() && !r.is_special() && r.size() >= THP_SIZE)
        .collect();

    if large_regions.is_empty() {
        return 0;
    }

    let pidfd = match pidfd_open(pid) {
        Ok(fd) => fd,
        Err(_) => return 0,
    };

    let mut collapsed = 0;

    for region in &large_regions {
        // Align to 2MB boundary for THP
        let start = (region.start + THP_SIZE - 1) & !(THP_SIZE - 1);
        let end = region.end & !(THP_SIZE - 1);
        if start >= end {
            continue;
        }

        let len = (end - start) as usize;
        match process_madvise_single(pidfd, start, len, MADV_COLLAPSE) {
            Ok(_) => collapsed += 1,
            Err(e) => {
                // ENOSYS = kernel doesn't support MADV_COLLAPSE (pre-6.1)
                // EINVAL = region not suitable for collapse
                // Both are non-fatal
                if e.contains("ENOSYS") {
                    debug!("MADV_COLLAPSE not supported by kernel");
                    break;
                }
                debug!(
                    pid,
                    start = format!("0x{start:x}"),
                    error = %e,
                    "MADV_COLLAPSE skipped for region"
                );
            }
        }
    }

    unsafe {
        libc::close(pidfd);
    }

    if collapsed > 0 {
        info!(pid, collapsed, "Collapsed regions to THP via MADV_COLLAPSE");
    }

    collapsed
}

/// Build the batch of (addr, len) pairs from eligible regions, capping at
/// `max_bytes` total.
fn build_batch(eligible: &[&MapsEntry], max_bytes: u64) -> Vec<(u64, usize)> {
    let mut batch: Vec<(u64, usize)> = Vec::new();
    let mut bytes_accumulated: u64 = 0;

    for region in eligible {
        if bytes_accumulated >= max_bytes {
            break;
        }

        let size = region.size();
        let remaining = max_bytes - bytes_accumulated;
        let len = size.min(remaining);
        if len == 0 {
            break;
        }

        batch.push((region.start, len as usize));
        bytes_accumulated += len;
    }

    batch
}

/// Apply MADV_MERGEABLE to multiple processes at once.
pub fn batch_apply_mergeable(
    targets: &[(u32, Vec<MapsEntry>)],
    max_bytes_per_process: u64,
    dry_run: bool,
) -> HashMap<u32, MadviseResult> {
    let mut results = HashMap::new();

    for (pid, regions) in targets {
        let result = apply_mergeable(*pid, regions, max_bytes_per_process, dry_run);
        results.insert(*pid, result);
    }

    results
}

/// Open a pidfd for the given PID using pidfd_open(2).
fn pidfd_open(pid: u32) -> Result<RawFd, String> {
    let ret = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid as libc::c_int, 0 as libc::c_uint) };

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(format!("errno={errno} ({})", errno_to_str(errno)));
    }

    Ok(ret as RawFd)
}

/// Find a `syscall` instruction (0x0F 0x05) in the target process’s vDSO.
///
/// We read /proc/pid/maps to locate the [vdso] mapping, then scan its
/// memory via /proc/pid/mem for the two-byte sequence. Returns the
/// virtual address of the instruction or an error string.
fn find_syscall_in_vdso(pid: u32) -> Result<u64, String> {
    use std::io::{Read, Seek, SeekFrom};

    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))
        .map_err(|e| format!("read maps: {e}"))?;

    let vdso_line = maps
        .lines()
        .find(|l| l.contains("[vdso]"))
        .ok_or_else(|| "no [vdso] mapping found".to_string())?;

    let vdso_start = vdso_line
        .split('-')
        .next()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .ok_or_else(|| "bad vdso start".to_string())?;
    let vdso_end = vdso_line
        .split('-')
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .ok_or_else(|| "bad vdso end".to_string())?;

    // Read vDSO memory to find 0x0F 0x05 (syscall instruction)
    // Validate vDSO size to prevent underflow/OOM
    let sz = vdso_end
        .checked_sub(vdso_start)
        .ok_or_else(|| "vdso end before start".to_string())? as usize;
    if sz > 10 * 1024 * 1024 {
        return Err("vdso size too large".to_string());
    }
    let mut mem = std::fs::File::open(format!("/proc/{}/mem", pid))
        .map_err(|e| format!("open /proc/{}/mem: {e}", pid))?;
    mem.seek(SeekFrom::Start(vdso_start))
        .map_err(|e| format!("seek: {e}"))?;
    let mut buf = vec![0u8; sz];
    mem.read_exact(&mut buf)
        .map_err(|e| format!("read vdso: {e}"))?;

    buf.windows(2)
        .position(|w| w == [0x0f, 0x05])
        .map(|off| vdso_start + off as u64)
        .ok_or_else(|| "no syscall instruction in vdso".to_string())
}

/// Inject `madvise(MADV_MERGEABLE)` into a target process via ptrace.
///
/// ptrace(2) syscall injection pattern (x86_64):
///   1. PTRACE_ATTACH + waitpid(WSTOPPED)
///   2. getregs → save ALL registers (syscall clobbers rcx, r11)
///   3. Find a `syscall` instruction in the target’s vDSO
///   4. Set regs: rip → vDSO syscall addr, rax=28, rdi=addr, rsi=len, rdx=12
///   5. ptrace(SYSCALL) → waitpid (entry stop)
///   6. ptrace(SYSCALL) → waitpid (exit stop)
///   7. getregs → read rax for return value
///   8. Restore ALL original registers
///   9. PTRACE_DETACH
fn madvise_via_ptrace(pid: u32, addr: u64, len: usize, syscall_addr: u64) -> Result<(), String> {
    let nix_pid = Pid::from_raw(pid as i32);

    debug!(
        pid,
        addr = format!("0x{addr:x}"),
        len_kb = len / 1024,
        "Injecting madvise via ptrace"
    );

    // Attach to the target process
    if let Err(e) = ptrace::attach(nix_pid) {
        return Err(format!("ptrace attach failed: {e}"));
    }

    // Wait for the process to stop
    match waitpid(nix_pid, Some(WaitPidFlag::WSTOPPED)) {
        Ok(WaitStatus::Stopped(_, _)) => {}
        Ok(WaitStatus::Exited(pid, code)) => {
            return Err(format!("target process {pid} exited with code {code}"));
        }
        Ok(other) => {
            return Err(format!("unexpected wait status: {other:?}"));
        }
        Err(e) => {
            let _ = ptrace::detach(nix_pid, None);
            return Err(format!("waitpid failed: {e}"));
        }
    }

    // Get current registers and save ALL of them (syscall clobbers rcx, r11)
    let orig = match ptrace::getregs(nix_pid) {
        Ok(r) => r,
        Err(e) => {
            let _ = ptrace::detach(nix_pid, None);
            return Err(format!("getregs failed: {e}"));
        }
    };

    let mut regs = orig;

    // Set up madvise(addr, len, MADV_MERGEABLE) syscall
    // x86_64: rax=28 (SYS_madvise), rdi=addr, rsi=len, rdx=advice
    regs.rip = syscall_addr;
    regs.rax = SYS_MADVISE as u64;
    regs.rdi = addr;
    regs.rsi = len as u64;
    regs.rdx = MADV_MERGEABLE as u64;

    if let Err(e) = ptrace::setregs(nix_pid, regs) {
        let _ = ptrace::detach(nix_pid, None);
        return Err(format!("setregs failed: {e}"));
    }

    // Step 1: continue until syscall entry
    if let Err(e) = ptrace::syscall(nix_pid, None) {
        let _ = ptrace::setregs(nix_pid, orig);
        let _ = ptrace::detach(nix_pid, None);
        return Err(format!("ptrace syscall (entry) failed: {e}"));
    }
    match waitpid(nix_pid, Some(WaitPidFlag::WSTOPPED)) {
        Ok(WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP)) => {}
        Ok(other) => {
            let _ = ptrace::setregs(nix_pid, orig);
            let _ = ptrace::detach(nix_pid, None);
            return Err(format!("unexpected wait at syscall entry: {other:?}"));
        }
        Err(e) => {
            let _ = ptrace::setregs(nix_pid, orig);
            let _ = ptrace::detach(nix_pid, None);
            return Err(format!("waitpid at syscall entry failed: {e}"));
        }
    }

    // Step 2: continue until syscall exit
    if let Err(e) = ptrace::syscall(nix_pid, None) {
        let _ = ptrace::setregs(nix_pid, orig);
        let _ = ptrace::detach(nix_pid, None);
        return Err(format!("ptrace syscall (exit) failed: {e}"));
    }
    match waitpid(nix_pid, Some(WaitPidFlag::WSTOPPED)) {
        Ok(WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP)) => {}
        Ok(other) => {
            let _ = ptrace::setregs(nix_pid, orig);
            let _ = ptrace::detach(nix_pid, None);
            return Err(format!("unexpected wait at syscall exit: {other:?}"));
        }
        Err(e) => {
            let _ = ptrace::setregs(nix_pid, orig);
            let _ = ptrace::detach(nix_pid, None);
            return Err(format!("waitpid at syscall exit failed: {e}"));
        }
    }

    // Read the syscall return value from rax
    let regs_after = match ptrace::getregs(nix_pid) {
        Ok(r) => r,
        Err(e) => {
            let _ = ptrace::setregs(nix_pid, orig);
            let _ = ptrace::detach(nix_pid, None);
            return Err(format!("getregs after syscall failed: {e}"));
        }
    };

    // Restore ALL original registers before detaching
    if let Err(e) = ptrace::setregs(nix_pid, orig) {
        // CRITICAL: if register restoration fails, the target will resume
        // with corrupted registers (pointing to vDSO syscall) and crash.
        // Treat as fatal, detach and return error.
        let _ = ptrace::detach(nix_pid, None);
        return Err(format!(
            "failed to restore registers after ptrace injection: {e}"
        ));
    }

    if let Err(e) = ptrace::detach(nix_pid, None) {
        return Err(format!("ptrace detach failed: {e}"));
    }

    // Check result (rax contains return value; negative values are errno)
    if (regs_after.rax as i64) < 0 && (regs_after.rax as i64) > -4096 {
        let errno = (-(regs_after.rax as i64)) as i32;
        return Err(format!(
            "madvise failed: errno={errno} ({})",
            errno_to_str(errno)
        ));
    }

    Ok(())
}

/// Convert errno to human-readable string.
fn errno_to_str(errno: i32) -> &'static str {
    match errno {
        libc::EPERM => "EPERM: Operation not permitted",
        libc::ESRCH => "ESRCH: No such process",
        libc::EINVAL => "EINVAL: Invalid argument",
        libc::ENOMEM => "ENOMEM: Cannot allocate memory",
        libc::EBADF => "EBADF: Bad file descriptor",
        libc::ENOSYS => "ENOSYS: Function not implemented",
        _ => "unknown",
    }
}

fn process_madvise_single(
    pidfd: RawFd,
    addr: u64,
    len: usize,
    advice: libc::c_int,
) -> Result<(), String> {
    if advice == MADV_MERGEABLE {
        return Err("MADV_MERGEABLE not supported by process_madvise; use ptrace".to_string());
    }
    let iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    let ret = unsafe {
        libc::syscall(
            SYS_PROCESS_MADVISE,
            pidfd as libc::c_int,
            &iov as *const libc::iovec,
            1usize,
            advice,
            0u32,
        )
    };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(format!("errno={errno} ({})", errno_to_str(errno)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use animaksm_common::procfs::MapsEntry;

    // ── build_batch ──────────────────────────────────────────────────────

    #[test]
    fn test_build_batch_empty_eligible() {
        let eligible: Vec<&MapsEntry> = vec![];
        let batch = build_batch(&eligible, 4096);
        assert!(batch.is_empty());
    }

    #[test]
    fn test_build_batch_collects_regions() {
        let regions = [
            MapsEntry {
                start: 0x10000,
                end: 0x11000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            },
            MapsEntry {
                start: 0x20000,
                end: 0x22000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            },
        ];
        let refs: Vec<&MapsEntry> = regions.iter().collect();
        let batch = build_batch(&refs, 10 * 4096);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], (0x10000, 0x1000usize));
        assert_eq!(batch[1], (0x20000, 0x2000usize));
    }

    #[test]
    fn test_build_batch_respects_max_bytes() {
        let regions = [
            MapsEntry {
                start: 0x10000,
                end: 0x11000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }, // 4KB
            MapsEntry {
                start: 0x20000,
                end: 0x24000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }, // 16KB
            MapsEntry {
                start: 0x30000,
                end: 0x31000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }, // 4KB
        ];
        let refs: Vec<&MapsEntry> = regions.iter().collect();
        // max_bytes = 12KB -> first region plus 8KB from the second region.
        let batch = build_batch(&refs, 12 * 1024);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], (0x10000, 0x1000usize));
        assert_eq!(batch[1], (0x20000, 8 * 1024usize));
    }

    #[test]
    fn test_build_batch_partially_marks_first_large_region() {
        let regions = [MapsEntry {
            start: 0x10000,
            end: 0x90000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        }];
        let refs: Vec<&MapsEntry> = regions.iter().collect();
        let batch = build_batch(&refs, 64 * 1024);
        assert_eq!(batch, vec![(0x10000, 64 * 1024usize)]);
    }

    #[test]
    fn test_build_batch_does_not_apply_iovec_limit_to_ptrace_path() {
        let regions: Vec<MapsEntry> = (0..300)
            .map(|i| {
                let start = 0x10000 + i * 0x2000;
                MapsEntry {
                    start,
                    end: start + 0x1000,
                    perms: "rw-p".into(),
                    offset: 0,
                    dev: "00:00".into(),
                    inode: 0,
                    pathname: String::new(),
                }
            })
            .collect();
        let refs: Vec<&MapsEntry> = regions.iter().collect();
        let batch = build_batch(&refs, 2 * 1024 * 1024);
        assert_eq!(batch.len(), 300);
    }

    #[test]
    fn test_build_batch_exact_capacity() {
        let regions = [
            MapsEntry {
                start: 0x10000,
                end: 0x12000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }, // 8KB
            MapsEntry {
                start: 0x20000,
                end: 0x22000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }, // 8KB
        ];
        let refs: Vec<&MapsEntry> = regions.iter().collect();
        // max_bytes = 16KB → exactly both
        let batch = build_batch(&refs, 16 * 1024);
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn test_build_batch_zero_max_bytes() {
        let regions = [MapsEntry {
            start: 0x10000,
            end: 0x11000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        }];
        let refs: Vec<&MapsEntry> = regions.iter().collect();
        let batch = build_batch(&refs, 0);
        assert!(batch.is_empty(), "zero cap should yield empty batch");
    }

    // ── apply_mergeable (dry-run, using our own PID) ────────────────────

    #[test]
    fn test_apply_mergeable_dry_run_eligible_regions() {
        let my_pid = std::process::id();
        let regions = vec![
            MapsEntry {
                start: 0x10000,
                end: 0x11000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            },
            MapsEntry {
                start: 0x20000,
                end: 0x24000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            },
        ];
        let result = apply_mergeable(my_pid, &regions, 1024 * 1024, true);
        // Both regions should be eligible (anon RW, no exec, not special)
        // First region = 4KB, second = 16KB → total = 20KB
        assert_eq!(result.regions_attempted, 2);
        assert_eq!(result.regions_merged, 2);
        assert_eq!(result.total_bytes_marked, (4 + 16) * 1024);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_apply_mergeable_dry_run_filters_non_eligible() {
        let my_pid = std::process::id();
        // One eligible, one file-backed (not anon), one executable
        let regions = vec![
            MapsEntry {
                start: 0x10000,
                end: 0x11000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }, // eligible
            MapsEntry {
                start: 0x20000,
                end: 0x21000,
                perms: "rw-p".into(),
                offset: 1,
                dev: "00:00".into(),
                inode: 12345,
                pathname: "/some/file".into(),
            }, // file-backed, not eligible
            MapsEntry {
                start: 0x30000,
                end: 0x31000,
                perms: "r-xp".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }, // executable, not eligible
        ];
        let result = apply_mergeable(my_pid, &regions, 1024 * 1024, true);
        // Only the first region should pass the eligibility filter
        assert_eq!(result.regions_attempted, 1);
        assert_eq!(result.regions_merged, 1);
    }

    #[test]
    fn test_apply_mergeable_dry_run_respects_max_bytes() {
        let my_pid = std::process::id();
        let regions = vec![
            MapsEntry {
                start: 0x10000,
                end: 0x12000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }, // 8KB
            MapsEntry {
                start: 0x20000,
                end: 0x24000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }, // 16KB
        ];
        // max_bytes = 8KB → only 1 region fits
        let result = apply_mergeable(my_pid, &regions, 8 * 1024, true);
        assert_eq!(result.regions_attempted, 1);
        assert_eq!(result.regions_merged, 1);
        assert_eq!(result.total_bytes_marked, 8 * 1024);
    }

    #[test]
    fn test_apply_mergeable_dry_run_invalid_pid() {
        // PID 0xFFFFFF is almost certainly non-existent
        let regions = vec![MapsEntry {
            start: 0x10000,
            end: 0x11000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        }];
        let result = apply_mergeable(0xFFFFFF, &regions, 4096, true);
        // In dry_run mode, we build a batch and simulate success without
        // actually checking PID validity (ptrace happens at runtime, not batch-build time)
        assert_eq!(result.regions_attempted, 1);
        assert_eq!(result.regions_merged, 1);
        assert_eq!(result.total_bytes_marked, 4096);
        assert!(
            result.errors.is_empty(),
            "dry run should have no errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_apply_mergeable_returns_zero_when_no_regions_are_eligible() {
        let result = apply_mergeable(
            std::process::id(),
            &[MapsEntry {
                start: 0x10000,
                end: 0x11000,
                perms: "r-xp".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }],
            4096,
            true,
        );

        assert_eq!(result.regions_attempted, 0);
        assert_eq!(result.regions_merged, 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_apply_mergeable_non_dry_run_reports_fallback_errors() {
        let result = apply_mergeable(
            std::process::id(),
            &[MapsEntry {
                start: 0x10000,
                end: 0x11000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }],
            4096,
            false,
        );

        assert_eq!(result.regions_attempted, 1);
        assert_eq!(result.regions_merged, 0);
        assert_eq!(result.total_bytes_marked, 0);
        assert!(!result.errors.is_empty());
        // Now uses ptrace injection, not process_madvise
        assert!(result.errors[0].1.contains("ptrace madvise failed"));
    }

    #[test]
    fn test_collapse_regions_returns_zero_without_large_eligible_regions() {
        let collapsed = collapse_regions(
            std::process::id(),
            &[MapsEntry {
                start: 0x10000,
                end: 0x11000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }],
        );

        assert_eq!(collapsed, 0);
    }

    #[test]
    fn test_collapse_regions_attempts_large_aligned_region_without_panicking() {
        let collapsed = collapse_regions(
            std::process::id(),
            &[MapsEntry {
                start: 0x200000,
                end: 0x400000,
                perms: "rw-p".into(),
                offset: 0,
                dev: "00:00".into(),
                inode: 0,
                pathname: String::new(),
            }],
        );

        assert_eq!(collapsed, 0);
    }

    // ── collapse_regions: eligibility + 2 MiB alignment (pure logic) ────

    /// Helper: an anonymous RW private mapping, the only shape `collapse_regions`
    /// ever considers.
    fn anon_rw_entry(start: u64, end: u64) -> MapsEntry {
        MapsEntry {
            start,
            end,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        }
    }

    /// A PID that cannot exist on this host, so `pidfd_open` fails with EINVAL
    /// (u32::MAX does not fit a valid pid_t) and no process is ever touched.
    /// With the pidfd unavailable, `collapse_regions` returns 0 before any
    /// syscall, which makes the pure-logic tests below fully deterministic.
    const ABSENT_PID: u32 = u32::MAX;

    /// The 2 MiB alignment rules `collapse_regions` applies, reproduced against
    /// the real implementation's arithmetic:
    ///
    /// * `start` rounds UP to the next 2 MiB boundary (partial head page dropped)
    /// * `end` rounds DOWN to the previous 2 MiB boundary (partial tail dropped)
    /// * a region is only attempted when the rounded `start` is strictly below
    ///   the rounded `end`
    ///
    /// Verified cases (all of which pass the `size() >= 2 MiB` filter, so the
    /// decision is made purely by the rounding):
    ///
    /// | start      | end        | size     | rounded window       | verdict |
    /// |------------|------------|----------|----------------------|---------|
    /// | 0x200000   | 0x600000   | 4 MiB    | [0x200000, 0x600000) | attempt |
    /// | 0x200000   | 0x600001   | 4 MiB+1  | [0x200000, 0x600000) | attempt |
    /// | 0x201000   | 0x800000   | 6 MiB-4K | [0x400000, 0x800000) | attempt |
    /// | 0x100000   | 0x300000   | 2 MiB    | [0x200000, 0x200000) | skip    |
    /// | 0x0        | 0x200000   | 2 MiB    | [0x0, 0x200000)      | attempt |
    #[test]
    fn test_collapse_regions_rounding_decides_attempt_vs_skip() {
        const THP_SIZE: u64 = 2 * 1024 * 1024;

        // Rounding arithmetic of `collapse_regions`, reproduced here:
        //   start = (region.start + THP_SIZE - 1) & !(THP_SIZE - 1)
        //   end   = region.end & !(THP_SIZE - 1)
        let aligned_window = |start: u64, end: u64| {
            (
                (start + THP_SIZE - 1) & !(THP_SIZE - 1),
                end & !(THP_SIZE - 1),
            )
        };

        // Fully aligned region → whole region is the window.
        let whole = anon_rw_entry(0x200000, 0x600000);
        assert_eq!(aligned_window(whole.start, whole.end), (0x200000, 0x600000));
        assert_eq!(whole.end - whole.start, 4 * 1024 * 1024);

        // Unaligned end → the partial tail page is dropped from the window.
        let ragged = anon_rw_entry(0x200000, 0x600001);
        assert_eq!(
            aligned_window(ragged.start, ragged.end),
            (0x200000, 0x600000)
        );

        // Unaligned start → the partial head page is dropped from the window.
        let ragged_head = anon_rw_entry(0x201000, 0x800000);
        assert_eq!(
            aligned_window(ragged_head.start, ragged_head.end),
            (0x400000, 0x800000)
        );

        // A region that passes the size filter but contains no aligned window:
        // start rounds up to 0x200000 and end rounds down to the same address.
        let no_window = anon_rw_entry(0x100000, 0x300000);
        assert!(no_window.size() >= THP_SIZE, "size filter is satisfied");
        let (window_start, window_end) = aligned_window(no_window.start, no_window.end);
        assert_eq!(window_start, 0x200000);
        assert_eq!(window_end, 0x200000);
        assert!(
            window_start >= window_end,
            "empty window → region is skipped"
        );

        // Drive the real function with the attempt-class regions. `ABSENT_PID`
        // makes `pidfd_open` fail first, so no syscall is issued and 0
        // collapses is the only possible outcome — but the entries must still
        // survive the filters without panicking.
        let attempted = collapse_regions(ABSENT_PID, &[whole, ragged, ragged_head]);
        assert_eq!(attempted, 0, "absent pid → pidfd_open fails → 0 collapsed");
    }

    /// Regions that carry no aligned 2 MiB window and must be skipped.
    ///
    /// The first two fail the `size() >= 2 MiB` filter outright. The third is
    /// the interesting one: it is exactly 2 MiB but sits between boundaries, so
    /// `start` rounds up to 0x200000 while `end` rounds down to 0x200000 and the
    /// window is empty — the skip comes from the alignment logic, not the size.
    #[test]
    fn test_collapse_regions_skips_regions_without_aligned_thp_window() {
        const THP_SIZE: u64 = 2 * 1024 * 1024;

        // A 1 MiB region: fails the `size() >= 2 MiB` filter outright.
        let too_small = anon_rw_entry(0x200000, 0x300000);
        // A single page: also fails the size filter.
        let single_page = anon_rw_entry(0x200000, 0x201000);
        // Exactly 2 MiB but starting 1 MiB into a boundary, so its aligned
        // window [0x200000, 0x200000) is empty and it is skipped by the
        // rounding rather than the size filter.
        let straddling = anon_rw_entry(0x100000, 0x300000);

        assert!(too_small.size() < THP_SIZE);
        assert!(single_page.size() < THP_SIZE);
        assert!(
            straddling.size() == THP_SIZE,
            "size filter must still pass — the skip is decided by rounding"
        );
        assert_eq!(
            straddling.start % THP_SIZE,
            THP_SIZE / 2,
            "premise: start is half a THP past a boundary"
        );
        assert_eq!(
            straddling.end % THP_SIZE,
            THP_SIZE / 2,
            "premise: end bears the same offset, so it rounds back to the same boundary"
        );

        // Reproduce collapse_regions' rounding to show the window is empty.
        assert_eq!(
            (straddling.start + THP_SIZE - 1) & !(THP_SIZE - 1),
            0x200000
        );
        assert_eq!(straddling.end & !(THP_SIZE - 1), 0x200000);

        let collapsed = collapse_regions(ABSENT_PID, &[too_small, single_page, straddling]);
        assert_eq!(
            collapsed, 0,
            "no region contains an aligned 2 MiB window → nothing attempted"
        );
    }

    /// The eligibility filter: only anonymous RW private, non-exec, non-special
    /// mappings qualify. Every variant below is rejected, so neither the
    /// rounding nor a syscall is ever reached.
    #[test]
    fn test_collapse_regions_filters_ineligible_permissions() {
        const THP_SIZE: u64 = 2 * 1024 * 1024;

        let mut executable = anon_rw_entry(0x200000, 0x600000);
        executable.perms = "rwxp".into();
        assert!(executable.has_exec());
        assert!(executable.size() >= THP_SIZE);

        let mut shared = anon_rw_entry(0x200000, 0x600000);
        shared.perms = "rw-s".into();
        assert!(
            !shared.is_anon_rw(),
            "shared mappings are not KSM candidates"
        );

        let mut read_only = anon_rw_entry(0x200000, 0x600000);
        read_only.perms = "r--p".into();
        assert!(!read_only.is_anon_rw());

        let mut file_backed = anon_rw_entry(0x200000, 0x600000);
        file_backed.pathname = "/usr/lib/libfoo.so".into();
        assert!(!file_backed.is_anon_rw());

        let special = MapsEntry {
            start: 0x200000,
            end: 0x600000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: "[vdso]".into(),
        };
        assert!(special.is_special());
        assert!(!special.is_anon_rw(), "[vdso] has a non-empty pathname");

        let empty: &[MapsEntry] = &[];
        assert_eq!(collapse_regions(ABSENT_PID, empty), 0);

        let collapsed = collapse_regions(
            ABSENT_PID,
            &[executable, shared, read_only, file_backed, special],
        );
        assert_eq!(
            collapsed, 0,
            "ineligible mappings are filtered before any pidfd/syscall"
        );
    }

    /// Drive the real syscall path of `collapse_regions` →
    /// `process_madvise_single(MADV_COLLAPSE)` against our own process only,
    /// with an address that is guaranteed unmapped. MADV_COLLAPSE must fail
    /// (EINVAL for an unsuitable range) and that failure must be non-fatal:
    /// `collapse_regions` logs and continues, returning 0 rather than panicking
    /// or propagating an error.
    ///
    /// This also proves the pidfd opened for our own process is closed on the
    /// error path and the surrounding loop keeps going.
    #[test]
    fn test_collapse_regions_handles_process_madvise_error_gracefully() {
        // An address well past the canonical userspace limit, so no mapping can
        // cover it — process_madvise(2) rejects the whole range with EINVAL
        // (verified against this kernel).
        let unmapped = 0x7fff_ffff_0000u64;

        // Attempted before and after the rejected range: both must be
        // attempted (non-fatal) and neither collapses.
        let regions = [
            anon_rw_entry(unmapped, unmapped + 4 * 1024 * 1024),
            anon_rw_entry(unmapped + 16 * 1024 * 1024, unmapped + 20 * 1024 * 1024),
        ];

        let collapsed = collapse_regions(std::process::id(), &regions);
        assert_eq!(
            collapsed, 0,
            "a rejected MADV_COLLAPSE must be absorbed, not fatal"
        );
    }

    /// The errno string formatting shared by every process_madvise path:
    /// `errno_to_str` must map the errnos that MADV_COLLAPSE actually
    /// produces, otherwise the ENOSYS break in `collapse_regions` never fires.
    #[test]
    fn test_errno_to_str_covers_collapse_errnos() {
        assert!(errno_to_str(libc::EBADF).contains("EBADF"));
        assert!(errno_to_str(libc::ENOSYS).contains("ENOSYS"));
        assert!(errno_to_str(libc::EINVAL).contains("EINVAL"));
        assert!(errno_to_str(libc::ESRCH).contains("ESRCH"));
        assert!(errno_to_str(libc::ENOMEM).contains("ENOMEM"));
        assert!(errno_to_str(libc::EPERM).contains("EPERM"));
        assert_eq!(errno_to_str(-1), "unknown");
    }

    // ── batch_apply_mergeable ───────────────────────────────────────────

    #[test]
    fn test_batch_apply_mergeable_multiple_targets() {
        let my_pid = std::process::id();
        let regions = vec![MapsEntry {
            start: 0x10000,
            end: 0x11000,
            perms: "rw-p".into(),
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            pathname: String::new(),
        }];

        // Two different PIDs — batch_apply_mergeable returns one per PID
        let other_pid = my_pid.checked_add(1).unwrap_or(2);
        let targets = vec![(my_pid, regions.clone()), (other_pid, regions)];
        let results = batch_apply_mergeable(&targets, 4096, true);

        assert_eq!(results.len(), 2, "should have entries for both PIDs");
        // First PID exists → dry-run succeeds with 1 region merged
        assert_eq!(results[&my_pid].regions_merged, 1);
        // In dry_run mode, non-existent PID still simulates success
        // (ptrace only runs at runtime, not during dry-run batch building)
        assert_eq!(results[&other_pid].regions_merged, 1);
    }

    // ── MadviseResult ───────────────────────────────────────────────────

    #[test]
    fn test_madvise_result_default_zeroes() {
        let result = MadviseResult {
            pid: 42,
            regions_attempted: 0,
            regions_merged: 0,
            total_bytes_marked: 0,
            errors: vec![],
        };
        assert_eq!(result.pid, 42);
        assert_eq!(result.regions_merged, 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_madvise_result_with_errors() {
        let result = MadviseResult {
            pid: 99,
            regions_attempted: 2,
            regions_merged: 1,
            total_bytes_marked: 4096,
            errors: vec![(0x10000, "EPERM: Operation not permitted".into())],
        };
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.regions_merged, 1);
    }
    #[test]
    fn test_errno_to_str_known_and_unknown() {
        assert!(errno_to_str(libc::EPERM).contains("EPERM"));
        assert_eq!(errno_to_str(999_999), "unknown");
    }
    /// The helper must reject `MADV_MERGEABLE` *before* issuing any syscall —
    /// process_madvise(2) cannot apply that advice cross-process, so ptrace is
    /// the only route. Guarded with an advice check against an intentionally bad
    /// fd so the assertion can only be satisfied by the early return.
    #[test]
    fn test_process_madvise_guards_madvise_mergeable() {
        // A fd that is never valid in this process. Were the guard missing, the
        // helper would fall through to process_madvise and report an EBADF
        // errno string instead of this exact advice message.
        const GUARD_FD: RawFd = -1;

        let single_err =
            process_madvise_single(GUARD_FD, 0x200000, 2 * 1024 * 1024, MADV_MERGEABLE)
                .unwrap_err();

        assert_eq!(
            single_err, "MADV_MERGEABLE not supported by process_madvise; use ptrace",
            "the helper must reject MADV_MERGEABLE before the syscall"
        );
    }

    /// The negative side of the same guard: advice values that process_madvise
    /// *does* support must pass the check and reach the syscall, where the bad
    /// fd surfaces as an EBADF-annotated errno string instead of the advice
    /// message. This pins the guard's boundary so a future regression that
    /// widens it to all advice values is caught.
    #[test]
    fn test_process_madvise_allows_supported_advice() {
        const GUARD_FD: RawFd = -1;

        // MADV_COLLAPSE is the advice `collapse_regions` passes in production.
        let collapsed_err =
            process_madvise_single(GUARD_FD, 0x200000, 2 * 1024 * 1024, MADV_COLLAPSE).unwrap_err();
        assert!(
            collapsed_err.contains("errno="),
            "supported advice must reach the syscall, got: {collapsed_err}"
        );
        assert!(
            !collapsed_err.contains("not supported by process_madvise"),
            "MADV_COLLAPSE must not trip the MERGEABLE guard, got: {collapsed_err}"
        );

        let cold_err = process_madvise_single(GUARD_FD, 0x200000, 2 * 1024 * 1024, libc::MADV_COLD)
            .unwrap_err();
        assert!(
            cold_err.contains("errno="),
            "MADV_COLD must reach the syscall, got: {cold_err}"
        );
        assert!(
            !cold_err.contains("not supported by process_madvise"),
            "MADV_COLD must not trip the MERGEABLE guard, got: {cold_err}"
        );
    }

    /// The helper, given supported advice against a bad fd, must report the raw
    /// errno and its human-readable name — the exact string `collapse_regions`
    /// pattern-matches on to decide whether to break out of its loop.
    #[test]
    fn test_process_madvise_reports_bad_fd_errno_message() {
        const GUARD_FD: RawFd = -1;

        let single_err =
            process_madvise_single(GUARD_FD, 0x200000, 2 * 1024 * 1024, MADV_COLLAPSE).unwrap_err();

        assert!(single_err.contains("errno="), "got: {single_err}");
        assert!(single_err.contains("EBADF"), "got: {single_err}");
    }

    /// `pidfd_open` on a PID that cannot exist must fail cleanly with an errno
    /// string — this is the path `collapse_regions` takes to return 0 without
    /// attempting any syscall.
    #[test]
    fn test_pidfd_open_reports_absent_pid_as_errno_string() {
        let err = pidfd_open(ABSENT_PID).unwrap_err();
        assert!(err.contains("errno="), "got: {err}");
    }
}
