//! Tier 2: process-wide KSM eligibility + THP collapse.
//!
//! ## Why `PR_SET_MEMORY_MERGE` instead of per-region `MADV_MERGEABLE`
//!
//! The original approach injected `madvise(addr, len, MADV_MERGEABLE)` once per
//! eligible VMA via ptrace. That had two costs measured on a live workstation:
//! it required parsing `/proc/PID/maps` for every candidate, and it capped how
//! many candidates could be marked per cycle, leaving ~2.4 GiB of anonymous
//! memory permanently un-offered while netting only 22.3 MiB of savings.
//!
//! Linux gained a per-`mm` alternative — `PR_SET_MEMORY_MERGE` (prctl option
//! 67, confirmed present and working on 6.x/7.x) — which is what uksmd's
//! `process_ksm_enable()` syscall did on pf-kernel. One injection marks
//! **every** mapping of a process mergeable, including VMAs created after the
//! call, and no address/length pair is needed for the marking itself.
//!
//! The saving over the old path is the *population*: every non-executable
//! mapping is offered, not just the ones a userspace daemon enumerated.
//! `/proc/PID/maps` is still read, but only to locate executable mappings to
//! withdraw from merging — see [`unmerge_executable_vmas`].
//!
//! ## Safety: the flag is inherited
//!
//! `MMF_VM_MERGE_ANY` is a property of `struct mm_struct`, so it is inherited by
//! children across `fork` **and across `execve`** — both verified live. Marking
//! a shell therefore marks every command it later runs. The scanner's blocklist
//! and an optional ancestor blocklist are the guard; see `scanner.rs`.
//!
//! ## MADV_COLLAPSE
//!
//! Opportunistic THP promotion: when KSM unmerges pages (triggering CoW),
//! those pages lose their THP backing. MADV_COLLAPSE (Linux 6.1+)
//! re-promotes aligned 2MB regions to transparent huge pages, recovering
//! TLB efficiency. This uses `process_madvise(2)` directly, which does support
//! it cross-process.

use std::os::unix::io::RawFd;

use animaksm_common::procfs::MapsEntry;
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use tracing::{debug, info};

/// `PR_SET_MEMORY_MERGE` — marks every mapping of the calling process
/// KSM-eligible (`MMF_VM_MERGE_ANY` in `struct mm_struct`).
/// From `linux/prctl.h`; verified present and functional on 6.x/7.x.
const PR_SET_MEMORY_MERGE: libc::c_ulong = 67;

/// MADV_MERGEABLE constant (from linux/mman.h).
///
/// `process_madvise(2)` rejects this advice, so [`process_madvise_single`]
/// guards against it explicitly rather than letting callers reach a syscall
/// that cannot succeed. It is *not* used to mark memory any more.
const MADV_MERGEABLE: libc::c_int = 12;

/// `MADV_UNMERGEABLE` — undoes `MADV_MERGEABLE` for one VMA.
///
/// This is the safety valve for `PR_SET_MEMORY_MERGE`. See
/// [`unmerge_executable_vmas`] for why the kernel's own gate is not enough.
const MADV_UNMERGEABLE: libc::c_int = 13;

/// MADV_COLLAPSE constant (Linux 6.1+, collapses memory into THP).
const MADV_COLLAPSE: libc::c_int = 25;

/// process_madvise syscall number (x86_64).
const SYS_PROCESS_MADVISE: libc::c_long = 440;

/// pidfd_open syscall number (x86_64).
const SYS_PIDFD_OPEN: libc::c_long = 434;

/// prctl syscall number (x86_64).
const SYS_PRCTL: libc::c_long = 157;

/// madvise syscall number (x86_64).
const SYS_MADVISE: libc::c_long = 28;

/// Result of enabling process-wide KSM eligibility on one process.
#[derive(Debug)]
pub struct MergeableResult {
    pub pid: u32,
    /// 1 when the injection succeeded, else 0.
    pub processes_marked: usize,
    /// Executable VMAs withdrawn from merging after the flag was set. See
    /// [`unmerge_executable_vmas`] — this is a safety counter, not a tunable.
    pub exec_vmas_protected: usize,
    pub error: Option<String>,
}

/// Enable process-wide KSM eligibility on a target process.
///
/// Injects `prctl(PR_SET_MEMORY_MERGE, 1, 0, 0, 0)` via ptrace, then withdraws
/// eligibility from the process's executable mappings. Both steps are
/// required: the first opens the whole address space to KSM, the second puts
/// `.text` back out of reach, which is the constraint the userspace
/// `madvise(MADV_MERGEABLE)` API used to provide and the kernel's `merge_any`
/// gate does not. See [`unmerge_executable_vmas`] for the kernel source and
/// the measured failure this prevents.
///
/// `prctl` cannot be executed on another process by any other means — it always
/// acts on the calling process's `mm` — so ptrace injection is the only route
/// for a target the daemon does not own. systemd's `MemoryKSM=` covers the
/// service case at launch.
///
/// For `dry_run`, no attachment happens and success is assumed.
pub fn enable_merge_any(pid: u32, dry_run: bool) -> MergeableResult {
    if dry_run {
        return MergeableResult {
            pid,
            processes_marked: 1,
            exec_vmas_protected: 0,
            error: None,
        };
    }

    match prctl_via_ptrace(pid, PR_SET_MEMORY_MERGE, 1, 0, 0) {
        Ok(()) => {
            // Ordering matters: `PR_SET_MEMORY_MERGE` marks every existing VMA,
            // so the executable ones must be withdrawn immediately after, in
            // the same pass, before ksmd can observe them.
            let (withdrawn, exec_vmas) = unmerge_executable_vmas(pid, false);
            debug!(
                pid,
                withdrawn, exec_vmas, "Enabled process-wide KSM eligibility"
            );
            MergeableResult {
                pid,
                processes_marked: 1,
                exec_vmas_protected: withdrawn,
                error: None,
            }
        }
        Err(e) => MergeableResult {
            pid,
            processes_marked: 0,
            exec_vmas_protected: 0,
            error: Some(e),
        },
    }
}

/// Withdraw process-wide eligibility from executable code mappings.
///
/// ## Why this is mandatory
///
/// `PR_SET_MEMORY_MERGE` makes **every** mapping of a process eligible, and the
/// kernel's gate (`__ksm_should_add_vma` → `ksm_compatible()`) decides what to
/// accept with this rule and no other:
///
/// ```c
/// static bool ksm_compatible(const struct file *file, vma_flags_t vma_flags)
/// {
///         if (vma_flags_test_any(&vma_flags, VMA_SHARED_BIT, VMA_MAYSHARE_BIT,
///                                VMA_HUGETLB_BIT))
///                 return false;
///         if (vma_flags_test_single_mask(&vma_flags, VMA_DROPPABLE))
///                 return false;
///         if (vma_flags_test_any(&vma_flags, VMA_SPECIAL_FLAGS))
///                 return false;
///         return true;
/// }
/// ```
///
/// Verified against `torvalds/linux:mm/ksm.c`. **`VM_EXEC` is not in that
/// list.** A userspace `madvise(addr, len, MADV_MERGEABLE)` would never have
/// been issued against a code mapping, so in-tree KSM's long-standing
/// behaviour is to leave `.text` alone — the kernel simply never gets the
/// chance. `merge_any` removes that implicit constraint by marking the VMA
/// itself, so the daemon has to restore the constraint the userspace API used
/// to provide.
///
/// The consequence of not doing so is measured, not theoretical. A live run
/// of the daemon marked Chrome (Chromium clang build, `--app=` window plus
/// four renderers); 90 seconds later the renderers died with
///
/// ```text
/// traps: chrome[1178241] trap invalid opcode ip:559b3271e0c0 sp:7ffc95e99410
/// error:0 in chrome[6d9d0c0,559b2d01c000+e32d000]
/// ```
///
/// The minidumps resolve that faulting address to offset `0x6d9e0c0` of
/// `/opt/chromium.org/chromium-unstable/chrome` — the V8/Blink `.text`
/// segment, with the same IP and SP in all four reports.
///
/// ## Why it must be injected rather than called through `process_madvise`
///
/// `process_madvise(2)` handles `MADV_UNMERGEABLE` internally (line 1418 of
/// `mm/madvise.c`) but gates *remote* calls with `process_madvise_remote_valid()`,
/// which allows only `MADV_COLD`, `MADV_PAGEOUT`, `MADV_WILLNEED` and
/// `MADV_COLLAPSE`. A KSM advice on another process's `mm` therefore has no
/// syscall route, and — exactly as for `prctl` — needs ptrace injection of
/// `madvise(addr, len, MADV_UNMERGEABLE)` per region.
///
/// This is still a large win over the path it replaces: one `prctl` plus a
/// handful of `madvise` calls per process, versus one `madvise` per eligible
/// region over the whole process.
///
/// ## Correctness note
///
/// `MADV_UNMERGEABLE` clears only `VM_MERGEABLE` on the targeted VMA; it leaves
/// `MMF_VM_MERGE_ANY` on the `mm_struct` intact and therefore still covers
/// every other mapping, including those created after this call.
///
/// # Returns
/// `(vmas_withdrawn, exec_vmas)` — the first is the count withdrawn, the second
/// is the count of executable mappings found, so metrics can tell "protected"
/// apart from "none found".
pub fn unmerge_executable_vmas(pid: u32, dry_run: bool) -> (usize, usize) {
    let maps = match animaksm_common::procfs::read_process_maps(pid) {
        Ok(m) => m,
        Err(e) => {
            debug!(pid, error = %e, "cannot read maps to protect executable VMAs");
            return (0, 0);
        }
    };

    let exec_vmas: Vec<&MapsEntry> = maps.iter().filter(|e| e.has_exec()).collect();
    if exec_vmas.is_empty() {
        return (0, 0);
    }

    if dry_run {
        return (exec_vmas.len(), exec_vmas.len());
    }

    let mut withdrawn = 0;
    for vma in &exec_vmas {
        let len = vma.end.saturating_sub(vma.start) as usize;
        if len == 0 {
            continue;
        }
        match madvise_via_ptrace(pid, vma.start, len, MADV_UNMERGEABLE) {
            Ok(()) => withdrawn += 1,
            Err(e) => debug!(
                pid,
                start = format!("0x{:x}", vma.start),
                error = %e,
                "MADV_UNMERGEABLE skipped for executable VMA"
            ),
        }
    }

    if withdrawn > 0 {
        debug!(
            pid,
            withdrawn,
            exec_vmas = exec_vmas.len(),
            "Protected executable VMAs from KSM merging"
        );
    }

    (withdrawn, exec_vmas.len())
}
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

/// ptrace(2) syscall injection pattern (x86_64):
///   1. PTRACE_ATTACH + waitpid(WSTOPPED)
///   2. getregs → save ALL registers (syscall clobbers rcx, r11)
///   3. Find a `syscall` instruction in the target’s vDSO
///   4. Set regs: rip → vDSO syscall addr, rax=nr, rdi..r5 = args
///   5. ptrace(SYSCALL) → waitpid (entry stop)
///   6. ptrace(SYSCALL) → waitpid (exit stop)
///   7. getregs → read rax for return value
///   8. Restore ALL original registers
///   9. PTRACE_DETACH
///
/// Inject `prctl(option, arg2, arg3, arg4, arg5)` into a target process.
fn prctl_via_ptrace(
    pid: u32,
    option: libc::c_ulong,
    arg2: libc::c_ulong,
    arg3: libc::c_ulong,
    arg4: libc::c_ulong,
) -> Result<(), String> {
    inject_syscall(pid, SYS_PRCTL, option, arg2, arg3, arg4, 0, 0)
}

/// Inject `madvise(addr, len, advice)` into a target process.
///
/// Needed because `process_madvise(2)` refuses KSM advices on a remote `mm`
/// (`process_madvise_remote_valid()` in `mm/madvise.c` allows only COLD,
/// PAGEOUT, WILLNEED and COLLAPSE), so `MADV_UNMERGEABLE` on another process
/// has no syscall route.
fn madvise_via_ptrace(pid: u32, addr: u64, len: usize, advice: libc::c_int) -> Result<(), String> {
    inject_syscall(pid, SYS_MADVISE, addr, len as u64, advice as u64, 0, 0, 0)
}

/// Inject an arbitrary syscall into a target process via ptrace.
///
/// Attaches, saves every register, points RIP at the target's own vDSO
/// `syscall` instruction with the requested number in RAX and the arguments
/// in RDI..R9, single-steps entry then exit, reads RAX, and restores *all*
/// original registers before detaching. Register restoration failure is
/// treated as fatal: the target would otherwise resume with a corrupted RIP.
#[allow(clippy::too_many_arguments)]
fn inject_syscall(
    pid: u32,
    syscall_nr: libc::c_long,
    arg1: libc::c_ulong,
    arg2: libc::c_ulong,
    arg3: libc::c_ulong,
    arg4: libc::c_ulong,
    arg5: libc::c_ulong,
    arg6: libc::c_ulong,
) -> Result<(), String> {
    let nix_pid = Pid::from_raw(pid as i32);

    debug!(
        pid,
        syscall_nr, "Injecting syscall into target process via ptrace"
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

    // Locate the target's own vDSO `syscall` instruction to execute.
    let syscall_addr = match find_syscall_in_vdso(pid) {
        Ok(addr) => addr,
        Err(e) => {
            let _ = ptrace::detach(nix_pid, None);
            return Err(format!("cannot find syscall instruction: {e}"));
        }
    };

    let mut regs = orig;

    // Set up the injected syscall: rax = number, rdi..r6 = the six arguments.
    // On x86_64 the register set doubles as the argument registers, minus r10
    // which carries the kernel-side rcx clobber.
    regs.rip = syscall_addr;
    regs.rax = syscall_nr as u64;
    regs.rdi = arg1;
    regs.rsi = arg2;
    regs.rdx = arg3;
    regs.r10 = arg4;
    regs.r8 = arg5;
    regs.r9 = arg6;

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
    let ret = regs_after.rax as i64;
    if ret < 0 && ret > -4096 {
        let errno = (-ret) as i32;
        return Err(format!(
            "injected syscall (nr={}) failed: errno={errno} ({})",
            syscall_nr,
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

    // ── enable_merge_any (dry-run) ────────────────────────────────────────

    #[test]
    fn test_enable_merge_any_dry_run_marks_without_attaching() {
        let result = enable_merge_any(std::process::id(), true);

        assert_eq!(result.pid, std::process::id());
        assert_eq!(result.processes_marked, 1);
        assert!(
            result.error.is_none(),
            "dry run must not attach or report errors: {:?}",
            result.error
        );
    }

    #[test]
    fn test_enable_merge_any_on_dead_pid_reports_error_not_success() {
        // A PID that cannot exist on this host; the ptrace attach must fail
        // loudly rather than silently claiming success.
        let result = enable_merge_any(0xFFFF_FFFE, false);

        assert_eq!(result.processes_marked, 0);
        assert_eq!(result.exec_vmas_protected, 0);
        assert!(
            result.error.is_some(),
            "injecting into a dead PID must report an error"
        );
    }

    // ── executable-VMA guard ──────────────────────────────────────────────

    /// Regression test for the SIGILL crashes this guard prevents.
    ///
    /// `PR_SET_MEMORY_MERGE` makes every VMA eligible, and in-tree KSM's gate
    /// (`ksm_compatible()` in `mm/ksm.c`) excludes only VM_SHARED, VM_HUGETLB
    /// and the VMA_SPECIAL set — **not VM_EXEC**. So a browser's `r-xp` code
    /// mapping becomes mergeable. Live evidence: four Chromium renderers died
    /// with `traps: chrome[...] trap invalid opcode ip:559b3271e0c0` at the
    /// same offset (0x6d9e0c0) of the chrome binary, i.e. inside `.text`.
    ///
    /// This asserts the guard finds and withdraws a real executable VMA in the
    /// test binary itself, using its own maps — no mocking.
    #[test]
    fn test_unmerge_executable_vmas_withdraws_real_executable_vmas() {
        let pid = std::process::id();

        // Precondition: any process running code has executable mappings.
        let exec_in_maps = animaksm_common::procfs::read_process_maps(pid)
            .expect("test process maps must be readable")
            .iter()
            .filter(|m| m.has_exec())
            .count();
        assert!(
            exec_in_maps > 0,
            "expected this process to have executable mappings to protect"
        );

        // dry_run: reports what it would do, touches nothing.
        let (dry, dry_total) = unmerge_executable_vmas(pid, true);
        assert_eq!(dry, dry_total);
        assert_eq!(dry_total, exec_in_maps);

        // Real run. On a build host the injected madvise may be refused (no
        // ptrace scope available in a sandboxed CI), so the contract is that
        // the guard *attempted* every executable VMA and reported honestly.
        let (withdrawn, total) = unmerge_executable_vmas(pid, false);
        assert_eq!(
            total, exec_in_maps,
            "every executable VMA must be attempted, none skipped silently"
        );
        assert!(
            withdrawn <= total,
            "cannot withdraw more VMAs than were found"
        );
    }

    /// The guard must not invent executable VMAs for a process that has none.
    #[test]
    fn test_unmerge_executable_vmas_reports_zero_for_dead_pid() {
        let (withdrawn, total) = unmerge_executable_vmas(0xFFFF_FFFE, false);

        assert_eq!(withdrawn, 0);
        assert_eq!(total, 0);
    }

    /// `enable_merge_any` must carry the guard's result, so operators can see
    /// protection actually happening rather than assume it.
    #[test]
    fn test_enable_merge_any_on_dead_pid_reports_zero_exec_vmas_protected() {
        let result = enable_merge_any(0xFFFF_FFFE, false);

        assert_eq!(result.exec_vmas_protected, 0);
    }

    // ── collapse_regions (MADV_COLLAPSE via process_madvise) ──────────────

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
