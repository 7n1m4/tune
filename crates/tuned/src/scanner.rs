//! Tier 2: Process-aware Memory Scanner
//!
//! Identifies processes with high duplicate-page potential and applies
//! MADV_MERGEABLE via process_madvise(2). Acts as a **KSM hint generator**,
//! not a forced deduplicator — it seeds KSM eligibility for stable,
//! cold anonymous regions.
//!
//! ## Multi-Level Filtering (avoids O(n×m) cost)
//!
//! 1. **Level 1 (cheap):** `/proc/PID/status` RSS threshold → filter to
//!    large processes only.
//! 2. **Level 2 (medium):** `/proc/PID/ksm_stat` → skip already-merged.
//! 3. **Level 3 (expensive):** `/proc/PID/maps` → only for top K candidates
//!    by RSS, then apply madvise.
//!
//! ## Guard re-protection
//!
//! Level 2 does not merely skip an already-flagged process: it routes it into a
//! separate pass that re-withdraws executable VMAs (see
//! [`madvise::unmerge_executable_vmas`]). `MMF_VM_MERGE_ANY` is sticky and
//! inherited, so a flagged process keeps acquiring new `r-xp` mappings after it
//! was marked. That pass is budgeted by `max_candidates_per_cycle`, rate-limited
//! per PID to the scan interval, and skips the daemon's own PID.
//!
//! ## Stabilization
//!
//! Respects its own stabilization window for madvise bursts. Governor profile
//! changes use a separate timestamp and do not block scanner cycles.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::time;
use tracing::{debug, info, warn};
use tuned_common::config::ScannerConfig;
use tuned_common::procfs::{self, KsmProcStat, ProcessStatus};
use tuned_common::SharedGovernorState;

use crate::madvise;

/// Scanner statistics.
#[derive(Debug, Clone, Default)]
pub struct ScannerStats {
    pub processes_filtered_l1: u64,
    pub processes_filtered_l2: u64,
    pub processes_filtered_l25_profit: u64,
    pub processes_marked: u64,
    /// Executable VMAs withdrawn from KSM eligibility after marking. Non-zero
    /// means the guard in `madvise::enable_merge_any` ran; the guard exists
    /// because in-tree KSM's `merge_any` gate does not exclude `VM_EXEC`.
    pub exec_vmas_protected: u64,
    /// Executable VMAs that could **not** be withdrawn — the ptrace attach was
    /// refused or the target vanished mid-pass. This is the counter that makes
    /// `exec_vmas_protected` readable: zero protected *with* zero failed means
    /// the target had no executable mappings, whereas zero protected *with*
    /// non-zero failed means the target is mergeable through its code and the
    /// guard could not stop it. A live Chromium fault is exactly the latter.
    pub exec_vmas_unprotected: u64,
    /// Executable VMAs withdrawn again on processes already holding the flag.
    /// A browser maps new `r-xp` regions (JIT, fresh renderers) after it was
    /// flagged, so the guard must re-run, not merely run once.
    pub exec_vmas_reprotected: u64,
    pub injection_failures: u64,
    pub scan_cycles: u64,
    pub skipped_stabilization: u64,
    pub thp_collapsed: u64,
}

/// A scored candidate process.
struct Candidate {
    pid: u32,
    name: String,
    anon_rss_mb: u64,
}

fn l1_candidate_from_status(status: ProcessStatus, config: &ScannerConfig) -> Option<Candidate> {
    if status.pid <= 2 {
        return None;
    }

    if procfs::is_blocklisted(&status.name, &config.blocklist) {
        return None;
    }

    let anon_rss_mb = status.anon_rss_kb / 1024;
    if anon_rss_mb < config.min_anon_rss_mb {
        return None;
    }

    Some(Candidate {
        pid: status.pid,
        name: status.name,
        anon_rss_mb,
    })
}

fn passes_l2_already_merged_filter(ksm_stat: Option<&KsmProcStat>) -> bool {
    !ksm_stat.map(|s| s.merge_any).unwrap_or(false)
}

fn passes_l25_profit_filter(ksm_stat: Option<&KsmProcStat>) -> bool {
    ksm_stat.map(|s| s.process_profit >= 0).unwrap_or(true)
}

/// Candidates from Level 1, plus the set that already holds the KSM flag.
///
/// Already-flagged processes are returned rather than dropped: the
/// executable-VMA guard has to re-run on them, because new `r-xp` mappings
/// appear after the flag was set and are otherwise never withdrawn.
struct ScanTargets {
    /// Processes that passed L1/L2/L2.5 and are eligible to be marked.
    to_mark: Vec<Candidate>,
    /// Processes that already hold `merge_any` and need the guard re-applied.
    already_flagged: Vec<Candidate>,
}

fn collect_scan_targets<StatusFn, KsmFn>(
    config: &ScannerConfig,
    pids: Vec<u32>,
    stats: &mut ScannerStats,
    mut read_status: StatusFn,
    mut read_ksm_stat: KsmFn,
) -> ScanTargets
where
    StatusFn: FnMut(u32) -> Option<ProcessStatus>,
    KsmFn: FnMut(u32) -> Option<KsmProcStat>,
{
    let mut l1_candidates: Vec<Candidate> = Vec::new();

    for pid in pids {
        let status = match read_status(pid) {
            Some(s) => s,
            None => continue,
        };

        if let Some(candidate) = l1_candidate_from_status(status, config) {
            l1_candidates.push(candidate);
        }
    }

    stats.processes_filtered_l1 += l1_candidates.len() as u64;

    if l1_candidates.is_empty() {
        debug!("No processes passed Level 1 RSS filter");
        return ScanTargets {
            to_mark: Vec::new(),
            already_flagged: Vec::new(),
        };
    }

    let mut l25_candidates: Vec<Candidate> = Vec::new();
    let mut already_flagged: Vec<Candidate> = Vec::new();
    let mut l2_passed_count = 0u64;

    for candidate in l1_candidates {
        let ksm_stat = read_ksm_stat(candidate.pid);
        if !passes_l2_already_merged_filter(ksm_stat.as_ref()) {
            // Already mergeable: not a marking target, but its executable
            // mappings still need the guard re-applied every cycle.
            already_flagged.push(candidate);
            continue;
        }
        l2_passed_count += 1;

        if !passes_l25_profit_filter(ksm_stat.as_ref()) {
            stats.processes_filtered_l25_profit += 1;
            debug!(
                pid = candidate.pid,
                profit = ksm_stat.map(|s| s.process_profit).unwrap_or_default(),
                "Skipped: KSM reports negative process profit"
            );
            continue;
        }
        l25_candidates.push(candidate);
    }

    stats.processes_filtered_l2 += l2_passed_count;

    l25_candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.anon_rss_mb));
    l25_candidates.truncate(config.max_candidates_per_cycle);

    if l25_candidates.is_empty() {
        debug!("No Level 3 targets after eligibility filters");
    }

    // The guard pass is a safety check, not a tuning decision, so it takes the
    // same budget as the marking pass: bounded, cheapest-vs-complexity, and it
    // never expands into a full process-table ptrace burst.
    already_flagged.sort_by_key(|candidate| std::cmp::Reverse(candidate.anon_rss_mb));
    already_flagged.truncate(config.max_candidates_per_cycle);

    // Process-wide eligibility needs no address ranges, so the merge population
    // is never derived from `/proc/PID/maps` — that is what makes this
    // dramatically cheaper than the per-region `madvise` approach it replaces.
    // Maps is still read once per marked PID, but only to withdraw executable
    // VMAs (see `madvise::unmerge_executable_vmas`).
    ScanTargets {
        to_mark: l25_candidates,
        already_flagged,
    }
}

/// Outcome of one executable-VMA re-protection pass.
#[derive(Debug, Default, PartialEq, Eq)]
struct ReprotectTotals {
    /// Processes the pass actually ran on (exit-losing targets excluded).
    processes: usize,
    /// Executable VMAs withdrawn across those processes.
    withdrawn: usize,
    /// Executable VMAs that could not be withdrawn. Non-zero means the target
    /// stays mergeable through its code, so the guard is not protecting it.
    failed: usize,
    /// Processes deferred by the per-PID rate limit rather than protected.
    rate_limited: usize,
}

/// Per-PID bookkeeping for the executable-VMA re-protection pass.
///
/// The pass is a safety guard, not a tuning decision, so it must not run more
/// often than the scan interval on any single process: a rate-limited PID keeps
/// the ptrace burst bounded even if cycles start running back to back (manual
/// restarts, a shortened interval, a cycle that is forced early).
#[derive(Debug, Default)]
struct ReprotectLedger {
    /// PID → instant of the last completed re-protection pass on that PID.
    last_run: HashMap<u32, Instant>,
}

impl ReprotectLedger {
    fn last_run(&self, pid: u32) -> Option<Instant> {
        self.last_run.get(&pid).copied()
    }

    fn record(&mut self, pid: u32, at: Instant) {
        self.last_run.insert(pid, at);
    }
}

/// The process scanner.
pub struct Scanner {
    config: ScannerConfig,
    dry_run: bool,
    stats: ScannerStats,
    stabilization_secs: u64,
    /// This daemon's PID. Never a re-protection target: injecting `madvise`
    /// into the process that owns the sysfs writes serves no purpose, and a
    /// renamed logger into itself is a self-inflicted ptrace storm.
    daemon_pid: u32,
    reprotect_ledger: ReprotectLedger,
}

impl Scanner {
    pub fn new(config: ScannerConfig, dry_run: bool, stabilization_secs: u64) -> Self {
        Self {
            config,
            dry_run,
            stats: ScannerStats::default(),
            stabilization_secs,
            daemon_pid: std::process::id(),
            reprotect_ledger: ReprotectLedger::default(),
        }
    }

    /// Run the scanner loop until shutdown is signaled.
    pub async fn run(
        mut self,
        state: SharedGovernorState,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let base_interval = Duration::from_secs(self.config.interval_secs);
        let mut interval = time::interval(base_interval);

        info!(
            interval_secs = self.config.interval_secs,
            min_anon_rss_mb = self.config.min_anon_rss_mb,
            max_candidates = self.config.max_candidates_per_cycle,
            stabilization_secs = self.stabilization_secs,
            "Process scanner started (KSM hint generator mode)"
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.scan_cycle(&state).await;
                    self.stats.scan_cycles += 1;
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Scanner received shutdown signal");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Execute one scan cycle with multi-level filtering.
    async fn scan_cycle(&mut self, state: &SharedGovernorState) {
        // Check scanner stabilization window. This intentionally does not use
        // the governor timestamp; a recent KSM profile write must not starve
        // process discovery/madvise.
        let stabilization = Duration::from_secs(self.stabilization_secs);
        {
            let s = state.read().await;
            if s.last_scanner_action.elapsed() < stabilization {
                debug!("Scanner deferred (scanner stabilization window active)");
                self.stats.skipped_stabilization += 1;
                return;
            }
        }

        let processes_marked_before = self.stats.processes_marked;

        // === Level 1: Cheap /proc/PID/status filter ===
        // Only read RssAnon — no maps parsing, no pagemap.
        let pids = match procfs::list_pids() {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "Failed to list PIDs");
                return;
            }
        };

        let targets = collect_scan_targets(
            &self.config,
            pids,
            &mut self.stats,
            |pid| procfs::read_process_status(pid).ok(),
            |pid| procfs::read_ksm_stat(pid).ok(),
        );
        let candidates = targets.to_mark;

        if candidates.is_empty() && targets.already_flagged.is_empty() {
            return;
        }

        // Enable process-wide KSM eligibility — one prctl injection per PID.
        let mut injected = Vec::with_capacity(candidates.len());
        for candidate in &candidates {
            let result = madvise::enable_merge_any(candidate.pid, self.dry_run);
            self.stats.processes_marked += result.processes_marked as u64;
            self.stats.exec_vmas_protected += result.exec_vmas_protected as u64;
            self.stats.exec_vmas_unprotected += result.exec_vmas_failed as u64;

            if let Some(error) = result.error {
                // A target can exit, or be un-injectable (kernel threads, and
                // processes staring a hardened sandbox). Both are expected, so
                // this is a per-PID debug line rather than an error level.
                warn!(
                    pid = result.pid,
                    name = %candidate.name,
                    error = %error,
                    "Could not enable process-wide KSM eligibility"
                );
                self.stats.injection_failures += 1;
            } else {
                // The flag is set, so the process is eligible; the question is
                // whether its code is protected. `prctl` succeeding does not
                // imply the withdrawals did — a ptrace attach can be refused
                // (EPERM) for the very same target, leaving it mergeable
                // through its executable mappings. That is the state that
                // faulted Chromium, so it must not be silent.
                if result.exec_vmas_failed > 0 {
                    warn!(
                        pid = result.pid,
                        name = %candidate.name,
                        marked = result.processes_marked,
                        protected = result.exec_vmas_protected,
                        unprotected = result.exec_vmas_failed,
                        "Marked process is NOT fully protected: executable VMAs \
                         remain mergeable"
                    );
                }
                injected.push(candidate.pid);
            }
        }

        // Re-apply the executable-VMA guard to processes that were flagged on
        // an earlier cycle. `PR_SET_MEMORY_MERGE` is sticky and inherited, so a
        // browser keeps accumulating `r-xp` mappings (JIT, forked renderers)
        // after it was marked; without this pass those mappings stay mergeable
        // for the daemon's whole lifetime, which is exactly the SIGILL this
        // guard exists to prevent. The withdrawal is per-VMA and idempotent.
        let reprotected =
            self.reprotect_exec_vmas(&targets.already_flagged, madvise::unmerge_executable_vmas);
        self.stats.exec_vmas_reprotected += reprotected.withdrawn as u64;
        // The re-protection pass acts on processes that already hold the flag
        // from an earlier cycle, so a failure here is not a missed opportunity
        // — it is an already-mergeable target left mergeable. Count it, and
        // surface the total in the cycle line so it cannot be read as health.
        self.stats.exec_vmas_unprotected += reprotected.failed as u64;
        if reprotected.rate_limited > 0 {
            debug!(
                rate_limited = reprotected.rate_limited,
                "Executable-VMA re-protection deferred by per-PID rate limit"
            );
        }

        // Opportunistic MADV_COLLAPSE: if KSM has been unmerging pages
        // (high pages_volatile), try to re-promote large regions to THPs
        // for TLB efficiency. process_madvise supports COLLAPSE cross-process,
        // so it needs the region list this path used to be able to rely on.
        if let Ok(ksm_stats) = tuned_common::ksm::KsmController::new("/sys/kernel/mm/ksm") {
            if let Ok(stats) = ksm_stats.read_stats() {
                if stats.pages_volatile > 1000 {
                    for pid in &injected {
                        if !self.dry_run {
                            if let Ok(maps) = procfs::read_process_maps(*pid) {
                                let collapsed = madvise::collapse_regions(*pid, &maps);
                                self.stats.thp_collapsed += collapsed as u64;
                            }
                        }
                    }
                }
            }
        }

        // Update scanner stabilization timestamp if this cycle actually did
        // something. `processes_marked` is cumulative, so compare against the
        // start-of-cycle value instead of checking it for nonzero.
        if self.stats.processes_marked > processes_marked_before {
            let mut s = state.write().await;
            s.last_scanner_action = Instant::now();
            s.last_global_action = Instant::now();
        }

        info!(
            scan_cycle = self.stats.scan_cycles,
            l1_passed = self.stats.processes_filtered_l1,
            l2_passed = self.stats.processes_filtered_l2,
            l25_profit_filtered = self.stats.processes_filtered_l25_profit,
            targeted = candidates.len(),
            processes_marked = self.stats.processes_marked,
            exec_vmas_protected = self.stats.exec_vmas_protected,
            exec_vmas_unprotected = self.stats.exec_vmas_unprotected,
            exec_vmas_reprotected = self.stats.exec_vmas_reprotected,
            reprotect_processes = reprotected.processes,
            reprotect_rate_limited = reprotected.rate_limited,
            thp_collapsed = self.stats.thp_collapsed,
            skipped_stab = self.stats.skipped_stabilization,
            "Scanner cycle complete"
        );
    }

    /// Re-withdraw executable VMAs on processes that already hold the flag.
    ///
    /// `unmerge` is injected so tests can drive the withdrawal deterministically;
    /// the live path passes [`madvise::unmerge_executable_vmas`]. Each target is
    /// rate-limited to one pass per `interval_secs` window, and the pass skips
    /// this daemon's own PID. A target that exited since collection is skipped,
    /// not fatal to the cycle — and because it never consumed its rate-limit
    /// slot, it stays eligible for the next cycle.
    fn reprotect_exec_vmas<WithdrawFn>(
        &mut self,
        targets: &[Candidate],
        mut unmerge: WithdrawFn,
    ) -> ReprotectTotals
    where
        WithdrawFn: FnMut(u32, bool) -> (usize, usize),
    {
        let interval = Duration::from_secs(self.config.interval_secs);
        let now = Instant::now();
        let mut totals = ReprotectTotals::default();

        for candidate in targets {
            // The daemon's own pages are its own business and the guard exists
            // for targets it does not own code-unaware of.
            if candidate.pid == self.daemon_pid {
                debug!(
                    pid = candidate.pid,
                    name = %candidate.name,
                    "Skipped executable-VMA re-protection of this daemon"
                );
                continue;
            }

            // The budget bounds the number of ptrace injections this pass can
            // issue; a rate-limited or already-scanned target does not consume
            // one, so a full process table never turns into a burst.
            if totals.processes >= self.config.max_candidates_per_cycle {
                break;
            }

            if let Some(last) = self.reprotect_ledger.last_run(candidate.pid) {
                if now.duration_since(last) < interval {
                    debug!(
                        pid = candidate.pid,
                        name = %candidate.name,
                        remaining_ms = interval
                            .saturating_sub(now.duration_since(last))
                            .as_millis(),
                        "Deferred executable-VMA re-protection (rate limited)"
                    );
                    totals.rate_limited += 1;
                    continue;
                }
            }

            // A target that exited between listing and injection has no maps to
            // read, so the withdrawal reports zero rather than an error: the
            // cycle continues with the remaining targets.
            let (withdrawn, failed) = unmerge(candidate.pid, self.dry_run);

            if withdrawn + failed == 0 {
                debug!(
                    pid = candidate.pid,
                    name = %candidate.name,
                    "No executable mappings found to re-protect"
                );
                continue;
            }

            self.reprotect_ledger.record(candidate.pid, now);
            totals.processes += 1;
            totals.withdrawn += withdrawn;
            totals.failed += failed;
            if failed > 0 {
                // The flag is already set on this process from an earlier
                // cycle, so a failed withdrawal leaves it mergeable through its
                // code. Warn rather than debug: this is the crash shape.
                warn!(
                    pid = candidate.pid,
                    name = %candidate.name,
                    withdrawn, failed,
                    "Already-flagged process is NOT fully protected: executable \
                     VMAs remain mergeable"
                );
            }
            debug!(
                pid = candidate.pid,
                name = %candidate.name,
                withdrawn,
                failed,
                "Re-protected executable VMAs on an already-flagged process"
            );
        }

        totals
    }

    /// Get current scanner statistics.
    #[allow(dead_code)]
    pub fn stats(&self) -> &ScannerStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tuned_common::config::ScannerConfig;
    use tuned_common::GovernorState;

    // ── Integration: scanner not blocked by governor actions ──────────

    #[tokio::test]
    async fn scanner_stabilization_is_not_blocked_by_governor_action() {
        let mut scanner = Scanner::new(
            ScannerConfig {
                min_anon_rss_mb: u64::MAX,
                ..ScannerConfig::default()
            },
            true,
            30,
        );
        let state = Arc::new(RwLock::new(GovernorState::default()));

        {
            let mut s = state.write().await;
            s.last_governor_action = Instant::now();
            s.last_global_action = Instant::now();
            s.last_scanner_action = Instant::now() - Duration::from_secs(31);
        }

        scanner.scan_cycle(&state).await;

        assert_eq!(
            scanner.stats.skipped_stabilization, 0,
            "a fresh governor action must not defer the scanner"
        );
    }

    #[tokio::test]
    async fn scanner_defer_when_scanner_stabilization_window_is_active() {
        let mut scanner = Scanner::new(ScannerConfig::default(), true, 30);
        let state = Arc::new(RwLock::new(GovernorState::default()));

        {
            let mut s = state.write().await;
            s.last_scanner_action = Instant::now();
        }

        scanner.scan_cycle(&state).await;

        assert_eq!(scanner.stats.skipped_stabilization, 1);
        assert_eq!(scanner.stats.processes_filtered_l1, 0);
    }

    #[tokio::test]
    async fn scanner_run_exits_on_shutdown_signal() {
        let scanner = Scanner::new(
            ScannerConfig {
                interval_secs: 60,
                min_anon_rss_mb: u64::MAX,
                ..ScannerConfig::default()
            },
            true,
            0,
        );
        let state = Arc::new(RwLock::new(GovernorState::default()));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = tokio::spawn(scanner.run(state, shutdown_rx));
        shutdown_tx.send(true).unwrap();

        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    // ── Unit tests: constructor and defaults ──────────────────────────

    #[test]
    fn test_scanner_new_initial_state() {
        let scanner = Scanner::new(ScannerConfig::default(), false, 30);
        assert_eq!(scanner.config.interval_secs, 30);
        assert!(!scanner.dry_run);
        assert_eq!(scanner.stabilization_secs, 30);
        assert_eq!(scanner.stats.scan_cycles, 0);
        assert_eq!(scanner.stats.skipped_stabilization, 0);
    }

    #[test]
    fn test_scanner_stats_default() {
        let stats = ScannerStats::default();
        assert_eq!(stats.scan_cycles, 0);
        assert_eq!(stats.processes_filtered_l1, 0);
        assert_eq!(stats.processes_filtered_l2, 0);
        assert_eq!(stats.processes_filtered_l25_profit, 0);
        assert_eq!(stats.processes_marked, 0);
        assert_eq!(stats.exec_vmas_protected, 0);
        assert_eq!(stats.exec_vmas_reprotected, 0);
        assert_eq!(stats.injection_failures, 0);
        assert_eq!(stats.skipped_stabilization, 0);
        assert_eq!(stats.thp_collapsed, 0);
    }

    #[test]
    fn test_scanner_new_respects_dry_run() {
        let scanner = Scanner::new(ScannerConfig::default(), true, 60);
        assert!(scanner.dry_run);
        assert_eq!(scanner.stabilization_secs, 60);
    }

    #[test]
    fn test_scanner_stats_getter() {
        let scanner = Scanner::new(ScannerConfig::default(), false, 30);
        let stats = scanner.stats();
        assert_eq!(stats.scan_cycles, 0);
    }

    #[test]
    fn test_scanner_new_with_nondefault_config() {
        let config = ScannerConfig {
            interval_secs: 120,
            min_anon_rss_mb: 200,
            max_candidates_per_cycle: 10,
            ..Default::default()
        };

        let scanner = Scanner::new(config, false, 30);
        assert_eq!(scanner.config.interval_secs, 120);
        assert_eq!(scanner.config.min_anon_rss_mb, 200);
        assert_eq!(scanner.config.max_candidates_per_cycle, 10);
    }

    #[test]
    fn test_l1_candidate_filters_kernel_small_and_blocklisted_processes() {
        let config = ScannerConfig {
            min_anon_rss_mb: 100,
            blocklist: vec!["tuned".into()],
            ..ScannerConfig::default()
        };

        assert!(l1_candidate_from_status(
            ProcessStatus {
                pid: 2,
                name: "kthreadd".into(),
                anon_rss_kb: 1024 * 1024,
                ..Default::default()
            },
            &config
        )
        .is_none());

        assert!(l1_candidate_from_status(
            ProcessStatus {
                pid: 100,
                name: "tiny".into(),
                anon_rss_kb: 99 * 1024,
                ..Default::default()
            },
            &config
        )
        .is_none());

        assert!(l1_candidate_from_status(
            ProcessStatus {
                pid: 101,
                name: "tuned-daemon".into(),
                anon_rss_kb: 500 * 1024,
                ..Default::default()
            },
            &config
        )
        .is_none());
    }

    #[test]
    fn test_l1_candidate_keeps_large_unblocked_process() {
        let config = ScannerConfig {
            min_anon_rss_mb: 100,
            blocklist: vec!["blocked".into()],
            ..ScannerConfig::default()
        };

        let candidate = l1_candidate_from_status(
            ProcessStatus {
                pid: 200,
                name: "browser".into(),
                anon_rss_kb: 256 * 1024,
                ..Default::default()
            },
            &config,
        )
        .unwrap();

        assert_eq!(candidate.pid, 200);
        assert_eq!(candidate.name, "browser");
        assert_eq!(candidate.anon_rss_mb, 256);
    }

    #[test]
    fn test_l2_filter_skips_already_mergeable_processes() {
        assert!(passes_l2_already_merged_filter(None));
        assert!(passes_l2_already_merged_filter(Some(&KsmProcStat {
            merge_any: false,
            ..Default::default()
        })));
        assert!(!passes_l2_already_merged_filter(Some(&KsmProcStat {
            merge_any: true,
            ..Default::default()
        })));
    }

    #[test]
    fn test_l25_filter_skips_negative_profit_only_when_known() {
        assert!(passes_l25_profit_filter(None));
        assert!(passes_l25_profit_filter(Some(&KsmProcStat {
            process_profit: 0,
            ..Default::default()
        })));
        assert!(passes_l25_profit_filter(Some(&KsmProcStat {
            process_profit: 42,
            ..Default::default()
        })));
        assert!(!passes_l25_profit_filter(Some(&KsmProcStat {
            process_profit: -1,
            ..Default::default()
        })));
    }

    #[test]
    fn test_collect_scan_targets_returns_empty_when_l1_has_no_candidates() {
        let config = ScannerConfig {
            min_anon_rss_mb: 128,
            ..ScannerConfig::default()
        };
        let mut stats = ScannerStats::default();

        let candidates = collect_scan_targets(
            &config,
            vec![1, 2, 10],
            &mut stats,
            |pid| {
                Some(ProcessStatus {
                    pid,
                    name: "tiny".into(),
                    anon_rss_kb: 64 * 1024,
                    ..Default::default()
                })
            },
            |_| None,
        );

        assert!(candidates.to_mark.is_empty());
        assert!(candidates.already_flagged.is_empty());
        assert_eq!(stats.processes_filtered_l1, 0);
        assert_eq!(stats.processes_filtered_l2, 0);
    }

    #[test]
    fn test_collect_scan_targets_filters_already_merged_processes() {
        let config = ScannerConfig {
            min_anon_rss_mb: 128,
            ..ScannerConfig::default()
        };
        let mut stats = ScannerStats::default();

        let candidates = collect_scan_targets(
            &config,
            vec![10, 11],
            &mut stats,
            |pid| {
                Some(ProcessStatus {
                    pid,
                    name: format!("proc-{pid}"),
                    anon_rss_kb: 256 * 1024,
                    ..Default::default()
                })
            },
            |_| {
                Some(KsmProcStat {
                    merge_any: true,
                    ..Default::default()
                })
            },
        );

        assert!(candidates.to_mark.is_empty());
        assert_eq!(stats.processes_filtered_l1, 2);
        assert_eq!(stats.processes_filtered_l2, 0);
    }

    /// Already-flagged processes must not be dropped: they are exactly the set
    /// whose executable VMAs need the guard re-applied.
    #[test]
    fn test_collect_scan_targets_returns_already_flagged_processes() {
        let config = ScannerConfig {
            min_anon_rss_mb: 128,
            ..ScannerConfig::default()
        };
        let mut stats = ScannerStats::default();

        let candidates = collect_scan_targets(
            &config,
            vec![10, 11],
            &mut stats,
            |pid| {
                Some(ProcessStatus {
                    pid,
                    name: format!("proc-{pid}"),
                    anon_rss_kb: 256 * 1024,
                    ..Default::default()
                })
            },
            |_| {
                Some(KsmProcStat {
                    merge_any: true,
                    ..Default::default()
                })
            },
        );

        assert!(candidates.to_mark.is_empty());
        assert_eq!(candidates.already_flagged.len(), 2);
        // Both must be offered for re-protection regardless of ordering, since
        // equal RSS makes the sort order an implementation detail.
        let mut pids: Vec<u32> = candidates.already_flagged.iter().map(|c| c.pid).collect();
        pids.sort();
        assert_eq!(pids, vec![10, 11]);
    }

    /// The guard pass is bounded by the same budget as the marking pass, so it
    /// can never grow into a full process-table ptrace burst.
    #[test]
    fn test_collect_scan_targets_bounds_already_flagged_set() {
        let config = ScannerConfig {
            min_anon_rss_mb: 128,
            max_candidates_per_cycle: 2,
            ..ScannerConfig::default()
        };
        let mut stats = ScannerStats::default();

        let candidates = collect_scan_targets(
            &config,
            vec![10, 11, 12, 13],
            &mut stats,
            |pid| {
                let anon_mb = match pid {
                    10 => 64,
                    11 => 512,
                    12 => 256,
                    13 => 128,
                    _ => 0,
                };
                Some(ProcessStatus {
                    pid,
                    name: format!("proc-{pid}"),
                    anon_rss_kb: anon_mb * 1024,
                    ..Default::default()
                })
            },
            |_| {
                Some(KsmProcStat {
                    merge_any: true,
                    ..Default::default()
                })
            },
        );

        assert_eq!(candidates.already_flagged.len(), 2);
        // Highest anonymous RSS first — the guard should cover the largest
        // mappings before the smallest.
        assert_eq!(candidates.already_flagged[0].pid, 11);
        assert_eq!(candidates.already_flagged[1].pid, 12);
    }

    #[test]
    fn test_collect_scan_targets_filters_negative_profit() {
        let config = ScannerConfig {
            min_anon_rss_mb: 128,
            max_candidates_per_cycle: 3,
            ..ScannerConfig::default()
        };
        let mut stats = ScannerStats::default();

        let candidates = collect_scan_targets(
            &config,
            vec![10, 11, 12],
            &mut stats,
            |pid| {
                Some(ProcessStatus {
                    pid,
                    name: format!("proc-{pid}"),
                    anon_rss_kb: 256 * 1024,
                    ..Default::default()
                })
            },
            |pid| match pid {
                10 => Some(KsmProcStat {
                    process_profit: -1,
                    ..Default::default()
                }),
                _ => None,
            },
        );

        assert_eq!(candidates.to_mark.len(), 2);
        // PID 10 was dropped for negative profit, leaving 11 and 12. Both have
        // equal anonymous RSS, so the (stable) sort keeps discovery order.
        assert_eq!(candidates.to_mark[0].pid, 11);
        assert_eq!(candidates.to_mark[1].pid, 12);
        assert_eq!(stats.processes_filtered_l1, 3);
        assert_eq!(stats.processes_filtered_l2, 3);
        assert_eq!(stats.processes_filtered_l25_profit, 1);
    }

    #[test]
    fn test_collect_scan_targets_sorts_by_rss_and_truncates_top_candidates() {
        let config = ScannerConfig {
            min_anon_rss_mb: 1,
            max_candidates_per_cycle: 2,
            ..ScannerConfig::default()
        };
        let mut stats = ScannerStats::default();

        let candidates = collect_scan_targets(
            &config,
            vec![10, 11, 12],
            &mut stats,
            |pid| {
                let anon_mb = match pid {
                    10 => 64,
                    11 => 512,
                    12 => 256,
                    _ => 0,
                };
                Some(ProcessStatus {
                    pid,
                    name: format!("proc-{pid}"),
                    anon_rss_kb: anon_mb * 1024,
                    ..Default::default()
                })
            },
            |_| None,
        );

        // Top-2 by anonymous RSS: 11 (512 MiB) then 12 (256 MiB).
        assert_eq!(candidates.to_mark.len(), 2);
        assert_eq!(candidates.to_mark[0].pid, 11);
        assert_eq!(candidates.to_mark[1].pid, 12);
    }

    #[test]
    fn test_pipeline_helpers_model_l1_l2_l25_l3_flow() {
        let config = ScannerConfig {
            min_anon_rss_mb: 128,
            max_candidates_per_cycle: 1,
            blocklist: vec!["blocked".into()],
            ..ScannerConfig::default()
        };

        let statuses = vec![
            ProcessStatus {
                pid: 10,
                name: "small".into(),
                anon_rss_kb: 64 * 1024,
                ..Default::default()
            },
            ProcessStatus {
                pid: 11,
                name: "merged".into(),
                anon_rss_kb: 256 * 1024,
                ..Default::default()
            },
            ProcessStatus {
                pid: 12,
                name: "negative".into(),
                anon_rss_kb: 512 * 1024,
                ..Default::default()
            },
            ProcessStatus {
                pid: 13,
                name: "winner".into(),
                anon_rss_kb: 1024 * 1024,
                ..Default::default()
            },
        ];

        let l1: Vec<Candidate> = statuses
            .into_iter()
            .filter_map(|status| l1_candidate_from_status(status, &config))
            .collect();
        assert_eq!(
            l1.iter().map(|c| c.pid).collect::<Vec<_>>(),
            vec![11, 12, 13]
        );

        let l2: Vec<Candidate> = l1
            .into_iter()
            .filter(|candidate| {
                let stat = match candidate.pid {
                    11 => Some(KsmProcStat {
                        merge_any: true,
                        ..Default::default()
                    }),
                    _ => None,
                };
                passes_l2_already_merged_filter(stat.as_ref())
            })
            .collect();
        assert_eq!(l2.iter().map(|c| c.pid).collect::<Vec<_>>(), vec![12, 13]);

        let mut l25: Vec<Candidate> = l2
            .into_iter()
            .filter(|candidate| {
                let stat = match candidate.pid {
                    12 => Some(KsmProcStat {
                        process_profit: -100,
                        ..Default::default()
                    }),
                    _ => None,
                };
                passes_l25_profit_filter(stat.as_ref())
            })
            .collect();
        l25.sort_by_key(|c| std::cmp::Reverse(c.anon_rss_mb));
        l25.truncate(config.max_candidates_per_cycle);

        assert_eq!(l25.len(), 1);
        assert_eq!(l25[0].pid, 13);

        // The candidate carries only a name, a PID and its anonymous RSS — no
        // address ranges are needed to enable process-wide KSM eligibility.
        assert_eq!(l25[0].name, "winner");
        assert_eq!(l25[0].anon_rss_mb, 1024);
    }

    // ── Unit tests: executable-VMA re-protection pass ─────────────────

    fn reprotect_candidate(pid: u32, name: &str, anon_rss_mb: u64) -> Candidate {
        Candidate {
            pid,
            name: name.to_string(),
            anon_rss_mb,
        }
    }

    /// A withdrawal closure that reports `(withdrawn, found)` per PID and
    /// records every PID it was called on.
    fn recording_unmerge(
        withdrawn: usize,
        failed: usize,
        calls: std::rc::Rc<std::cell::RefCell<Vec<u32>>>,
    ) -> impl FnMut(u32, bool) -> (usize, usize) {
        move |pid, _dry_run| {
            calls.borrow_mut().push(pid);
            (withdrawn, failed)
        }
    }

    #[test]
    fn test_reprotect_exec_vmas_counts_failures_instead_of_swallowing_them() {
        // The real bug this guards against: `unmerge_executable_vmas` used to
        // report `(0, found)` when the prctl succeeded but every ptrace attach
        // was refused, so a *completely failed* guard looked like a healthy
        // one. A live run showed exactly that — `withdrawn=0 exec_vmas=9`, all
        // nine returns EPERM — leaving a process mergeable through its code.
        let mut scanner = Scanner::new(
            ScannerConfig {
                interval_secs: 30,
                max_candidates_per_cycle: 4,
                ..ScannerConfig::default()
            },
            false,
            0,
        );
        scanner.daemon_pid = u32::MAX;

        let targets = vec![reprotect_candidate(4242, "app", 256)];

        // Every injection refused. Withdrawn is zero, so the target is left
        // unprotected, and the pass must say so rather than reporting nothing.
        let totals = scanner.reprotect_exec_vmas(
            &targets,
            recording_unmerge(0, 9, std::rc::Rc::new(std::cell::RefCell::new(Vec::new()))),
        );

        assert_eq!(totals.withdrawn, 0, "nothing was withdrawn");
        assert_eq!(
            totals.failed, 9,
            "nine refused withdrawals must be reported as failures"
        );
        assert_eq!(
            totals.processes, 1,
            "a fully-failed target is still a process the pass ran on"
        );

        // And the counter `scan_cycle` maintains must carry it.
        scanner.stats.exec_vmas_unprotected += totals.failed as u64;
        assert_eq!(scanner.stats.exec_vmas_unprotected, 9);
        assert_eq!(
            scanner.stats.exec_vmas_reprotected, 0,
            "a failed guard must not increment the success counter"
        );
    }

    #[test]
    fn test_reprotect_exec_vmas_selects_already_flagged_processes() {
        let mut scanner = Scanner::new(
            ScannerConfig {
                interval_secs: 30,
                max_candidates_per_cycle: 8,
                ..ScannerConfig::default()
            },
            false,
            0,
        );

        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let targets = vec![
            reprotect_candidate(4242, "jit-app", 512),
            reprotect_candidate(4243, "static-app", 256),
        ];

        let totals = scanner.reprotect_exec_vmas(
            &targets,
            recording_unmerge(3, 0, std::rc::Rc::clone(&calls)),
        );

        assert_eq!(
            totals,
            ReprotectTotals {
                processes: 2,
                withdrawn: 6,
                failed: 0,
                rate_limited: 0,
            },
            "every already-flagged process must be offered the guard again"
        );
        assert_eq!(scanner.stats.exec_vmas_reprotected, 0);
        assert_eq!(*calls.borrow(), vec![4242, 4243]);
    }

    #[test]
    fn test_reprotect_exec_vmas_accumulates_stat_counter() {
        let mut scanner = Scanner::new(
            ScannerConfig {
                interval_secs: 30,
                max_candidates_per_cycle: 4,
                ..ScannerConfig::default()
            },
            false,
            0,
        );

        let targets = vec![reprotect_candidate(5000, "app", 100)];

        // Drain the per-PID rate limit between the two passes, as successive
        // cycles with a fresh interval would.
        let first = scanner.reprotect_exec_vmas(&targets, |_pid, _dry| (2, 5));
        scanner.config.interval_secs = 0;
        let second = scanner.reprotect_exec_vmas(&targets, |_pid, _dry| (1, 4));
        scanner.config.interval_secs = 30;

        assert_eq!(first.withdrawn, 2);
        assert_eq!(second.withdrawn, 1);
        // The pass itself is side-effect free apart from the ledger; the
        // cycle-level accumulation is what feeds the metric.
        assert_eq!(scanner.stats.exec_vmas_reprotected, 0);
        scanner.stats.exec_vmas_reprotected += first.withdrawn as u64;
        scanner.stats.exec_vmas_reprotected += second.withdrawn as u64;
        assert_eq!(scanner.stats.exec_vmas_reprotected, 3);
    }

    #[test]
    fn test_reprotect_exec_vmas_survives_target_exit() {
        let mut scanner = Scanner::new(
            ScannerConfig {
                interval_secs: 30,
                max_candidates_per_cycle: 8,
                ..ScannerConfig::default()
            },
            false,
            0,
        );

        let targets = vec![
            // PID 4241 is dead: no maps to read, nothing withdrawn.
            reprotect_candidate(4241, "gone", 512),
            reprotect_candidate(4242, "alive", 256),
        ];

        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let totals = scanner.reprotect_exec_vmas(&targets, {
            let calls = std::rc::Rc::clone(&calls);
            move |pid, _dry_run| {
                calls.borrow_mut().push(pid);
                // A dead PID reports "no executable mappings", the same shape
                // `unmerge_executable_vmas` returns for an unreadable maps.
                match pid {
                    4241 => (0, 0),
                    _ => (4, 0),
                }
            }
        });

        assert_eq!(
            totals,
            ReprotectTotals {
                processes: 1,
                withdrawn: 4,
                failed: 0,
                rate_limited: 0,
            },
            "a target exiting mid-pass must be skipped, not abort the cycle"
        );
        assert_eq!(
            *calls.borrow(),
            vec![4241, 4242],
            "the surviving process after the dead one must still be protected"
        );

        // The dead PID never consumed its slot, so it is retried on the next
        // cycle rather than being suppressed for a whole interval.
        let calls_after = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        scanner.reprotect_exec_vmas(
            &[reprotect_candidate(4241, "gone", 512)],
            recording_unmerge(1, 0, std::rc::Rc::clone(&calls_after)),
        );
        assert_eq!(*calls_after.borrow(), vec![4241]);
    }

    #[test]
    fn test_reprotect_exec_vmas_skips_daemon_pid() {
        let mut scanner = Scanner::new(
            ScannerConfig {
                interval_secs: 30,
                max_candidates_per_cycle: 8,
                ..ScannerConfig::default()
            },
            false,
            0,
        );

        let daemon_pid = scanner.daemon_pid;
        let targets = vec![
            reprotect_candidate(daemon_pid, "tuned-daemon", 512),
            reprotect_candidate(4242, "app", 256),
        ];

        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let totals = scanner.reprotect_exec_vmas(
            &targets,
            recording_unmerge(2, 0, std::rc::Rc::clone(&calls)),
        );

        assert!(!calls.borrow().contains(&daemon_pid));
        assert_eq!(totals.processes, 1);
        assert_eq!(totals.withdrawn, 2);
    }

    #[test]
    fn test_reprotect_exec_vmas_is_rate_limited_within_one_interval() {
        let mut scanner = Scanner::new(
            ScannerConfig {
                interval_secs: 3600,
                max_candidates_per_cycle: 8,
                ..ScannerConfig::default()
            },
            false,
            0,
        );

        let targets = vec![reprotect_candidate(4242, "app", 512)];

        let first = scanner.reprotect_exec_vmas(&targets, |_pid, _dry| (3, 3));
        assert_eq!(first.processes, 1);

        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let second = scanner.reprotect_exec_vmas(
            &targets,
            recording_unmerge(3, 0, std::rc::Rc::clone(&calls)),
        );

        assert!(calls.borrow().is_empty());
        assert_eq!(second.processes, 0);
        assert_eq!(second.withdrawn, 0);
        assert_eq!(second.rate_limited, 1);
    }

    #[test]
    fn test_reprotect_exec_vmas_respects_candidate_budget() {
        let mut scanner = Scanner::new(
            ScannerConfig {
                interval_secs: 0,
                max_candidates_per_cycle: 2,
                ..ScannerConfig::default()
            },
            false,
            0,
        );

        let targets = vec![
            reprotect_candidate(6001, "a", 512),
            reprotect_candidate(6002, "b", 256),
            reprotect_candidate(6003, "c", 128),
            reprotect_candidate(6004, "d", 64),
        ];

        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let totals = scanner.reprotect_exec_vmas(
            &targets,
            recording_unmerge(1, 0, std::rc::Rc::clone(&calls)),
        );

        assert_eq!(totals.processes, 2);
        assert_eq!(
            *calls.borrow(),
            vec![6001, 6002],
            "the guard pass must stay bounded by the same budget as marking"
        );
    }

    /// Live `madvise::unmerge_executable_vmas` already returns `(0, 0)` for an
    /// unreachable PID instead of panicking, and a fresh long-range PID does
    /// not exist on this machine — this drives the real function rather than a
    /// stub to pin that contract.
    #[test]
    fn test_reprotect_exec_vmas_absorbs_unreachable_pid_via_real_madvise() {
        let mut scanner = Scanner::new(
            ScannerConfig {
                interval_secs: 30,
                max_candidates_per_cycle: 4,
                ..ScannerConfig::default()
            },
            true,
            0,
        );

        let totals = scanner.reprotect_exec_vmas(
            &[reprotect_candidate(0x7FFF_FFFF, "gone", 512)],
            madvise::unmerge_executable_vmas,
        );

        assert_eq!(
            totals,
            ReprotectTotals::default(),
            "an unreachable PID must yield an empty pass, not an error"
        );
    }

    /// End-to-end: the pass, the live withdrawal function, and the cycle-level
    /// accumulation. The daemon-PID skip is lifted for this test only, so the
    /// test process itself can act as the already-flagged target.
    #[test]
    fn test_reprotect_exec_vmas_wires_real_madvise_into_the_stat_counter() {
        let mut scanner = Scanner::new(
            ScannerConfig {
                interval_secs: 30,
                max_candidates_per_cycle: 4,
                ..ScannerConfig::default()
            },
            true,
            0,
        );
        scanner.daemon_pid = u32::MAX;

        let own = std::process::id();
        let targets = vec![reprotect_candidate(own, "test-runner", 512)];

        let totals = scanner.reprotect_exec_vmas(&targets, madvise::unmerge_executable_vmas);
        assert!(totals.withdrawn > 0);
        assert_eq!(totals.processes, 1);
        assert_eq!(scanner.stats.exec_vmas_reprotected, 0);

        // Exactly what `scan_cycle` does with the pass result.
        scanner.stats.exec_vmas_reprotected += totals.withdrawn as u64;
        assert!(scanner.stats.exec_vmas_reprotected > 0);
    }

    // ── scan_cycle: the marking loop's accounting contract ──────────────

    /// The injection loop runs `enable_merge_any` once per candidate, so the
    /// two outcome counters must always partition the candidate set exactly:
    /// a candidate is either marked or failed, never both, never neither.
    ///
    /// `min_anon_rss_mb = 0` makes every readable status pass Level 1
    /// (`anon_rss_mb < 0` is false for a `u64`), so the candidate count is a
    /// property of the host rather than of a hand-fed fixture — and it is
    /// derived from the *public* counters, so a scanner that silently stopped
    /// injecting cannot make the arithmetic look right.
    ///
    /// `dry_run = true`: no ptrace attach happens at all, so nothing on this
    /// host is touched and no injection can fail.
    #[tokio::test]
    async fn test_scan_cycle_partitions_candidates_into_marked_and_failed() {
        let config = ScannerConfig {
            min_anon_rss_mb: 0,
            max_candidates_per_cycle: 64,
            blocklist: Vec::new(),
            ..ScannerConfig::default()
        };
        let mut scanner = Scanner::new(
            config.clone(),
            /* dry_run */ true,
            /* stabilization */ 0,
        );
        let state = Arc::new(RwLock::new(GovernorState::default()));
        {
            let mut s = state.write().await;
            s.last_scanner_action = Instant::now() - Duration::from_secs(120);
            s.last_global_action = Instant::now() - Duration::from_secs(120);
            s.last_governor_action = Instant::now() - Duration::from_secs(120);
        }
        let governor_action_before = state.read().await.last_governor_action;

        scanner.scan_cycle(&state).await;

        // `to_mark` after truncation. Neither `filtered_l2` nor
        // `filtered_l25_profit` is truncated, so their difference is the
        // pre-truncation candidate count and the budget clips it.
        let selected = (scanner.stats.processes_filtered_l2
            - scanner.stats.processes_filtered_l25_profit)
            .min(config.max_candidates_per_cycle as u64);

        assert!(
            selected >= 1,
            "a zero RSS floor must admit at least one process on any host \
             (l1={}, l2={}, l25={})",
            scanner.stats.processes_filtered_l1,
            scanner.stats.processes_filtered_l2,
            scanner.stats.processes_filtered_l25_profit
        );

        assert_eq!(
            scanner.stats.processes_marked + scanner.stats.injection_failures,
            selected,
            "every candidate must be accounted for as marked or failed"
        );
        assert_eq!(
            scanner.stats.injection_failures, 0,
            "a dry-run injection attaches nothing, so nothing can fail"
        );
        assert_eq!(
            scanner.stats.processes_marked, selected,
            "the dry run must report one mark per candidate"
        );

        // The cycle "actually did something", so both of its own timestamps
        // advance — while the governor's must not, because the scanner has no
        // business touching a tier it does not own.
        let s = state.read().await;
        assert!(
            s.last_scanner_action.elapsed() < Duration::from_secs(5),
            "a cycle that marked processes must refresh last_scanner_action"
        );
        assert!(
            s.last_global_action.elapsed() < Duration::from_secs(5),
            "a cycle that marked processes must refresh last_global_action"
        );
        assert_eq!(
            s.last_governor_action, governor_action_before,
            "the scanner must never touch the governor's timestamp"
        );
    }

    /// The other half of the timestamp contract: a cycle that found no
    /// candidates must not claim it acted. Leaving `stabilization_secs` at 0
    /// is deliberate — the cycle has to reach candidate selection and return
    /// from *there*, which is the only way this test can tell the difference
    /// between "deferred by the window" and "nothing to do".
    #[tokio::test]
    async fn test_scan_cycle_advances_no_timestamp_when_no_candidate_is_found() {
        let mut scanner = Scanner::new(
            ScannerConfig {
                min_anon_rss_mb: u64::MAX,
                ..ScannerConfig::default()
            },
            true,
            0,
        );
        let state = Arc::new(RwLock::new(GovernorState::default()));
        {
            let mut s = state.write().await;
            s.last_scanner_action = Instant::now() - Duration::from_secs(120);
            s.last_global_action = Instant::now() - Duration::from_secs(120);
        }
        let (scanner_before, global_before) = {
            let s = state.read().await;
            (s.last_scanner_action, s.last_global_action)
        };

        scanner.scan_cycle(&state).await;

        assert_eq!(
            scanner.stats.processes_filtered_l1, 0,
            "an impossible RSS floor must filter every process at Level 1"
        );
        let s = state.read().await;
        assert_eq!(
            s.last_scanner_action, scanner_before,
            "a cycle that did nothing must not refresh last_scanner_action"
        );
        assert_eq!(
            s.last_global_action, global_before,
            "a cycle that did nothing must not refresh last_global_action"
        );
    }

    // ── Fault injection: /proc boundary failures ────────────────────────
    //
    // Every test below drives a real failure at the kernel boundary the scanner
    // depends on: a `/proc` entry that disappears between listing and reading, a
    // process that legitimately cannot be injected, and a blocklist match that is
    // only ever a heuristic. The assertions are about the loop surviving with
    // coherent accounting — never about the fault being prevented. Stopping a
    // process from exiting is not something this daemon can do, so "survive and
    // stay truthful" is the contract.

    /// A child this test process owns. `Drop` reaps it, so every exit path —
    /// including a failing assertion — leaves no process behind.
    struct OwnedChild(std::process::Child);

    impl OwnedChild {
        fn spawn(argv: &[&str]) -> Self {
            let mut cmd = std::process::Command::new(argv[0]);
            for arg in &argv[1..] {
                cmd.arg(arg);
            }
            let child = cmd
                .spawn()
                .unwrap_or_else(|e| panic!("spawning {argv:?} must work: {e}"));
            Self(child)
        }
    }

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Yama `ptrace_scope`, or `u8::MAX` when the file is absent (kernels built
    /// without Yama, where any descendant is attachable anyway).
    fn ptrace_scope() -> u8 {
        std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(u8::MAX)
    }

    /// `/proc/PID/comm`, trimmed, or `None` when the process is already gone.
    fn comm_of(pid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// The parent PID of this process, read through the same `/proc/self/stat`
    /// layout the kernel documents (fields after the comm).
    /// Real UID of the running process, from `/proc/self/status`. `0` means
    /// root, which is the branch several fault tests must take because the
    /// kernel's Yama `ptrace_scope` restriction does not apply to root: an
    /// attach that is refused for an unprivileged user succeeds here.
    fn is_root() -> bool {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|uid| uid.parse::<u32>().ok())
            .map(|uid| uid == 0)
            .unwrap_or(false)
    }

    fn parent_pid() -> u32 {
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let rest = stat.rsplit_once(')').expect("/proc/self/stat has a comm").1;
        rest.split_whitespace()
            .nth(1)
            .expect("ppid is the second field after the comm")
            .parse()
            .expect("ppid parses")
    }

    /// Spin until the predicate holds for `pid`, or give up and return `false`.
    /// Used to reach a deterministic child state (comm renamed, process gone)
    /// instead of sleeping a fixed interval.
    fn wait_until<F: Fn() -> bool>(what: &str, ready: F) -> bool {
        for _ in 0..400 {
            if ready() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        eprintln!("condition never became true: {what}");
        false
    }

    /// Re-read `/proc/PID/stat` until the field named by `field_index` matches
    /// `want`, returning whether it did.
    fn wait_until_state(pid: u32, want: &str) -> bool {
        wait_until("process state", || {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|s| {
                    s.rsplit_once(')')
                        .map(|(_, rest)| rest.split_whitespace().next().unwrap_or("").to_string())
                })
                .as_deref()
                == Some(want)
        })
    }

    /// A freshly built cycle: zero RSS floor, no blocklist, dry run, and a
    /// stabilization window already expired.
    fn churn_ready_scanner() -> (Scanner, std::sync::Arc<tokio::sync::RwLock<GovernorState>>) {
        let config = ScannerConfig {
            min_anon_rss_mb: 0,
            max_candidates_per_cycle: usize::MAX,
            blocklist: Vec::new(),
            ..ScannerConfig::default()
        };
        let scanner = Scanner::new(config, /* dry_run */ true, 0);
        let state = std::sync::Arc::new(tokio::sync::RwLock::new(GovernorState::default()));
        (scanner, state)
    }

    /// `processes_filtered_l2 - processes_filtered_l25_profit`, clipped by the
    /// budget — the pre-truncation candidate count, which is what the marking
    /// loop's two outcome counters must partition.
    fn selected_candidates(scanner: &Scanner, max_candidates: usize) -> u64 {
        (scanner.stats.processes_filtered_l2 - scanner.stats.processes_filtered_l25_profit)
            .min(max_candidates as u64)
    }

    async fn prime_state(state: &std::sync::Arc<tokio::sync::RwLock<GovernorState>>) {
        let mut s = state.write().await;
        s.last_scanner_action = Instant::now() - Duration::from_secs(120);
        s.last_global_action = Instant::now() - Duration::from_secs(120);
        s.last_governor_action = Instant::now() - Duration::from_secs(120);
    }

    #[test]
    fn test_collect_scan_targets_skips_a_pid_whose_proc_entry_is_gone() {
        // Deterministic version of the list/read race: spawn a child, reap it
        // first, so `/proc/PID/status` is guaranteed unreadable before the
        // collector runs. Production closure `.ok()`s the read into `None`, so a
        // vanished PID must be skipped, not turned into an error or a panic.
        let mut dead_child = std::process::Command::new("/usr/bin/sleep")
            .arg("0")
            .spawn()
            .expect("spawning a sleep target must work");
        let dead_pid = dead_child.id();
        dead_child.wait().expect("reaping the sleep target");

        // A live sibling, so the result is not empty for the wrong reason: a
        // collector that dropped every PID would also produce an empty set.
        let live = OwnedChild::spawn(&["/usr/bin/sleep", "30"]);
        let live_pid = live.0.id();
        assert!(
            wait_until("live child status readable", || std::fs::metadata(format!(
                "/proc/{live_pid}/status"
            ))
            .is_ok()),
            "the live child must be observable"
        );

        let config = ScannerConfig {
            min_anon_rss_mb: 0,
            max_candidates_per_cycle: 16,
            blocklist: Vec::new(),
            ..ScannerConfig::default()
        };
        let mut stats = ScannerStats::default();

        let targets = collect_scan_targets(
            &config,
            vec![dead_pid, live_pid],
            &mut stats,
            |pid| procfs::read_process_status(pid).ok(),
            |pid| procfs::read_ksm_stat(pid).ok(),
        );

        let collected: Vec<u32> = targets.to_mark.iter().map(|c| c.pid).collect();
        assert!(
            !collected.contains(&dead_pid),
            "a reaped child must be skipped, not injected: {collected:?}"
        );
        assert!(
            collected.contains(&live_pid),
            "a vanished PID must not stop the surviving processes from being \
         collected: {collected:?}"
        );
        assert_eq!(
            stats.processes_filtered_l1, 1,
            "only the readable status may be counted at Level 1"
        );
    }

    #[tokio::test]
    async fn test_scan_cycle_partition_holds_while_a_child_is_dying() {
        // The accounting contract under real churn: a dying child can land in the
        // candidate set and then fail its injection, which is one of the two
        // allowed outcomes — the partition must still close.
        let (mut scanner, state) = churn_ready_scanner();
        let max_candidates = scanner.config.max_candidates_per_cycle;
        prime_state(&state).await;

        let dying = OwnedChild::spawn(&["/usr/bin/sleep", "0.3"]);
        let dying_pid = dying.0.id();
        assert!(
            wait_until("dying child status readable", || std::fs::metadata(
                format!("/proc/{dying_pid}/status")
            )
            .is_ok()),
            "the dying child must be observable"
        );

        scanner.scan_cycle(&state).await;

        assert_eq!(
            scanner.stats.processes_marked + scanner.stats.injection_failures,
            selected_candidates(&scanner, max_candidates),
            "every candidate must still be accounted for while a child exits"
        );
        assert_eq!(
            scanner.stats.injection_failures, 0,
            "a dry run attaches nothing, so an exited child cannot become a failure"
        );
    }

    #[tokio::test]
    async fn test_scan_cycle_survives_a_proc_entry_vanishing_during_the_walk() {
        // The same race from the other side: PID churn happening *while* the
        // `/proc` walk runs, so entries genuinely disappear between listing and
        // reading. A busy host walks hundreds of entries; at least one is on its
        // way out. The cycle must complete, and — because it is a dry run — the
        // partition must still close exactly.
        let (mut scanner, state) = churn_ready_scanner();
        let max_candidates = scanner.config.max_candidates_per_cycle;
        prime_state(&state).await;

        // A churn child that keeps creating and losing PIDs for the duration.
        let churn =
            OwnedChild::spawn(&["/bin/sh", "-c", "while :; do sleep 0.01 & sleep 0.01; done"]);
        let _ = &churn;

        scanner.scan_cycle(&state).await;

        assert!(
            scanner.stats.processes_filtered_l1 >= 1,
            "a zero RSS floor must admit at least one process on any host (l1={})",
            scanner.stats.processes_filtered_l1
        );
        assert_eq!(
            scanner.stats.processes_marked + scanner.stats.injection_failures,
            selected_candidates(&scanner, max_candidates),
            "a dry-run cycle must close the partition even while PIDs churn"
        );
        assert_eq!(scanner.stats.skipped_stabilization, 0);
    }

    #[test]
    fn test_a_zombie_child_is_non_injectable_but_not_a_crash() {
        // A zombie's `/proc/PID/status` is still readable (it has no `RssAnon:`
        // line, so the field parses as 0) — the fault must be modelled as it
        // really is. What makes it non-injectable is that it has no `mm`, so the
        // prctl injection fails, which is the `Err` arm `scan_cycle` counts as
        // `injection_failures`.
        let mut zombie_child = std::process::Command::new("/usr/bin/sleep")
            .arg("0")
            .spawn()
            .expect("spawning a sleep target must work");
        let zombie_pid = zombie_child.id();
        // Do NOT reap yet: hold the child in Z until the assertions are done.
        assert!(
            wait_until_state(zombie_pid, "Z"),
            "the child must reach the zombie state before the assertion"
        );

        let status = procfs::read_process_status(zombie_pid);
        assert!(
            status.is_ok(),
            "a zombie's status is readable; the fault is not a read error: \
         {status:?}"
        );
        let status = status.unwrap();
        // A zombie has no `mm`, so the kernel reports whatever RSS it held at
        // exit — `/proc/PID/status` keeps the last `RssAnon:` line it printed, it
        // does not zero it. This is why the default 100 MiB floor, not a
        // zombie-specific check, is what keeps a zombie out of the candidate set.
        assert!(
            status.anon_rss_kb < 1024,
            "a just-exited sleep held no meaningful anonymous RSS, got {} KiB",
            status.anon_rss_kb
        );

        // Un-injectability must be *reported*, not hidden.
        if ptrace_scope() > 1 {
            // A stricter Yama refuses the attach for a different reason; the
            // assertion would be indistinguishable, so stop before injecting.
            zombie_child.wait().expect("reaping the zombie");
            return;
        }
        let result = madvise::enable_merge_any(zombie_pid, false);
        assert!(
            result.error.is_some(),
            "injecting into a zombie must be reported as a failure: {result:?}"
        );
        assert_eq!(result.processes_marked, 0);
        assert_eq!(result.exec_vmas_protected, 0);
        assert_eq!(result.exec_vmas_failed, 0);

        // And it must never become an injectable candidate: a nonzero RSS floor
        // (the shipped default is 100 MiB) filters a 0 KiB process out.
        let config = ScannerConfig {
            min_anon_rss_mb: 1,
            blocklist: Vec::new(),
            ..ScannerConfig::default()
        };
        let mut stats = ScannerStats::default();
        let targets = collect_scan_targets(
            &config,
            vec![zombie_pid],
            &mut stats,
            |pid| procfs::read_process_status(pid).ok(),
            |pid| procfs::read_ksm_stat(pid).ok(),
        );
        assert!(targets.to_mark.is_empty());
        assert!(targets.already_flagged.is_empty());

        zombie_child.wait().expect("reaping the zombie");
    }

    #[test]
    fn test_parent_and_own_pid_pass_through_collection_without_panicking() {
        // Deterministic: the parent PID (ptrace-refused) and our own PID are
        // handed to the collector directly. Neither aborts the walk, and the
        // totals stay coherent with the number of readable statuses.
        let own = std::process::id();
        let parent = parent_pid();

        let config = ScannerConfig {
            min_anon_rss_mb: 0,
            max_candidates_per_cycle: 16,
            blocklist: Vec::new(),
            ..ScannerConfig::default()
        };
        let mut stats = ScannerStats::default();

        let targets = collect_scan_targets(
            &config,
            vec![parent, own],
            &mut stats,
            |pid| procfs::read_process_status(pid).ok(),
            |pid| procfs::read_ksm_stat(pid).ok(),
        );

        let readable = [parent, own]
            .iter()
            .filter(|pid| procfs::read_process_status(**pid).is_ok())
            .count();
        assert_eq!(
            stats.processes_filtered_l1, readable as u64,
            "Level 1 must count exactly the readable statuses"
        );

        let collected: Vec<u32> = targets.to_mark.iter().map(|c| c.pid).collect();
        assert!(
            collected.iter().all(|pid| *pid == parent || *pid == own),
            "only the offered PIDs may be collected: {collected:?}"
        );
        assert!(
            collected.len() as u64 + stats.processes_filtered_l25_profit
                <= stats.processes_filtered_l2,
            "the filtered counts must bound the selected set"
        );
    }

    #[tokio::test]
    async fn test_scan_cycle_partition_closes_with_an_uninjectable_candidate() {
        // A full cycle whose candidate set contains a process the daemon cannot
        // inject: the parent of this test process is live, outside this test's
        // subtree, and refused by Yama. Under `dry_run` nothing is attached, so
        // the partition must still close over the candidate set.
        let (mut scanner, state) = churn_ready_scanner();
        let max_candidates = scanner.config.max_candidates_per_cycle;
        prime_state(&state).await;

        scanner.scan_cycle(&state).await;

        let selected = selected_candidates(&scanner, max_candidates);
        assert!(
            selected >= 1,
            "a zero RSS floor must admit the parent process (l1={}, l2={})",
            scanner.stats.processes_filtered_l1,
            scanner.stats.processes_filtered_l2
        );
        assert_eq!(
            scanner.stats.processes_marked + scanner.stats.injection_failures,
            selected,
            "the partition must close over the candidate set, including any \
         process that would refuse a real attach"
        );
    }

    #[test]
    fn test_enable_merge_any_reports_the_parent_pid_as_uninjectable() {
        // The empirical half of the parent-PID fault: the real injection
        // function, driven against a real ptrace-refused process. This is the arm
        // `scan_cycle` counts, and it must leave every success count at zero —
        // never a partial mark on a process that was not touched.
        if ptrace_scope() > 1 {
            // A stricter Yama refuses this too, but for a different reason; the
            // assertion would be indistinguishable.
            return;
        }

        let parent = parent_pid();
        assert!(
            parent > 2,
            "there must be a parent process to refuse injection, got {parent}"
        );

        // Un-privileged (yama scope 1): a non-ancestor attach is refused, so
        // injection must report failure with every success count at zero.
        // Under root, ptrace_scope does not apply and the attach to the parent
        // legitimately succeeds — so the two outcomes are branched on, and the
        // accounting contract (marked XOR refused, never both) is what is
        // asserted in both arms rather than a single hardcoded outcome.
        let result = madvise::enable_merge_any(parent, false);
        if is_root() {
            assert_eq!(
                result.processes_marked, 1,
                "as root the parent is injectable, so it must be marked exactly \
             once: {result:?}"
            );
            // The additive accounting contract holds in both arms: every
            // executable VMA found is either protected or failed, so the two
            // counts must sum to the number of exec VMAs the maps actually
            // carry. 9 + 1 = 10 here is the coherent total, and a handler that
            // double-counted or dropped one would break this. The perms field
            // (second whitespace token) is what carries the execute bit —
            // matching the path or device column would over-count.
            let total_exec_vmas = std::fs::read_to_string(format!("/proc/{parent}/maps"))
                .map(|maps| {
                    maps.lines()
                        .filter(|line| {
                            line.split_whitespace()
                                .nth(1)
                                .is_some_and(|perms| perms.contains('x'))
                        })
                        .count()
                })
                .unwrap_or(0);
            assert_eq!(
                result.exec_vmas_protected + result.exec_vmas_failed,
                total_exec_vmas,
                "every executable VMA must be either protected or failed: \
             protected={} failed={} but maps carries {total_exec_vmas}: {result:?}",
                result.exec_vmas_protected,
                result.exec_vmas_failed,
            );
            assert!(
                result.exec_vmas_failed >= 1,
                "at least one VMA must be protected or failed, got {result:?}"
            );
            // Leave the parent as it was found: undo the real mark.
            let _ = madvise::unmerge_executable_vmas(parent, false);
        } else {
            assert!(
                result.error.is_some(),
                "a ptrace-refused parent must be reported as an injection failure: \
             {result:?}"
            );
            assert_eq!(result.processes_marked, 0);
            assert_eq!(result.exec_vmas_protected, 0);
            assert_eq!(result.exec_vmas_failed, 0);
        }

        // Un-injectability is a runtime outcome, not a discovery-time filter:
        // the collector must still offer the target as a candidate. The
        // discovery half uses a self-spawned child rather than the ambient
        // parent, because a parent's `/proc/PID/status` is only guaranteed to
        // be readable while it lives — under a `sudo`-launched harness the
        // parent can already be gone, which would make the assertion depend on
        // process-tree timing rather than on the collector. A child spawned
        // here is stable for both an unprivileged user and root.
        let config = ScannerConfig {
            min_anon_rss_mb: 0,
            max_candidates_per_cycle: 16,
            blocklist: Vec::new(),
            ..ScannerConfig::default()
        };
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn a discovery target");
        let child_pid = child.id();
        let mut stats = ScannerStats::default();
        let targets = collect_scan_targets(
            &config,
            vec![child_pid],
            &mut stats,
            |pid| procfs::read_process_status(pid).ok(),
            |pid| procfs::read_ksm_stat(pid).ok(),
        );
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            stats.processes_filtered_l1, 1,
            "a live process must still be discovered as a candidate"
        );
        assert_eq!(
            targets.to_mark.len(),
            1,
            "a non-injectable target must still be discovered"
        );
        assert_eq!(targets.to_mark[0].pid, child_pid);
    }

    /// A blocklist match is a **heuristic, never a security boundary** (see the
    /// root `AGENTS.md`). `comm` is user-writable — `PR_SET_NAME`, or a plain
    /// write to `/proc/self/comm`, both of which these tests use — and is 15
    /// bytes. These tests pin the heuristic's behaviour on a **real** renamed
    /// child, and pin that a benign comm is not filtered.
    mod blocklist_is_a_heuristic {
        use super::*;

        /// Spawn a shell that renames itself to `comm` and then stays alive
        /// without exec'ing — a `PR_SET_NAME` before an `exec` does not survive
        /// it, so the process must be the one that writes its own comm.
        ///
        /// The wait accepts the first 15 characters of `comm`, because a longer
        /// name is truncated by the kernel before it is ever readable.
        ///
        /// `printf %s` rather than `echo`: `echo` writes a trailing newline, and
        /// the kernel stores it in `comm`, so the *status* name comes back with a
        /// stray `\n` while `comm_of` trims it. `printf %s` writes exactly the
        /// requested bytes.
        fn spawn_renamed(comm: &str) -> OwnedChild {
            let truncated = &comm[..comm.len().min(15)];
            let child = OwnedChild::spawn(&[
                "/bin/sh",
                "-c",
                &format!("printf %s {comm} > /proc/self/comm; while :; do sleep 0.2; done"),
            ]);
            let pid = child.0.id();
            assert!(
                wait_until("the shell to take its new comm", || comm_of(pid).as_deref()
                    == Some(truncated)),
                "the child must be observably renamed to {truncated:?}"
            );
            child
        }

        /// A blocklist entry can be updated in one place.
        fn defaults() -> ScannerConfig {
            ScannerConfig::default()
        }

        #[test]
        fn a_real_renamed_child_is_matched_by_the_default_blocklist() {
            let defaults = defaults();
            let child = spawn_renamed("chrome");
            let pid = child.0.id();

            // Both `/proc/PID/comm` and the parsed `Name:` of
            // `/proc/PID/status` carry the renamed string. `read_process_status`
            // trims the value, which is the field the collector actually uses.
            assert_eq!(comm_of(pid).as_deref(), Some("chrome"));
            let status = procfs::read_process_status(pid).expect("status is readable");
            assert_eq!(
                status.name, "chrome",
                "a rename is visible through the status name the scanner reads"
            );

            assert!(
                procfs::is_blocklisted(&status.name, &defaults.blocklist),
                "a browser comm must match the shipped heuristic"
            );
            assert!(
                l1_candidate_from_status(status, &defaults).is_none(),
                "a blocklisted comm must be dropped at Level 1"
            );
        }

        #[test]
        fn comm_is_truncated_to_fifteen_bytes_and_still_matches() {
            // The kernel's comm buffer is 15 bytes, so a longer name is cut to 15
            // characters — a 16-character browser name becomes
            // `firefox-nightly`. The blocklist must still match the truncated
            // form, which it does because `firefox` is a substring of it.
            let defaults = defaults();
            let child = spawn_renamed("firefox-nightly-2");
            let pid = child.0.id();

            let comm = comm_of(pid).expect("the renamed child must be alive");
            assert_eq!(comm, "firefox-nightly", "a 16-char name must be cut to 15");
            assert_eq!(comm.len(), 15);

            let status = procfs::read_process_status(pid).expect("status is readable");
            assert_eq!(status.name, comm);

            assert!(
                procfs::is_blocklisted(&comm, &defaults.blocklist),
                "the truncated comm must still match the firefox pattern"
            );
            assert!(
                l1_candidate_from_status(status, &defaults).is_none(),
                "a truncated-but-blocklisted comm must be filtered"
            );
        }

        #[test]
        fn a_benign_comm_is_a_candidate_even_though_comm_is_writable() {
            // The other face of the heuristic, and the reason it must never be
            // called a boundary: the only evidence the blocklist ever sees is the
            // comm substring. A process with an ordinary name is not filtered —
            // whatever its executable or mappings look like. Asserting that this
            // is by design is the point of the test.
            let defaults = defaults();
            let config = ScannerConfig {
                min_anon_rss_mb: 0,
                max_candidates_per_cycle: 16,
                ..ScannerConfig::default()
            };

            // The pure heuristic claim: a benign comm is not blocklisted, so the
            // Level 1 gate lets it through.
            assert!(
                !procfs::is_blocklisted("plausible-name", &defaults.blocklist),
                "a benign comm must not match any shipped pattern"
            );
            let candidate = l1_candidate_from_status(
                ProcessStatus {
                    pid: 4242,
                    name: "plausible-name".into(),
                    anon_rss_kb: 512 * 1024,
                    ..Default::default()
                },
                &config,
            )
            .expect("a benign comm must be a candidate");
            assert_eq!(candidate.name, "plausible-name");

            // Collection reads only `/proc/PID/status`, so a benign comm is the
            // whole of the evidence, and the process is selected.
            let targets = collect_scan_targets(
                &config,
                vec![4242],
                &mut ScannerStats::default(),
                |pid| {
                    Some(ProcessStatus {
                        pid,
                        name: "plausible-name".into(),
                        anon_rss_kb: 512 * 1024,
                        ..Default::default()
                    })
                },
                |_| None,
            );
            assert_eq!(targets.to_mark.len(), 1);

            // And from the other side, on a real renamed child: the comm the
            // operator chose is the only thing that decides.
            let child = spawn_renamed("plausible-name");
            let pid = child.0.id();
            let comm = comm_of(pid).expect("the renamed child must be alive");
            assert!(
                !procfs::is_blocklisted(&comm, &defaults.blocklist),
                "a benign comm must survive the default blocklist"
            );
            let status = procfs::read_process_status(pid).expect("status is readable");
            assert_eq!(
                status.name, comm,
                "the status name must be the renamed comm, exactly"
            );
        }
    }
}
