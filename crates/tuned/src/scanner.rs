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
}
