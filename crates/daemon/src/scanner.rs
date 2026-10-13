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
//! ## Stabilization
//!
//! Respects its own stabilization window for madvise bursts. Governor profile
//! changes use a separate timestamp and do not block scanner cycles.

use std::time::{Duration, Instant};

use animaksm_common::config::ScannerConfig;
use animaksm_common::procfs::{self, KsmProcStat, ProcessStatus};
use animaksm_common::SharedGovernorState;
use tokio::sync::watch;
use tokio::time;
use tracing::{debug, info, warn};

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

/// The process scanner.
pub struct Scanner {
    config: ScannerConfig,
    dry_run: bool,
    stats: ScannerStats,
    stabilization_secs: u64,
}

impl Scanner {
    pub fn new(config: ScannerConfig, dry_run: bool, stabilization_secs: u64) -> Self {
        Self {
            config,
            dry_run,
            stats: ScannerStats::default(),
            stabilization_secs,
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
                injected.push(candidate.pid);
            }
        }

        // Re-apply the executable-VMA guard to processes that were flagged on
        // an earlier cycle. `PR_SET_MEMORY_MERGE` is sticky and inherited, so a
        // browser keeps accumulating `r-xp` mappings (JIT, forked renderers)
        // after it was marked; without this pass those mappings stay mergeable
        // for the daemon's whole lifetime, which is exactly the SIGILL this
        // guard exists to prevent. The withdrawal is per-VMA and idempotent.
        for candidate in &targets.already_flagged {
            let (withdrawn, found) = madvise::unmerge_executable_vmas(candidate.pid, self.dry_run);
            self.stats.exec_vmas_reprotected += withdrawn as u64;

            if found > 0 {
                // A target can exit between listing and injection; that is
                // expected, so this is a debug line, not a failure count.
                debug!(
                    pid = candidate.pid,
                    name = %candidate.name,
                    withdrawn,
                    found,
                    "Re-protected executable VMAs on an already-flagged process"
                );
            }
        }

        // Opportunistic MADV_COLLAPSE: if KSM has been unmerging pages
        // (high pages_volatile), try to re-promote large regions to THPs
        // for TLB efficiency. process_madvise supports COLLAPSE cross-process,
        // so it needs the region list this path used to be able to rely on.
        if let Ok(ksm_stats) = animaksm_common::ksm::KsmController::new("/sys/kernel/mm/ksm") {
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
            exec_vmas_reprotected = self.stats.exec_vmas_reprotected,
            thp_collapsed = self.stats.thp_collapsed,
            skipped_stab = self.stats.skipped_stabilization,
            "Scanner cycle complete"
        );
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
    use animaksm_common::config::ScannerConfig;
    use animaksm_common::GovernorState;
    use std::sync::Arc;
    use tokio::sync::RwLock;

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
            blocklist: vec!["animaksm".into()],
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
                name: "animaksm-daemon".into(),
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
}
