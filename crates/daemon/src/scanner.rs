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
use animaksm_common::procfs::{self, KsmProcStat, MapsEntry, ProcessStatus};
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
    pub processes_targeted: u64,
    pub madvise_calls: u64,
    pub total_bytes_marked: u64,
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

fn eligible_anon_rw_summary(maps: &[MapsEntry]) -> (usize, u64) {
    let eligible = maps
        .iter()
        .filter(|m| m.is_anon_rw() && !m.has_exec() && !m.is_special());

    let mut count = 0;
    let mut bytes = 0;
    for map in eligible {
        count += 1;
        bytes += map.size();
    }

    (count, bytes)
}

fn collect_scan_targets<StatusFn, KsmFn, MapsFn>(
    config: &ScannerConfig,
    pids: Vec<u32>,
    stats: &mut ScannerStats,
    mut read_status: StatusFn,
    mut read_ksm_stat: KsmFn,
    mut read_maps: MapsFn,
) -> Vec<(u32, Vec<procfs::MapsEntry>)>
where
    StatusFn: FnMut(u32) -> Option<ProcessStatus>,
    KsmFn: FnMut(u32) -> Option<KsmProcStat>,
    MapsFn: FnMut(u32) -> Option<Vec<procfs::MapsEntry>>,
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
        return Vec::new();
    }

    let mut l25_candidates: Vec<Candidate> = Vec::new();
    let mut l2_passed_count = 0u64;

    for candidate in l1_candidates {
        let ksm_stat = read_ksm_stat(candidate.pid);
        if !passes_l2_already_merged_filter(ksm_stat.as_ref()) {
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

    if l25_candidates.is_empty() {
        debug!("All candidates filtered by KSM status or negative profit");
        return Vec::new();
    }

    l25_candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.anon_rss_mb));
    l25_candidates.truncate(config.max_candidates_per_cycle);

    let mut targets: Vec<(u32, Vec<procfs::MapsEntry>)> = Vec::new();

    for candidate in &l25_candidates {
        let maps = match read_maps(candidate.pid) {
            Some(m) => m,
            None => continue,
        };

        let (anon_rw_count, total_anon_rw_bytes) = eligible_anon_rw_summary(&maps);

        if anon_rw_count == 0 {
            continue;
        }

        debug!(
            pid = candidate.pid,
            name = %candidate.name,
            anon_rss_mb = candidate.anon_rss_mb,
            anon_rw_regions = anon_rw_count,
            eligible_mb = total_anon_rw_bytes / 1024 / 1024,
            "Level 3 candidate — seeding KSM eligibility"
        );

        targets.push((candidate.pid, maps));
    }

    if targets.is_empty() {
        debug!("No Level 3 targets after maps filtering");
    }

    targets
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

        let madvise_calls_before = self.stats.madvise_calls;

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
            |pid| procfs::read_process_maps(pid).ok(),
        );

        if targets.is_empty() {
            return;
        }

        // Apply MADV_MERGEABLE to targets
        let max_bytes = self.config.max_mergeable_per_process_mb * 1024 * 1024;
        let results = madvise::batch_apply_mergeable(&targets, max_bytes, self.dry_run);

        // Aggregate statistics
        for result in results.values() {
            self.stats.processes_targeted += 1;
            self.stats.madvise_calls += result.regions_merged as u64;
            self.stats.total_bytes_marked += result.total_bytes_marked;

            if !result.errors.is_empty() {
                for (addr, err) in &result.errors {
                    debug!(
                        pid = result.pid,
                        addr = format!("0x{addr:x}"),
                        error = %err,
                        "madvise error for region"
                    );
                }
            }
        }

        // Opportunistic MADV_COLLAPSE: if KSM has been unmerging pages
        // (high pages_volatile), try to re-promote large regions to THPs
        // for TLB efficiency. Only on processes we already touched.
        if let Ok(ksm_stats) = animaksm_common::ksm::KsmController::new("/sys/kernel/mm/ksm") {
            if let Ok(stats) = ksm_stats.read_stats() {
                if stats.pages_volatile > 1000 {
                    for (pid, maps) in &targets {
                        if !self.dry_run {
                            let collapsed = madvise::collapse_regions(*pid, maps);
                            self.stats.thp_collapsed += collapsed as u64;
                        }
                    }
                }
            }
        }

        // Update scanner stabilization timestamp if this cycle actually did
        // something. `madvise_calls` is cumulative, so compare against the
        // start-of-cycle value instead of checking it for nonzero.
        if self.stats.madvise_calls > madvise_calls_before {
            let mut s = state.write().await;
            s.last_scanner_action = Instant::now();
            s.last_global_action = Instant::now();
        }

        info!(
            scan_cycle = self.stats.scan_cycles,
            l1_passed = self.stats.processes_filtered_l1,
            l2_passed = self.stats.processes_filtered_l2,
            l25_profit_filtered = self.stats.processes_filtered_l25_profit,
            targeted = targets.len(),
            madvise_calls = self.stats.madvise_calls,
            marked_mb = self.stats.total_bytes_marked / 1024 / 1024,
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
        assert_eq!(stats.processes_targeted, 0);
        assert_eq!(stats.madvise_calls, 0);
        assert_eq!(stats.total_bytes_marked, 0);
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

    fn map(start: u64, end: u64, perms: &str, inode: u64, pathname: &str) -> MapsEntry {
        MapsEntry {
            start,
            end,
            perms: perms.into(),
            offset: 0,
            dev: "00:00".into(),
            inode,
            pathname: pathname.into(),
        }
    }

    #[test]
    fn test_eligible_anon_rw_summary_counts_only_l3_candidates() {
        let maps = vec![
            map(0x1000, 0x5000, "rw-p", 0, ""),
            map(0x5000, 0x9000, "rwxp", 0, ""),
            map(0x9000, 0xD000, "rw-s", 0, ""),
            map(0xD000, 0x11000, "rw-p", 12, "/tmp/file"),
            map(0x11000, 0x15000, "rw-p", 0, "[heap]"),
            map(0x15000, 0x1D000, "rw-p", 0, ""),
        ];

        let (count, bytes) = eligible_anon_rw_summary(&maps);
        assert_eq!(count, 2);
        assert_eq!(bytes, 0x4000 + 0x8000);
    }

    #[test]
    fn test_collect_scan_targets_returns_empty_when_l1_has_no_candidates() {
        let config = ScannerConfig {
            min_anon_rss_mb: 128,
            ..ScannerConfig::default()
        };
        let mut stats = ScannerStats::default();

        let targets = collect_scan_targets(
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
            |_| None,
        );

        assert!(targets.is_empty());
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

        let targets = collect_scan_targets(
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
            |_| Some(vec![map(0x1000, 0x5000, "rw-p", 0, "")]),
        );

        assert!(targets.is_empty());
        assert_eq!(stats.processes_filtered_l1, 2);
        assert_eq!(stats.processes_filtered_l2, 0);
    }

    #[test]
    fn test_collect_scan_targets_filters_negative_profit_and_missing_maps() {
        let config = ScannerConfig {
            min_anon_rss_mb: 128,
            max_candidates_per_cycle: 3,
            ..ScannerConfig::default()
        };
        let mut stats = ScannerStats::default();

        let targets = collect_scan_targets(
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
            |pid| match pid {
                11 => None,
                12 => Some(vec![map(0x1000, 0x5000, "rw-p", 0, "")]),
                _ => unreachable!(),
            },
        );

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, 12);
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

        let targets = collect_scan_targets(
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
            |pid| {
                Some(vec![map(
                    pid as u64 * 0x10000,
                    pid as u64 * 0x10000 + 0x4000,
                    "rw-p",
                    0,
                    "",
                )])
            },
        );

        assert_eq!(
            targets.iter().map(|(pid, _)| *pid).collect::<Vec<_>>(),
            vec![11, 12]
        );
        assert_eq!(stats.processes_filtered_l1, 3);
        assert_eq!(stats.processes_filtered_l2, 3);
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

        let maps = [map(0x1000, 0x5000, "rw-p", 0, "")];
        assert_eq!(eligible_anon_rw_summary(&maps), (1, 0x4000));
    }
}
