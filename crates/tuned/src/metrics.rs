//! Metrics collection and reporting for the daemon.
//!
//! Periodically logs structured metrics via tracing that get routed
//! to systemd journal or JSON log files.

use std::time::Duration;

use tokio::sync::watch;
use tokio::time;
use tracing::info;
use tuned_common::ksm::KsmController;
use tuned_common::SharedGovernorState;

/// Run the metrics reporting loop.
pub async fn run_metrics_loop(
    ksm: &KsmController,
    state: SharedGovernorState,
    interval_secs: u64,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = time::interval(Duration::from_secs(interval_secs));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                report_metrics(ksm, &state).await;
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

async fn report_metrics(ksm: &KsmController, state: &SharedGovernorState) {
    let ksm_stats = match ksm.read_stats() {
        Ok(s) => s,
        Err(_) => return,
    };

    let s = state.read().await;

    // Read our own RSS
    let daemon_rss_kb = read_self_rss_kb();

    info!(
        target = "tuned::metrics",
        ksm_pages_shared = ksm_stats.pages_shared,
        ksm_pages_sharing = ksm_stats.pages_sharing,
        // ksm_general_profit is in BYTES per mm/ksm.c:general_profit_show()
        // (pages_sharing + ksm_zero_pages) * PAGE_SIZE - rmap overhead. Its
        // neighbours on this line are all page counts, so emitting the raw
        // value invites reading it as pages and deriving ~64 GiB of "savings"
        // from a machine where KSM saved 36 MiB. Report MiB and say so.
        ksm_general_profit_mib = format!("{:.1}", ksm_stats.general_profit as f64 / 1048576.0),
        ksm_full_scans = ksm_stats.full_scans,
        governor_level = s.ksm_level,
        pressure = %s.current_pressure,
        daemon_rss_kb,
        "Metrics report"
    );
}

/// Read our own RSS from /proc/self/status.
fn read_self_rss_kb() -> u64 {
    if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if let Some(value) = line.strip_prefix("VmRSS:") {
                let s = value.trim().trim_end_matches(" kB").trim();
                return s.parse().unwrap_or(0);
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tuned_common::new_shared_state;

    fn seed_ksm_stats(dir: &std::path::Path) {
        for (name, value) in [
            ("pages_shared", "10"),
            ("pages_sharing", "20"),
            ("pages_unshared", "5"),
            ("pages_volatile", "1"),
            ("pages_scanned", "100"),
            ("pages_skipped", "2"),
            ("full_scans", "3"),
            ("general_profit", "4096"),
        ] {
            std::fs::write(dir.join(name), value).unwrap();
        }
    }

    #[test]
    fn test_read_self_rss_kb() {
        let rss = read_self_rss_kb();
        // The test process itself has some RSS; even a minimal binary
        // should have at least a few pages.
        assert!(rss > 0, "expected nonzero RSS for the test process");
    }

    #[test]
    fn test_read_self_rss_kb_returns_u64() {
        // This is a type/safety check — read_self_rss_kb must never panic
        // on the current process.
        let rss = read_self_rss_kb();
        // Sanity: a Rust test binary won't use terabytes
        assert!(rss < 1_000_000_000, "RSS unreasonably large: {rss}");
    }

    #[tokio::test]
    async fn test_report_metrics_reads_ksm_and_shared_state() {
        let dir = tempfile::tempdir().unwrap();
        seed_ksm_stats(dir.path());
        let ksm = KsmController::new(dir.path().to_str().unwrap()).unwrap();
        let state = new_shared_state();

        {
            let mut s = state.write().await;
            s.ksm_level = 3;
            s.pages_sharing = 20;
            s.general_profit = 4096;
        }

        report_metrics(&ksm, &state).await;
    }

    #[tokio::test]
    async fn test_report_metrics_returns_on_ksm_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let ksm = KsmController::new(dir.path().to_str().unwrap()).unwrap();
        let state = new_shared_state();

        report_metrics(&ksm, &state).await;
    }
}
