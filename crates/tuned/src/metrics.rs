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

    // ── run_metrics_loop: the interval arm ───────────────────────────────

    /// A subscriber that captures the `ksm_pages_sharing` field of every event
    /// emitted with target `tuned::metrics`. Installing it is what turns
    /// `run_metrics_loop` from an unobservable black box into something that
    /// can be checked for having actually reported.
    #[derive(Default)]
    struct MetricCapture {
        pages_sharing: Vec<u64>,
    }

    struct MetricSubscriber {
        inner: std::sync::Arc<parking_lot::Mutex<MetricCapture>>,
    }

    struct FieldVisitor {
        sink: std::sync::Arc<parking_lot::Mutex<MetricCapture>>,
    }

    impl tracing::field::Visit for FieldVisitor {
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            if field.name() == "ksm_pages_sharing" {
                self.sink.lock().pages_sharing.push(value);
            }
        }

        fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}
    }

    impl tracing::Subscriber for MetricSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() != "tuned::metrics" {
                return;
            }
            let sink = std::sync::Arc::clone(&self.inner);
            event.record(&mut FieldVisitor { sink });
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// The interval arm must actually fire and report the KSM stats. Both
    /// existing tests call `report_metrics` directly, so nothing has ever
    /// proved that `run_metrics_loop`'s `select!` reaches it — and a loop
    /// whose tick arm was inverted or starved would never be caught by them.
    ///
    /// The assertion is on the captured *value*, not on the count alone: if
    /// the loop reported a zeroed or stale stats struct, the count would still
    /// be ≥ 1.
    ///
    /// The loop is driven inline on a manually built runtime rather than
    /// spawned, because `spawn` would require the `KsmController` borrow to be
    /// `'static` and the subscriber default must already be installed on this
    /// thread when the first report lands.
    #[test]
    fn test_run_metrics_loop_reports_seeded_ksm_stats_on_every_tick() {
        let dir = tempfile::tempdir().unwrap();
        seed_ksm_stats(dir.path());
        let ksm = KsmController::new(dir.path().to_str().unwrap()).unwrap();
        let state = new_shared_state();

        let capture = std::sync::Arc::new(parking_lot::Mutex::new(MetricCapture::default()));
        let subscriber = MetricSubscriber {
            inner: std::sync::Arc::clone(&capture),
        };

        // Signal shutdown from another thread once two intervals have passed.
        // The loop needs `interval >= 1` (tokio forbids a zero period) and must
        // not be shorter than the harness's patience.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let signaller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(2500));
            let _ = shutdown_tx.send(true);
        });

        tracing::subscriber::with_default(subscriber, || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            // Returns as soon as the shutdown arm fires; a 10 s ceiling keeps a
            // broken `select!` from hanging the whole suite.
            runtime.block_on(async {
                let loop_task = std::pin::pin!(run_metrics_loop(&ksm, state, 1, shutdown_rx));
                let _ = tokio::time::timeout(Duration::from_secs(10), loop_task).await;
            });
        });

        signaller
            .join()
            .expect("the shutdown signaller must return");

        let reports = capture.lock().pages_sharing.clone();
        assert!(
            !reports.is_empty(),
            "the interval arm must report at least once before shutdown"
        );
        assert!(
            reports.iter().all(|&v| v == 20),
            "every report must carry the seeded pages_sharing; got {reports:?}"
        );
    }

    /// The shutdown arm must break out even when no report is pending. An
    /// interval far longer than the test's lifetime means the shutdown arm is
    /// the *only* way out, so this isolates it from the interval arm.
    #[test]
    fn test_run_metrics_loop_exits_on_shutdown_without_a_tick() {
        let dir = tempfile::tempdir().unwrap();
        // No stat files, so `read_stats` would fail: the loop must exit on the
        // signal rather than depend on the reads succeeding.
        let ksm = KsmController::new(dir.path().to_str().unwrap()).unwrap();
        let state = new_shared_state();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let signaller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let _ = shutdown_tx.send(true);
        });

        let exited =
            tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let loop_task =
                            std::pin::pin!(run_metrics_loop(&ksm, state, 3600, shutdown_rx));
                        tokio::time::timeout(Duration::from_secs(5), loop_task)
                            .await
                            .is_ok()
                    })
            });

        signaller
            .join()
            .expect("the shutdown signaller must return");
        assert!(
            exited,
            "run_metrics_loop must break out on the shutdown signal"
        );
    }
}
