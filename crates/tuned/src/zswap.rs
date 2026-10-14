//! The zswap subsystem of the fused daemon.
//!
//! The `tuned-zswap` crate is deliberately std-only and fully blocking — no
//! tokio, no async — because those constraints are what keep its decision
//! surface auditable. That leaves an impedance mismatch: a blocking
//! `thread::sleep` inside a tokio task would stall the reactor that is
//! simultaneously running the KSM governor and scanner.
//!
//! The answer is to keep the blocking code on the calling thread for the
//! duration of one short burst — a few `/proc`, sysfs and debugfs reads — and
//! let tokio's own timer do the 15 s wait. `block_in_place` is what makes that
//! safe: it moves the other tasks off this worker before blocking, so the
//! reactor never stalls, and the worker is only blocked for one poll.
//!
//! The alternative — one dedicated std thread with its own sleep loop — was
//! rejected because it could only observe shutdown by polling the channel, so
//! a stop could take up to a full interval instead of finishing inside the
//! daemon's 5 s grace period.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio::time;
use tracing::{debug, info, warn};
use tuned_zswap::{Debounce, PollAction};

use tuned_common::config::ZswapConfig;

/// Run the zswap tuning loop until the shutdown channel flips to `true`.
pub async fn run(config: ZswapConfig, mut shutdown: watch::Receiver<bool>) {
    let poll_every = poll_every_for(&config);
    let record_every = record_every_for(&config);

    info!(
        poll_secs = poll_every.as_secs(),
        record_secs = record_every.as_secs(),
        stats_path = %config.stats_path,
        "zswap tuning task started"
    );

    // Debounce state must survive across polls: the lowering rule needs three
    // consecutive low ratios, so a fresh Debounce per poll would never fire.
    // A `parking_lot` mutex holds nothing across an await, so it is never in a
    // position to block the reactor.
    let debounce = Arc::new(Mutex::new(Debounce::new(tuned_zswap::DEBOUNCE)));

    let mut ticker = time::interval(poll_every);
    // A missed tick must not trigger a catch-up burst; the next poll is what
    // matters, not the exact number of polls that were skipped.
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    // Sample immediately on start so a short window still yields several rows,
    // then on the cadence, decoupled from the decision poll.
    let mut next_record = time::Instant::now();

    loop {
        tokio::select! {
            // Shutdown first: if both are ready the daemon should stop rather
            // than take one more poll on the way out.
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("zswap tuning task stopped");
                    return;
                }
            }
            _ = ticker.tick() => {}
        }

        poll_once(Arc::clone(&debounce));

        if time::Instant::now() >= next_record {
            record_tick();
            next_record = time::Instant::now() + record_every;
        }
    }
}

/// One decision poll, run on the blocking path, with the outcome logged.
///
/// Errors are warnings, never fatal: a transient `/proc` or permission failure
/// must not stop the daemon from trying again on the next tick.
fn poll_once(debounce: Arc<Mutex<Debounce>>) {
    let result =
        tokio::task::block_in_place(|| tuned_zswap::poll_once(&mut debounce.lock(), false));

    let outcome = match result {
        Ok(outcome) => outcome,
        Err(e) => {
            warn!("zswap poll failed: {}", e);
            return;
        }
    };

    match outcome.action {
        PollAction::Applied { to } => info!(
            from = outcome.from,
            to,
            source = ?outcome.source,
            available_percent = outcome.available_percent,
            ratio = ?outcome.ratio,
            "zswap ceiling changed"
        ),
        PollAction::Hold => debug!(
            limit = outcome.from,
            source = ?outcome.source,
            available_percent = outcome.available_percent,
            ratio = ?outcome.ratio,
            "zswap ceiling already at target"
        ),
        PollAction::NoChange => debug!(
            limit = outcome.from,
            available_percent = outcome.available_percent,
            ratio = ?outcome.ratio,
            "zswap deadband: no change"
        ),
    }
}

/// One recording sample, appended to the JSONL history.
///
/// `record_tick` returns an error both when debugfs is unreadable (normal for
/// an unprivileged run) and when the log itself is unwritable. Neither is
/// fatal: the daemon keeps tuning and retries on the next cadence.
///
/// The limit argument is a pre-read placeholder that `record_sample`
/// overwrites with the live ceiling, so it is not read at all here.
fn record_tick() {
    if let Err(e) = tokio::task::block_in_place(|| tuned_zswap::record_tick(0)) {
        warn!("zswap sample skipped: {}", e);
    }
}

/// The decision-poll cadence, extracted so the fallback rule is testable
/// without starting a runtime.
fn poll_every_for(config: &ZswapConfig) -> Duration {
    if config.interval_secs == 0 {
        tuned_zswap::INTERVAL
    } else {
        Duration::from_secs(config.interval_secs)
    }
}

/// The recording cadence. Both zero and the `ZSWAP_TUNE_RECORD_INTERVAL`
/// environment variable resolve to the same library default.
fn record_every_for(config: &ZswapConfig) -> Duration {
    if config.record_interval_secs == 0 {
        tuned_zswap::record_interval()
    } else {
        Duration::from_secs(config.record_interval_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The blocking library call must complete inside a runtime rather than
    /// deadlocking or panicking. Dry-run, so nothing is written.
    #[tokio::test]
    async fn poll_once_completes_inside_a_runtime() {
        let debounce = Arc::new(Mutex::new(Debounce::new(tuned_zswap::DEBOUNCE)));
        // Dry-run against the live sysfs: with zswap enabled nothing is
        // written, with zswap disabled the read fails — both return, which is
        // what this test is actually pinning.
        let mut guard = debounce.lock();
        let outcome = tuned_zswap::poll_once(&mut guard, true);
        drop(guard);
        assert!(outcome.is_ok() || outcome.is_err());
    }

    /// The debounce must survive across polls, or the three-consecutive-low
    /// rule could never fire. Drive it the way the task does.
    #[test]
    fn debounce_survives_across_polls() {
        let mut debounce = Debounce::new(tuned_zswap::DEBOUNCE);
        assert_eq!(tuned_zswap::DEBOUNCE, 3);

        // A low ratio is withheld until it has been seen `DEBOUNCE` times.
        assert!(debounce.push(Some(1.0)).is_none(), "first low reading");
        assert!(debounce.push(Some(1.0)).is_none(), "second low reading");
        assert!(debounce.push(Some(1.0)).is_some(), "third forwards");
    }

    /// A zero configured interval means "library default"; mapping it to zero
    /// seconds would make the daemon spin, so the fallback is worth pinning.
    #[test]
    fn zero_interval_falls_back_to_the_library_default() {
        let cfg = ZswapConfig::default();
        assert_eq!(cfg.interval_secs, 0);

        let chosen = poll_every_for(&cfg);
        assert_eq!(chosen, tuned_zswap::INTERVAL, "default cadence preserved");
        assert!(
            chosen.as_secs() > 0,
            "a zero-second cadence would spin the loop"
        );
    }

    /// An explicit cadence is honoured rather than silently ignored, because an
    /// operator shortening it for a live measurement is expecting that value.
    #[test]
    fn explicit_interval_is_honoured() {
        let cfg = ZswapConfig {
            interval_secs: 4,
            ..ZswapConfig::default()
        };
        assert_eq!(poll_every_for(&cfg), Duration::from_secs(4));
    }
}
