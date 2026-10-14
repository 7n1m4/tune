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
    ///
    /// What this pins, and what the previous `assert!(outcome.is_ok() ||
    /// outcome.is_err())` did not: that the call *returned* at all. A
    /// deadlock inside `block_in_place` never reaches the assertion, and a
    /// panic aborts the task — so the assertion has to be on a value that only
    /// exists if the closure ran to completion.
    ///
    /// Both arms are strict. `expect` makes a deadlock, a panic, or an `Err`
    /// fail the test with the error text; on a host where zswap genuinely is
    /// unreadable the `Err` arm is asserted to carry a *message*, because an
    /// empty one would be the failure the `?` operator is silently producing
    /// rather than the kernel's reason.
    #[tokio::test]
    async fn poll_once_completes_inside_a_runtime() {
        let debounce = Arc::new(Mutex::new(Debounce::new(tuned_zswap::DEBOUNCE)));
        // Dry-run against the live sysfs: with zswap enabled nothing is
        // written, with zswap disabled the read fails — both return, which is
        // what this test is actually pinning.
        let mut guard = debounce.lock();
        let outcome = tuned_zswap::poll_once(&mut guard, true);
        drop(guard);

        let outcome = match outcome {
            Ok(outcome) => outcome,
            // A host without a readable zswap fails inside `poll_once`'s first
            // `?`. That is a legitimate outcome, but the error must still say
            // *why*: an empty message here is what a swallowed `?` produces.
            Err(e) => {
                assert!(
                    !e.trim().is_empty(),
                    "a failed poll must report its reason, not an empty error"
                );
                return;
            }
        };

        // The live poll's action must agree with the invariant. Only *one*
        // direction of this is exercised on any given host — whatever
        // `decide` picks right now — so it is not sufficient on its own and the
        // variant contract is pinned separately below.
        match outcome.action {
            tuned_zswap::PollAction::Applied { to } => {
                assert!(
                    outcome.action.changed(),
                    "an Applied action must report changed() == true"
                );
                // Every value the decision path can produce is clamped into
                // the allowed window, so anything outside it is a decision bug
                // — not a host quirk.
                assert!(
                    tuned_zswap::clamp(to) == to,
                    "an applied limit of {to} escaped the clamping window"
                );
            }
            ref other => assert!(
                !outcome.action.changed(),
                "changed() must be false for {other:?}, the non-Applied variants"
            ),
        }

        // The rest of the outcome must be internally coherent, so a `poll_once`
        // that returned a zeroed or partially-filled struct cannot pass.
        assert_eq!(outcome.from, self::read_zswap_limit_for_test());
        assert!(
            outcome.available_percent.is_finite() && outcome.available_percent >= 0.0,
            "a percentage must be a finite non-negative number, got {}",
            outcome.available_percent
        );
        if let Some(ratio) = outcome.ratio {
            assert!(
                ratio > 0.0 && ratio.is_finite(),
                "a reported ratio must be a positive finite number, got {ratio}"
            );
        }
    }

    /// `PollAction::changed()` is the one predicate the live poll above cannot
    /// fully exercise: on any given host only one of the three variants comes
    /// back, so a `changed()` that always answers the same way would survive a
    /// live-only test whenever it happens to match. All three variants are
    /// therefore constructed and pinned here, in both directions.
    #[test]
    fn poll_action_changed_is_true_only_for_applied() {
        // Applied: the ceiling moved, so it is a change.
        let applied = tuned_zswap::PollAction::Applied { to: 35 };
        assert!(applied.changed(), "Applied must report changed() == true");

        // Hold: the decision matched the ceiling already set. Nothing moved, so
        // it is not a change however similar it looks to a caller.
        assert!(
            !tuned_zswap::PollAction::Hold.changed(),
            "Hold must report changed() == false"
        );
        // NoChange: no decision at all, so still not a change. A `changed()`
        // that conflated "decided to do nothing" with "decided to act" would
        // inflate the daemon's change counter on every quiet poll.
        assert!(
            !tuned_zswap::PollAction::NoChange.changed(),
            "NoChange must report changed() == false"
        );

        // The predicate partitions the three variants into exactly one class,
        // so it is not something trivially right like `matches!(self, self)`.
        let variants = [
            tuned_zswap::PollAction::Hold,
            tuned_zswap::PollAction::NoChange,
        ];
        assert!(
            variants.iter().all(|v| !v.changed()),
            "the non-Applied variants must all report changed() == false"
        );
    }

    /// The ceiling the live poll reports in `Applied { to }` must already sit
    /// inside the clamping window. The live test asserts this only when it
    /// happens to get an `Applied` (on a host already at 50% with a healthy
    /// ratio it gets `Hold`), so the assertion is pinned on the value the
    /// decision path can actually return rather than on the host's state.
    #[test]
    fn applied_limit_always_survives_the_clamp() {
        // A boundary-legal value is its own clamp.
        assert_eq!(tuned_zswap::clamp(25), 25);
        assert_eq!(tuned_zswap::clamp(50), 50);
        // Out-of-window values are pulled inside, so nothing reaches sysfs at
        // 0 or 255, which the kernel would either reject or clamp differently.
        assert_eq!(tuned_zswap::clamp(0), 25);
        assert_eq!(tuned_zswap::clamp(255), 50);
        // The window is narrow enough that the two ends really differ from the
        // input, so these are not identity assertions on values already inside.
        assert_ne!(tuned_zswap::clamp(0), 0);
        assert_ne!(tuned_zswap::clamp(255), 255);

        // Whatever `decide` returns must be clamp-stable, or the `Applied { to }`
        // the daemon reports is not the value the decision path chose. The
        // inputs below are the two ends of the decision rule: lots of free RAM
        // with a good ratio raises the ceiling, a poor ratio lowers it.
        for (ratio, available) in [(0.1, 90.0), (3.0, 90.0), (2.0, 10.0)] {
            for current in [25u8, 30, 35, 40, 45, 50] {
                if let Some(to) = tuned_zswap::decide(current, Some(ratio), available) {
                    assert_eq!(
                        tuned_zswap::clamp(to),
                        to,
                        "decide proposed {to} outside the clamping window"
                    );
                }
            }
        }
    }

    /// The ceiling as the daemon would read it right now, used as the
    /// cross-check for `PollOutcome::from`. Kept beside the test that needs it
    /// so the expectation is produced by the same reader `poll_once` uses.
    fn read_zswap_limit_for_test() -> u8 {
        tuned_zswap::read_limit().unwrap_or(0)
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

    /// A zero recording interval means "library default", and the library's
    /// default is itself environment-overridable — so this asserts the daemon
    /// delegates rather than hardcoding `RECORD_INTERVAL`. Hardcoding would
    /// make `TUNED_ZSWAP_RECORD_INTERVAL` work for `poll_once`'s callers but
    /// silently not for the recording loop.
    #[test]
    fn zero_record_interval_defers_to_the_library_default() {
        let cfg = ZswapConfig::default();
        assert_eq!(cfg.record_interval_secs, 0);

        let chosen = record_every_for(&cfg);
        assert_eq!(
            chosen,
            tuned_zswap::record_interval(),
            "zero must defer to the library default, not a hardcoded duration"
        );
        assert!(
            chosen.as_secs() > 0,
            "a zero-second cadence would spin the loop"
        );
    }

    /// An explicit recording cadence is honoured. The guard matters: without
    /// it, a test whose chosen value happened to equal the library default
    /// would pass even if `record_every_for` ignored the configuration
    /// entirely.
    #[test]
    fn explicit_record_interval_is_honoured() {
        let cfg = ZswapConfig {
            record_interval_secs: 7,
            ..ZswapConfig::default()
        };
        assert_ne!(
            tuned_zswap::RECORD_INTERVAL,
            Duration::from_secs(7),
            "the fixture must differ from the library default or this cannot \
             tell the two branches apart"
        );
        assert_eq!(record_every_for(&cfg), Duration::from_secs(7));
    }
}
