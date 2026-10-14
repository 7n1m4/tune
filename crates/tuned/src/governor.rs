//! Tier 1: PSI-aware KSM Governor
//!
//! Monitors memory pressure and dynamically adjusts KSM scanning
//! aggressiveness to trade CPU cycles for effective RAM.
//!
//! ## Control Model (Option B — Advisor Primary)
//!
//! When `use_advisor = true`, the kernel advisor is the primary controller
//! for `pages_to_scan`. The governor acts as a **bias layer only**, adjusting:
//! - `max_page_sharing` (how many processes can share a page)
//! - `sleep_millisecs` bounds (pace of scanning)
//!
//! This avoids two controllers fighting the same parameters.
//!
//! ## Stabilization
//!
//! A stabilization window damps repeated governor profile changes. Other
//! tiers maintain their own stabilization timestamps so a KSM profile write
//! cannot starve the process scanner.
//!
//! ## Idle (level 0)
//!
//! Sustained idle pressure drives the governor to level 0, the profile with
//! `run: 0`. In manual mode that stops the scanner outright. In advisor mode
//! level 0 still keeps `run = 1` (the advisor needs it) but relaxes the
//! governor's bias knobs — it is a real, distinct state, not a no-op.
//!
//! Because PSI's EWMA scores sit on a wandering boundary between Idle and
//! Low, entering level 0 requires a *sustained* idle dwell
//! (`hysteresis_readings * IDLE_DWELL_FACTOR` consecutive idle readings) on
//! top of the cooldown, and leaving it still needs `hysteresis_readings`
//! consecutive non-idle readings. Flickering pressure cannot toggle KSM on
//! and off.

use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::time;
use tracing::{debug, info, warn};
use tuned_common::config::GovernorConfig;
use tuned_common::ksm::{KsmController, KsmStats};
use tuned_common::psi::{PressureLevel, PsiStats};
use tuned_common::SharedGovernorState;

/// KSM profile for each aggressiveness level.
///
/// In advisor mode (Option B), only `max_page_sharing` and `sleep_millisecs`
/// are written. The advisor handles `pages_to_scan` internally.
#[derive(Debug, Clone)]
pub struct KsmProfile {
    #[allow(dead_code)]
    pub level: u8,
    pub run: u64,
    pub max_page_sharing: u32,
    pub sleep_millisecs: u64,
    pub pages_to_scan: u64, // only used when advisor is OFF
}

/// The governor profiles table.
const PROFILES: &[KsmProfile] = &[
    // Level 0: Idle — KSM stopped, no scanning
    KsmProfile {
        level: 0,
        run: 0,
        max_page_sharing: 256,
        sleep_millisecs: 500,
        pages_to_scan: 100,
    },
    // Level 1: Light — minimal scanning
    KsmProfile {
        level: 1,
        run: 1,
        max_page_sharing: 256,
        sleep_millisecs: 100,
        pages_to_scan: 500,
    },
    // Level 2: Moderate
    KsmProfile {
        level: 2,
        run: 1,
        max_page_sharing: 384,
        sleep_millisecs: 50,
        pages_to_scan: 2000,
    },
    // Level 3: Active
    KsmProfile {
        level: 3,
        run: 1,
        max_page_sharing: 512,
        sleep_millisecs: 20,
        pages_to_scan: 5000,
    },
    // Level 4: Aggressive
    KsmProfile {
        level: 4,
        run: 1,
        max_page_sharing: 768,
        sleep_millisecs: 10,
        pages_to_scan: 15000,
    },
    // Level 5: Emergency — maximum scanning
    KsmProfile {
        level: 5,
        run: 1,
        max_page_sharing: 1024,
        sleep_millisecs: 5,
        pages_to_scan: 30000,
    },
];

/// Multiplier applied to `hysteresis_readings` to get the number of
/// *consecutive* idle readings required before stepping down into level 0.
///
/// Level 0 is the only profile that stops the scanner (`run: 0`), and starting
/// it again costs a full ramp-up. PSI's 10-second EWMAs make a single reading a
/// weak signal, so the transition demands sustained idleness well beyond the
/// ordinary hysteresis window.
const IDLE_DWELL_FACTOR: u32 = 3;

/// The governor state machine.
pub struct Governor {
    config: GovernorConfig,
    ksm: KsmController,
    current_level: u8,
    hysteresis_count: u32,
    /// Consecutive ticks with target above current level (ramp-up damping).
    ramp_up_count: u32,
    /// Consecutive ticks whose target is level 0 while sitting at level 1
    /// (idle dwell). Reset by any non-idle reading, so a PSI score straddling
    /// the Idle/Low boundary can never accumulate enough dwell to stop KSM.
    idle_dwell_count: u32,
    level_entered_at: Instant,
    full_scans_at_level: u64,
    /// Last PSI reading (for fallback stability check).
    last_psi: Option<PsiStats>,
    /// Consecutive ticks with stable PSI (for drift detection).
    stable_psi_ticks: u32,
}

impl Governor {
    pub fn new(config: GovernorConfig, ksm: KsmController) -> Self {
        Self {
            config,
            ksm,
            current_level: 0,
            hysteresis_count: 0,
            ramp_up_count: 0,
            idle_dwell_count: 0,
            level_entered_at: Instant::now(),
            full_scans_at_level: 0,
            last_psi: None,
            stable_psi_ticks: 0,
        }
    }

    /// Run the governor loop until shutdown is signaled.
    pub async fn run(
        mut self,
        state: SharedGovernorState,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let poll_interval = Duration::from_millis(2000);
        let mut interval = time::interval(poll_interval);

        info!(
            use_advisor = self.config.use_advisor,
            stabilization_secs = self.config.stabilization_secs,
            "KSM governor started (Option B: bias layer over kernel advisor)"
        );

        // Enable KSM and advisor mode on startup
        if self.config.use_advisor {
            let _ = self.ksm.set_advisor_mode("scan-time");
            info!("KSM advisor mode set to scan-time (governor biases bounds only)");
        }
        let _ = self.ksm.set_run(1);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.tick(&state).await;
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Governor received shutdown signal");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Single tick of the governor loop.
    async fn tick(&mut self, state: &SharedGovernorState) {
        // Read current PSI (this IS the periodic fallback poll — always runs)
        let psi = match PsiStats::read_memory() {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "Failed to read PSI stats");
                return;
            }
        };

        // Read current KSM stats
        let ksm_stats = match self.ksm.read_stats() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "Failed to read KSM stats");
                return;
            }
        };

        self.tick_with_readings(state, psi, ksm_stats).await;
    }

    async fn tick_with_readings(
        &mut self,
        state: &SharedGovernorState,
        psi: PsiStats,
        ksm_stats: KsmStats,
    ) {
        self.observe_psi_stability(&psi);

        // Classify pressure
        let pressure = psi.classify(
            self.config.psi_some_threshold,
            self.config.psi_full_threshold,
        );

        // Determine target level
        let target_level = self.pressure_to_level(pressure);

        // Apply transition logic with hysteresis
        let new_level = self.compute_transition(target_level);

        // Apply profile if level changed (with per-governor damping check)
        if new_level != self.current_level {
            // Check governor stabilization window
            let stabilization = Duration::from_secs(self.config.stabilization_secs);
            let time_since_action = {
                let s = state.read().await;
                s.last_governor_action.elapsed()
            };

            if time_since_action >= stabilization {
                self.apply_profile(new_level, state).await;
            } else {
                debug!(
                    remaining_secs = (stabilization - time_since_action).as_secs(),
                    "Level change deferred (governor stabilization window)"
                );
            }
        }

        // Profit monitoring: if KSM is running but profit is negative after many scans
        if self.current_level > 0
            && ksm_stats.general_profit < 0
            && ksm_stats.full_scans > self.full_scans_at_level + 10
        {
            warn!(
                level = self.current_level,
                profit = ksm_stats.general_profit,
                "KSM general_profit is negative after sustained scanning, reducing aggressiveness"
            );
            if self.current_level > 1 {
                self.apply_profile(self.current_level - 1, state).await;
            }
        }

        // Update shared state
        {
            let mut s = state.write().await;
            s.current_pressure = pressure;
            s.ksm_level = self.current_level;
            s.pages_sharing = ksm_stats.pages_sharing;
            s.general_profit = ksm_stats.general_profit;
            s.last_adjustment = Instant::now();
        }

        debug!(
            psi_some_avg10 = psi.some.avg10,
            psi_full_avg10 = psi.full.avg10,
            pressure = %pressure,
            ksm_level = self.current_level,
            pages_shared = ksm_stats.pages_shared,
            pages_sharing = ksm_stats.pages_sharing,
            general_profit = ksm_stats.general_profit,
            stable_psi_ticks = self.stable_psi_ticks,
            "Governor tick"
        );
    }

    fn observe_psi_stability(&mut self, psi: &PsiStats) {
        // PSI stability tracking (for drift detection)
        if let Some(ref prev) = self.last_psi {
            let some_diff = (psi.some.avg10 - prev.some.avg10).abs();
            let full_diff = (psi.full.avg10 - prev.full.avg10).abs();
            if some_diff < 0.5 && full_diff < 0.5 {
                self.stable_psi_ticks += 1;
            } else {
                self.stable_psi_ticks = 0;
            }
        }
        self.last_psi = Some(psi.clone());
    }

    /// Map pressure level to KSM aggressiveness level (0-5).
    ///
    /// Idle maps to level 0 — the profile with `run: 0` that stops scanning.
    /// The 0↔1 boundary is protected in `compute_transition`: entering Idle
    /// needs `hysteresis_readings * IDLE_DWELL_FACTOR` *consecutive* idle
    /// readings on top of the usual `min_level_duration_secs` cooldown, while
    /// leaving Idle still needs `hysteresis_readings` consecutive non-idle
    /// readings. PSI scores hovering around the Idle/Low classification
    /// threshold therefore cannot toggle the scanner on and off.
    fn pressure_to_level(&self, pressure: PressureLevel) -> u8 {
        match pressure {
            PressureLevel::Idle => 0,
            PressureLevel::Low => 1,
            PressureLevel::Medium => 3,
            PressureLevel::High => 4,
            PressureLevel::Critical => 5,
        }
    }

    /// Compute the actual transition with hysteresis and cooldown.
    ///
    /// Ramp-up requires consecutive hysteresis readings when the target is
    /// only +1 above the current level (prevents 1↔2 oscillation). Multi-level
    /// emergency jumps (target >= current+2) bypass hysteresis and ramp
    /// immediately.
    ///
    /// Ramp-down steps one level at a time, gated by the `min_level_duration_secs`
    /// cooldown plus `hysteresis_readings` consecutive readings. The final step
    /// into level 0 (KSM stopped) additionally needs
    /// `hysteresis_readings * IDLE_DWELL_FACTOR` consecutive idle readings, so
    /// a PSI score flickering across the Idle/Low boundary cannot toggle the
    /// scanner on and off.
    fn compute_transition(&mut self, target_level: u8) -> u8 {
        // Idle dwell tracking: only a *consecutive* run of idle readings counts,
        // so a single Low reading in between resets the count.
        if target_level == 0 && self.current_level == 1 {
            self.idle_dwell_count += 1;
        } else {
            self.idle_dwell_count = 0;
        }

        if target_level > self.current_level {
            // Multi-level jump (emergency): ramp immediately
            // Use saturating_add so this is safe if current_level is near u8::MAX
            // (in practice current_level is capped at 5 by PROFILES).
            if target_level >= self.current_level.saturating_add(2) {
                self.hysteresis_count = 0;
                self.ramp_up_count = 0;
                self.level_entered_at = Instant::now();
                self.full_scans_at_level = 0;
                return target_level;
            }

            // Single-level ramp-up with hysteresis
            self.ramp_up_count += 1;
            self.hysteresis_count = 0;
            if self.ramp_up_count >= self.config.hysteresis_readings {
                self.ramp_up_count = 0;
                self.level_entered_at = Instant::now();
                self.full_scans_at_level = 0;
                target_level
            } else {
                self.current_level
            }
        } else if target_level < self.current_level {
            // Ramp down with hysteresis and cooldown
            self.ramp_up_count = 0;
            let cooldown = Duration::from_secs(self.config.min_level_duration_secs);
            if self.level_entered_at.elapsed() < cooldown {
                return self.current_level; // Still in cooldown
            }

            self.hysteresis_count += 1;
            if self.hysteresis_count >= self.config.hysteresis_readings {
                self.hysteresis_count = 0;
                // The step into level 0 is the expensive one: it stops KSM
                // entirely, and restarting it later costs a full ramp-up, so it
                // needs a sustained idle dwell on top of the ordinary
                // hysteresis. While dwelling, stay at level 1.
                if self.current_level == 1 {
                    let required = self
                        .config
                        .hysteresis_readings
                        .saturating_mul(IDLE_DWELL_FACTOR)
                        .max(1);
                    if self.idle_dwell_count < required {
                        return self.current_level;
                    }
                    self.idle_dwell_count = 0;
                }
                self.level_entered_at = Instant::now();
                self.full_scans_at_level = 0;
                // Step down by one level at a time
                self.current_level - 1
            } else {
                self.current_level
            }
        } else {
            // Same level, reset both counters
            self.hysteresis_count = 0;
            self.ramp_up_count = 0;
            self.current_level
        }
    }

    /// Apply a KSM profile by writing sysfs parameters.
    ///
    /// In advisor mode (Option B), only writes `max_page_sharing` and
    /// `sleep_millisecs` — the kernel advisor controls `pages_to_scan`.
    /// Level 0 in advisor mode keeps `run = 1` (the advisor requires it) and
    /// simply relaxes the bias knobs. In manual mode, writes all parameters
    /// and level 0 stops the scanner with `run = 0`.
    async fn apply_profile(&mut self, level: u8, state: &SharedGovernorState) {
        let profile = &PROFILES[level as usize];
        let prev_level = self.current_level;

        info!(
            prev_level,
            new_level = level,
            advisor_mode = self.config.use_advisor,
            max_page_sharing = profile.max_page_sharing,
            sleep_millisecs = profile.sleep_millisecs,
            "Applying KSM profile"
        );

        // Write order matters: set run=0 first if going to idle, then params, then run=1.
        // In advisor mode, never stop KSM — the advisor needs run=1 to function.
        if profile.run == 0 && !self.config.use_advisor {
            let _ = self.ksm.set_run(0);
        }

        // Always write these — they are the governor's "bias knobs"
        let _ = self.ksm.set_sleep_millisecs(profile.sleep_millisecs);
        let _ = self
            .ksm
            .set_max_page_sharing(profile.max_page_sharing as u64);

        if self.config.use_advisor {
            // Option B: DON'T write pages_to_scan or advisor_target_scan_time.
            // Let the kernel advisor decide scan rate. We only bias the bounds.
            debug!("Advisor mode: skipping pages_to_scan (kernel controls scan rate)");
        } else {
            // Full manual control
            let _ = self.ksm.set_pages_to_scan(profile.pages_to_scan);
        }

        if profile.run != 0 {
            let _ = self.ksm.set_run(1);
        }

        self.current_level = level;

        // Update governor stabilization timestamp. Keep the global timestamp
        // as observability for "anything acted" without using it as a gate.
        {
            let mut s = state.write().await;
            s.last_governor_action = Instant::now();
            s.last_global_action = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tuned_common::new_shared_state;

    /// Create a Governor with default config and a dry-run KSM controller.
    fn make_gov() -> Governor {
        let mut ksm = KsmController::new("/sys/kernel/mm/ksm").unwrap();
        ksm.set_dry_run(true);
        Governor::new(GovernorConfig::default(), ksm)
    }

    /// Create a Governor with a modified config.
    fn make_gov_with(f: impl FnOnce(&mut GovernorConfig)) -> Governor {
        let mut config = GovernorConfig::default();
        f(&mut config);
        let mut ksm = KsmController::new("/sys/kernel/mm/ksm").unwrap();
        ksm.set_dry_run(true);
        Governor::new(config, ksm)
    }

    fn make_temp_gov_with(f: impl FnOnce(&mut GovernorConfig)) -> Governor {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep();
        let mut config = GovernorConfig {
            ksm_path: path.to_string_lossy().to_string(),
            ..Default::default()
        };
        f(&mut config);
        let mut ksm = KsmController::new(&config.ksm_path).unwrap();
        ksm.set_dry_run(true);
        Governor::new(config, ksm)
    }

    fn psi(some_avg10: f32, full_avg10: f32) -> PsiStats {
        PsiStats {
            some: tuned_common::psi::PsiLine {
                avg10: some_avg10,
                ..Default::default()
            },
            full: tuned_common::psi::PsiLine {
                avg10: full_avg10,
                ..Default::default()
            },
        }
    }

    /// Build a governor over a temp directory seeded with every KSM stat file
    /// and every parameter file, wired to a **real** (non-dry-run) controller
    /// so the writes can be read back off disk.
    ///
    /// The controller's 500 ms rate limiter is not an obstacle: `KsmController::
    /// new` already seeds `last_update` at now − 500 ms, and `write_param`
    /// never advances it, so every write lands on the first attempt.
    ///
    /// Returns the governor alongside its `TempDir`; dropping the dir first
    /// makes any post-drop write fail rather than silently pass.
    fn seeded_gov(f: impl FnOnce(&mut GovernorConfig)) -> (Governor, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        for (name, value) in [
            ("pages_shared", "10"),
            ("pages_sharing", "20"),
            ("pages_unshared", "5"),
            ("pages_volatile", "1"),
            ("pages_scanned", "100"),
            ("pages_skipped", "2"),
            ("full_scans", "3"),
            ("general_profit", "4096"),
            ("ksm_zero_pages", "0"),
            ("stable_node_chains", "0"),
            ("stable_node_dups", "0"),
            ("run", "1"),
            ("pages_to_scan", "100"),
            ("sleep_millisecs", "500"),
            ("max_page_sharing", "256"),
            ("advisor_mode", "scan-time"),
            ("advisor_target_scan_time", "200"),
            ("advisor_max_cpu", "70"),
            ("advisor_min_pages_to_scan", "500"),
            ("advisor_max_pages_to_scan", "30000"),
        ] {
            std::fs::write(dir.path().join(name), value).unwrap();
        }
        let mut config = GovernorConfig {
            ksm_path: dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        f(&mut config);
        let mut ctrl = KsmController::new(&config.ksm_path).unwrap();
        ctrl.set_dry_run(false);
        (Governor::new(config, ctrl), dir)
    }

    fn ksm_stats(pages_sharing: u64, general_profit: i64, full_scans: u64) -> KsmStats {
        KsmStats {
            pages_shared: pages_sharing / 2,
            pages_sharing,
            general_profit,
            full_scans,
            ..Default::default()
        }
    }

    // ── Initial state ────────────────────────────────────────────────

    #[test]
    fn test_new_initial_state() {
        let gov = make_gov();
        assert_eq!(gov.current_level, 0, "should start at Idle level");
        assert_eq!(gov.hysteresis_count, 0);
        assert_eq!(gov.stable_psi_ticks, 0);
        assert!(gov.last_psi.is_none());
    }

    // ── PROFILES table integrity ─────────────────────────────────────

    #[test]
    fn test_profiles_len() {
        assert_eq!(PROFILES.len(), 6, "must have exactly 6 profiles (0..=5)");
    }

    #[test]
    fn test_profiles_sequential() {
        for (i, p) in PROFILES.iter().enumerate() {
            assert_eq!(p.level as usize, i, "PROFILES[{i}] has mismatched level");
        }
    }

    #[test]
    fn test_profiles_idle_stops_ksm() {
        assert_eq!(PROFILES[0].run, 0, "Idle profile must set run=0");
        for p in &PROFILES[1..=5] {
            assert!(p.run > 0, "Profile {} should have run>0", p.level);
        }
    }

    #[test]
    fn test_profiles_monotonic() {
        // Higher levels = strictly more aggressive or equal
        for i in 1..=5 {
            let prev = &PROFILES[i - 1];
            let cur = &PROFILES[i];
            assert!(
                cur.max_page_sharing >= prev.max_page_sharing,
                "max_page_sharing regressed at level {i}: {} < {}",
                cur.max_page_sharing,
                prev.max_page_sharing
            );
            assert!(
                cur.sleep_millisecs <= prev.sleep_millisecs,
                "sleep_millisecs increased at level {i}: {} > {}",
                cur.sleep_millisecs,
                prev.sleep_millisecs
            );
            assert!(
                cur.pages_to_scan >= prev.pages_to_scan,
                "pages_to_scan regressed at level {i}: {} < {}",
                cur.pages_to_scan,
                prev.pages_to_scan
            );
        }
    }

    // ── pressure_to_level ────────────────────────────────────────────

    #[test]
    fn test_pressure_to_level_idle() {
        let gov = make_gov();
        assert_eq!(
            gov.pressure_to_level(PressureLevel::Idle),
            0,
            "Idle maps to level 0 (scanner stopped)"
        );
    }

    #[test]
    fn test_pressure_to_level_low() {
        let gov = make_gov();
        assert_eq!(gov.pressure_to_level(PressureLevel::Low), 1);
    }

    #[test]
    fn test_pressure_to_level_medium_skips_2() {
        let gov = make_gov();
        // Medium maps to 3 (jumps over profile level 2, which is only
        // reached during ramp-down from Active/Higher)
        assert_eq!(gov.pressure_to_level(PressureLevel::Medium), 3);
    }

    #[test]
    fn test_pressure_to_level_high() {
        let gov = make_gov();
        assert_eq!(gov.pressure_to_level(PressureLevel::High), 4);
    }

    #[test]
    fn test_pressure_to_level_critical() {
        let gov = make_gov();
        assert_eq!(gov.pressure_to_level(PressureLevel::Critical), 5);
    }

    // ── compute_transition (ramp-up) ─────────────────────────────────

    #[test]
    fn test_ramp_up_single_level_requires_hysteresis() {
        let mut gov = make_gov_with(|c| c.hysteresis_readings = 3);
        gov.current_level = 0;

        // Tick 1: counting
        assert_eq!(
            gov.compute_transition(1),
            0,
            "single-level ramp-up must wait for hysteresis"
        );
        assert_eq!(gov.ramp_up_count, 1);

        // Tick 2: counting
        assert_eq!(gov.compute_transition(1), 0);
        assert_eq!(gov.ramp_up_count, 2);

        // Tick 3: threshold reached → ramp up
        assert_eq!(
            gov.compute_transition(1),
            1,
            "should ramp up after hysteresis readings"
        );
        assert_eq!(gov.ramp_up_count, 0, "ramp_up_count reset after ramp-up");
    }

    #[test]
    fn test_ramp_up_multi_level_is_immediate() {
        let mut gov = make_gov();
        gov.current_level = 0;
        let result = gov.compute_transition(3);
        assert_eq!(result, 3, "multi-level ramp-up must be immediate");
        assert_eq!(gov.hysteresis_count, 0);
        assert_eq!(gov.ramp_up_count, 0);
    }

    #[test]
    fn test_ramp_up_resets_full_scans_tracking() {
        let mut gov = make_gov();
        gov.current_level = 0;
        gov.full_scans_at_level = 999;
        let _ = gov.compute_transition(4);
        assert_eq!(
            gov.full_scans_at_level, 0,
            "full_scans_at_level reset on ramp-up"
        );
    }

    #[test]
    fn test_ramp_up_hysteresis_resets_on_same_level() {
        let mut gov = make_gov_with(|c| c.hysteresis_readings = 3);
        gov.current_level = 0;

        // Count 2 ticks toward ramp-up
        let _ = gov.compute_transition(1);
        let _ = gov.compute_transition(1);
        assert_eq!(gov.ramp_up_count, 2);

        // Pressure drops back to idle → same level resets ramp_up_count
        let _ = gov.compute_transition(0);
        assert_eq!(
            gov.ramp_up_count, 0,
            "ramp_up_count reset when target drops back"
        );

        // Must restart hysteresis from scratch
        assert_eq!(gov.compute_transition(1), 0);
        assert_eq!(gov.ramp_up_count, 1);
    }

    #[test]
    fn test_ramp_up_hysteresis_resets_on_ramp_down_midway() {
        let mut gov = make_gov_with(|c| {
            c.hysteresis_readings = 3;
            c.min_level_duration_secs = 0;
        });
        gov.current_level = 1;

        // Start ramp-up counting from 1→2
        let _ = gov.compute_transition(2);
        assert_eq!(gov.ramp_up_count, 1);

        // Pressure drops below current level → ramp-down logic, resets ramp_up_count
        let _ = gov.compute_transition(0);
        assert_eq!(
            gov.ramp_up_count, 0,
            "ramp_up_count reset by ramp-down direction"
        );
    }

    // ── compute_transition (same level) ──────────────────────────────

    #[test]
    fn test_same_level_resets_hysteresis() {
        let mut gov = make_gov();
        gov.current_level = 3;
        gov.hysteresis_count = 42; // some pending count
        let result = gov.compute_transition(3);
        assert_eq!(result, 3);
        assert_eq!(
            gov.hysteresis_count, 0,
            "hysteresis reset on same-level tick"
        );
    }

    // ── compute_transition (ramp-down with cooldown) ─────────────────

    #[test]
    fn test_ramp_down_cooldown_blocks() {
        // min_level_duration_secs=10, and level_entered_at was just set
        // (the Governor was constructed moments ago). Elapsed < 10s → blocked.
        let mut gov = make_gov_with(|c| c.min_level_duration_secs = 10);
        gov.current_level = 4;

        let result = gov.compute_transition(1);
        assert_eq!(result, 4, "cooldown should block ramp-down");
        assert_eq!(gov.hysteresis_count, 0, "cooldown: no hysteresis increment");
    }

    #[test]
    fn test_ramp_down_cooldown_bypassed_after_duration() {
        // min_level_duration_secs=0 → cooldown never blocks
        let mut gov = make_gov_with(|c| {
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 1;
        });
        gov.current_level = 3;

        let result = gov.compute_transition(1);
        // hysteresis_readings=1, so immediately steps down
        assert_eq!(result, 2, "should step down by 1");
    }

    // ── compute_transition (ramp-down with hysteresis) ───────────────

    #[test]
    fn test_ramp_down_hysteresis_counting() {
        let mut gov = make_gov_with(|c| {
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 3;
        });
        gov.current_level = 4;

        // Call 1: starts counting
        assert_eq!(gov.compute_transition(1), 4);
        assert_eq!(gov.hysteresis_count, 1);

        // Call 2: counting
        assert_eq!(gov.compute_transition(1), 4);
        assert_eq!(gov.hysteresis_count, 2);

        // Call 3: threshold reached → step down
        assert_eq!(gov.compute_transition(1), 3);
        assert_eq!(gov.hysteresis_count, 0);
    }

    #[test]
    fn test_ramp_down_steps_one_at_a_time() {
        let mut gov = make_gov_with(|c| {
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 1;
        });
        gov.current_level = 5;

        // Each call steps down by exactly 1, regardless of how far the
        // target is.
        let r1 = gov.compute_transition(0);
        assert_eq!(r1, 4);
        gov.current_level = r1;

        let r2 = gov.compute_transition(0);
        assert_eq!(r2, 3);
        gov.current_level = r2;

        let r3 = gov.compute_transition(0);
        assert_eq!(r3, 2);
    }

    // ── Idle (level 0) reachability ───────────────────────────────────

    /// Idle ticks needed for the 1 → 0 step with the production defaults
    /// (`hysteresis_readings = 4`, `IDLE_DWELL_FACTOR = 3`).
    const DEFAULT_IDLE_DWELL_TICKS: u32 = 4 * IDLE_DWELL_FACTOR;

    /// Drive the governor down from `start_level` to a stable level by feeding
    /// `pressure` for `ticks` ticks, applying each returned level.
    fn drive_to_idle(gov: &mut Governor, pressure: PressureLevel, ticks: u32) {
        let target = gov.pressure_to_level(pressure);
        for _ in 0..ticks {
            let next = gov.compute_transition(target);
            gov.current_level = next;
        }
    }

    #[test]
    fn test_idle_requires_sustained_dwell_then_reaches_level_zero() {
        // Defaults: hysteresis_readings = 4, min_level_duration_secs = 0 so the
        // cooldown does not gate this unit test.
        let mut gov = make_gov_with(|c| c.min_level_duration_secs = 0);
        gov.current_level = 1;

        let dwell = DEFAULT_IDLE_DWELL_TICKS;

        // Ordinary ramp-down hysteresis (4 readings) is NOT sufficient: the
        // step into level 0 must wait for the full idle dwell.
        for _ in 0..dwell - 1 {
            assert_eq!(
                gov.compute_transition(0),
                1,
                "level 0 must stay unreachable before the dwell completes"
            );
            gov.current_level = 1;
        }

        // The dwell-completing tick drops to level 0.
        assert_eq!(
            gov.compute_transition(0),
            0,
            "sustained idle must reach level 0"
        );
        assert_eq!(
            gov.idle_dwell_count, 0,
            "dwell counter reset after entering 0"
        );
    }

    #[test]
    fn test_idle_reachable_from_high_levels_via_ramp_down() {
        // A full ride from Emergency (5) down to Idle (0) under sustained idle
        // pressure. min_level_duration_secs = 0 keeps the test fast; the
        // cooldown path is covered separately.
        let mut gov = make_gov_with(|c| {
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 2;
        });
        gov.current_level = 5;

        // The step into level 0 needs hysteresis_readings * IDLE_DWELL_FACTOR
        // = 6 consecutive idle readings; the other steps need only 2 each, so
        // 24 idle ticks comfortably covers the whole descent.
        drive_to_idle(&mut gov, PressureLevel::Idle, 24);

        assert_eq!(
            gov.current_level, 0,
            "sustained idle must drive the governor all the way to level 0"
        );
    }

    #[test]
    fn test_boundary_oscillation_does_not_reach_level_zero() {
        // PSI hovering around the Idle/Low boundary: alternate Idle and Low
        // ticks. Under the old mapping both mapped to level 1 and the governor
        // never left level 1; now every Low tick must reset the idle dwell, so
        // the scanner can never be switched off by a flickering signal.
        let mut gov = make_gov_with(|c| {
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 2;
        });
        gov.current_level = 1;

        // 40 alternating ticks is far more than the 6-reading dwell, so this
        // sequence would reach level 0 if any non-idle tick failed to reset it.
        for _ in 0..40 {
            let idle_level = gov.compute_transition(0);
            assert_eq!(idle_level, 1, "single idle tick must not stop KSM");
            let low_level = gov.compute_transition(1);
            assert_eq!(low_level, 1, "level must be stable during oscillation");
            gov.current_level = 1;
        }
        assert_eq!(gov.current_level, 1);
        assert_eq!(
            gov.idle_dwell_count, 0,
            "the trailing Low tick must reset the idle dwell"
        );
    }

    #[test]
    fn test_low_alone_never_stops_ksm() {
        // Low maps to level 1, which equals the current level, so no dwell can
        // ever accumulate.
        let mut gov = make_gov_with(|c| c.min_level_duration_secs = 0);
        gov.current_level = 1;

        drive_to_idle(&mut gov, PressureLevel::Low, 100);

        assert_eq!(
            gov.current_level, 1,
            "Low pressure alone must keep scanning"
        );
        assert_eq!(gov.idle_dwell_count, 0);
    }

    #[test]
    fn test_idle_dwell_resets_after_single_interruption() {
        // Almost enough dwell, interrupted by one Low tick: the count must
        // start over from scratch rather than continuing.
        let mut gov = make_gov_with(|c| {
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 2;
        });
        gov.current_level = 1;

        let required = 2 * IDLE_DWELL_FACTOR; // 6

        // Accumulate three of the six required idle readings.
        for _ in 0..(required - 3) {
            assert_eq!(gov.compute_transition(0), 1);
        }
        assert_eq!(gov.idle_dwell_count, required - 3);

        // One Low reading wipes the progress.
        assert_eq!(gov.compute_transition(1), 1);
        assert_eq!(gov.idle_dwell_count, 0, "interrupted dwell must restart");

        // Now the full requirement must be met again before reaching level 0.
        for _ in 0..required - 1 {
            assert_eq!(
                gov.compute_transition(0),
                1,
                "dwell restarted, so level 0 must stay unreachable"
            );
        }
        assert_eq!(
            gov.compute_transition(0),
            0,
            "dwell complete after the restart"
        );
    }

    #[test]
    fn test_leaving_idle_still_requires_hysteresis() {
        // Exiting level 0 keeps the ordinary ramp-up hysteresis: pressure
        // flickering back above Idle cannot immediately restart the scanner.
        let mut gov = make_gov_with(|c| {
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 3;
        });
        gov.current_level = 0;

        assert_eq!(
            gov.compute_transition(1),
            0,
            "leaving idle needs hysteresis readings"
        );
        assert_eq!(gov.ramp_up_count, 1);
        assert_eq!(gov.compute_transition(1), 0);
        assert_eq!(
            gov.compute_transition(1),
            1,
            "third consecutive Low reading restarts scanning"
        );
    }

    #[test]
    fn test_idle_dwell_not_required_for_intermediate_steps() {
        // Ramping from 5 to 4 must not pay the idle-dwell tax: only the step
        // into level 0 does. hysteresis_readings = 1 keeps each step a single
        // tick so the comparison is unambiguous.
        let mut gov = make_gov_with(|c| {
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 1;
        });
        gov.current_level = 5;

        assert_eq!(gov.compute_transition(0), 4);
        gov.current_level = 4;
        assert_eq!(gov.compute_transition(0), 3);
        gov.current_level = 3;
        assert_eq!(gov.compute_transition(0), 2);
        gov.current_level = 2;
        assert_eq!(gov.compute_transition(0), 1);
    }

    #[test]
    fn test_emergency_ramp_up_overrides_pending_idle_dwell() {
        // A sudden spike must escape immediately even if an idle dwell was in
        // progress at level 1 — safety must not be delayed by the dwell.
        let mut gov = make_gov_with(|c| {
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 2;
        });
        gov.current_level = 1;
        gov.idle_dwell_count = 2;

        let result = gov.compute_transition(3); // 3 >= 1 + 2 → emergency jump
        assert_eq!(result, 3, "emergency ramp-up must bypass the idle dwell");
        assert_eq!(gov.idle_dwell_count, 0, "dwell discarded on emergency jump");
    }

    #[tokio::test]
    async fn test_sustained_idle_tick_reaches_level_zero_via_tick_with_readings() {
        // End-to-end through `tick_with_readings`: sustained idle PSI drives the
        // governor to level 0 and the shared state reports it.
        let mut gov = make_temp_gov_with(|c| {
            c.stabilization_secs = 0;
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 2;
        });
        gov.current_level = 1;
        let state = new_shared_state();

        // Below the 5.0 some-threshold and 0.5 score floor → classified Idle.
        // Step 2→1 needs 2 readings; 1→0 needs 2 * IDLE_DWELL_FACTOR = 6.
        for _ in 0..16 {
            gov.tick_with_readings(&state, psi(0.0, 0.1), ksm_stats(500, 100, 5))
                .await;
        }

        assert_eq!(
            gov.current_level, 0,
            "sustained idle PSI must drive the governor to level 0"
        );
        let s = state.read().await;
        assert_eq!(s.current_pressure, PressureLevel::Idle);
        assert_eq!(s.ksm_level, 0);
    }

    #[tokio::test]
    async fn test_oscillating_pressure_never_reaches_level_zero_via_tick() {
        // The same boundary flicker driven through the real tick path: the
        // shared level must stay pinned at 1 forever.
        let mut gov = make_temp_gov_with(|c| {
            c.stabilization_secs = 0;
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 2;
        });
        gov.current_level = 1;
        let state = new_shared_state();

        for _ in 0..30 {
            // Idle: score = 0.7*0.2 + 0.3*0.1 = 0.17 (< the 0.5 floor)
            gov.tick_with_readings(&state, psi(0.1, 0.2), ksm_stats(500, 100, 5))
                .await;
            assert_eq!(gov.current_level, 1, "idle tick must not stop KSM");

            // Low: score = 0.7*0.5 + 0.3*1.0 = 0.65 — just above the Idle floor,
            // i.e. exactly the boundary where a flickering signal would straddle.
            gov.tick_with_readings(&state, psi(1.0, 0.5), ksm_stats(500, 100, 5))
                .await;
            assert_eq!(gov.current_level, 1, "low tick must not stop KSM");
        }
    }

    #[test]
    fn test_emergency_ramp_up_overrides_pending_ramp_down() {
        let mut gov = make_gov_with(|c| {
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 5;
        });
        gov.current_level = 4;
        gov.level_entered_at = Instant::now() - Duration::from_secs(60);

        // Start ramping down (2 hysteresis ticks)
        let _ = gov.compute_transition(1);
        let _ = gov.compute_transition(1);
        assert_eq!(gov.hysteresis_count, 2);

        // Emergency: target=5 >= 4+2 is false, so this is single-level, needs hysteresis.
        // Instead, use target=5 from level 3 (5 >= 3+2 is true = multi-level jump).
        gov.current_level = 3;
        let r = gov.compute_transition(5); // 5 >= 3+2 → emergency immediate
        assert_eq!(r, 5, "emergency multi-level ramp-up must be immediate");
        assert_eq!(gov.hysteresis_count, 0, "hysteresis reset by ramp-up");
        assert_eq!(gov.ramp_up_count, 0, "ramp_up_count reset by ramp-up");
    }

    #[test]
    fn test_single_level_ramp_up_midway_resets_ramp_down() {
        let mut gov = make_gov_with(|c| {
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 1;
        });
        gov.current_level = 2;
        gov.level_entered_at = Instant::now() - Duration::from_secs(60);

        // Start ramping down (hysteresis_readings=1, so.steps down immediately)
        let r = gov.compute_transition(0);
        assert_eq!(r, 1); // steps down by 1 from 2
        gov.current_level = r;

        // Now target > current (3 > 1), 3 >= 1+2 → emergency jump
        let r2 = gov.compute_transition(3);
        assert_eq!(r2, 3, "multi-level jump is immediate");
        assert_eq!(gov.hysteresis_count, 0);
    }

    // ── apply_profile (dry-run) ──────────────────────────────────────

    #[tokio::test]
    async fn test_apply_profile_dry_run_changes_level() {
        let mut ksm = KsmController::new("/sys/kernel/mm/ksm").unwrap();
        ksm.set_dry_run(true);
        let mut gov = Governor::new(GovernorConfig::default(), ksm);
        let state = new_shared_state();

        assert_eq!(gov.current_level, 0);
        gov.apply_profile(3, &state).await;
        assert_eq!(gov.current_level, 3);
    }

    #[tokio::test]
    async fn test_apply_profile_updates_governor_action() {
        let mut ksm = KsmController::new("/sys/kernel/mm/ksm").unwrap();
        ksm.set_dry_run(true);
        let mut gov = Governor::new(GovernorConfig::default(), ksm);
        let state = new_shared_state();

        gov.apply_profile(2, &state).await;

        let s = state.read().await;
        assert!(
            s.last_governor_action.elapsed().as_secs() < 5,
            "last_governor_action should have been updated very recently"
        );
        assert!(
            s.last_global_action.elapsed().as_secs() < 5,
            "last_global_action telemetry should have been updated very recently"
        );
    }

    #[tokio::test]
    async fn test_apply_profile_idle_stops_ksm_manual_mode() {
        let mut ksm = KsmController::new("/sys/kernel/mm/ksm").unwrap();
        ksm.set_dry_run(true);
        let mut gov = Governor::new(
            GovernorConfig {
                use_advisor: false,
                ..GovernorConfig::default()
            },
            ksm,
        );
        let state = new_shared_state();

        // In manual mode, level 0 (Idle) should set run=0
        gov.apply_profile(0, &state).await;
        assert_eq!(gov.current_level, 0);
    }

    #[tokio::test]
    async fn test_apply_profile_idle_keeps_ksm_running_in_advisor_mode() {
        let mut ksm = KsmController::new("/sys/kernel/mm/ksm").unwrap();
        ksm.set_dry_run(true);
        let mut gov = Governor::new(GovernorConfig::default(), ksm);
        let state = new_shared_state();

        // In advisor mode, level 0 should NOT stop KSM — the advisor needs run=1
        gov.apply_profile(0, &state).await;
        assert_eq!(gov.current_level, 0);
        // The key difference: dry-run won't emit the "Would write KSM parameter run=0"
        // line because the set_run(0) call is skipped entirely when use_advisor=true.
    }

    /// Build a governor over a temp directory seeded with the KSM parameters
    /// `apply_profile` touches, wired to a real (non-dry-run) controller so the
    /// writes can be read back from disk.
    fn level_zero_gov(use_advisor: bool) -> (Governor, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        for (name, value) in [
            ("run", "1"),
            ("pages_to_scan", "500"),
            ("sleep_millisecs", "100"),
            ("max_page_sharing", "256"),
            ("advisor_mode", "scan-time"),
            ("advisor_target_scan_time", "200"),
            ("advisor_max_cpu", "70"),
            ("advisor_min_pages_to_scan", "500"),
            ("advisor_max_pages_to_scan", "30000"),
        ] {
            std::fs::write(dir.path().join(name), value).unwrap();
        }
        let mut ctrl = KsmController::new(&dir.path().to_string_lossy()).unwrap();
        // Prime the controller's rate limiter so the first write is not skipped.
        std::thread::sleep(Duration::from_millis(600));
        ctrl.set_dry_run(false);
        let gov = Governor::new(
            GovernorConfig {
                use_advisor,
                ksm_path: dir.path().to_string_lossy().to_string(),
                ..GovernorConfig::default()
            },
            ctrl,
        );
        (gov, dir)
    }

    #[tokio::test]
    async fn test_level_zero_in_advisor_mode_writes_bias_knobs_not_run() {
        // Level 0 must remain a *meaningful* state in advisor mode: the bias
        // knobs move to their level-0 values while `run` is left untouched so
        // the kernel advisor keeps working.
        let (mut gov, dir) = level_zero_gov(true);
        let state = new_shared_state();
        gov.current_level = 1;

        gov.apply_profile(0, &state).await;

        let read = |name: &str| {
            std::fs::read_to_string(dir.path().join(name))
                .unwrap()
                .trim()
                .to_string()
        };
        assert_eq!(gov.current_level, 0, "advisor mode must reach level 0");
        assert_eq!(read("run"), "1", "advisor mode must never write run=0");
        assert_eq!(
            read("max_page_sharing"),
            "256",
            "level 0 bias knob must be applied in advisor mode"
        );
        assert_eq!(
            read("sleep_millisecs"),
            "500",
            "level 0 bias knob must be applied in advisor mode"
        );
    }

    #[tokio::test]
    async fn test_level_zero_in_manual_mode_stops_scanner() {
        // Counterpart in manual mode: reaching level 0 must really write
        // `run = 0` and stop the scanner.
        let (mut gov, dir) = level_zero_gov(false);
        let state = new_shared_state();
        gov.current_level = 1;

        gov.apply_profile(0, &state).await;

        assert_eq!(gov.current_level, 0);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("run"))
                .unwrap()
                .trim(),
            "0",
            "manual mode must write run=0 at level 0"
        );
    }

    #[test]
    fn test_level_zero_profile_is_a_real_state_in_advisor_mode() {
        // Level 0 differs from level 1 in the knobs the governor actually owns
        // in advisor mode, so reaching it has a real effect rather than being a
        // silent no-op.
        assert_eq!(PROFILES[0].max_page_sharing, PROFILES[1].max_page_sharing);
        assert!(
            PROFILES[0].sleep_millisecs > PROFILES[1].sleep_millisecs,
            "level 0 must slow scanning relative to level 1"
        );
    }

    #[tokio::test]
    async fn test_apply_profile_manual_mode_writes_pages_to_scan_path() {
        let mut gov = make_temp_gov_with(|c| c.use_advisor = false);
        let state = new_shared_state();

        gov.apply_profile(2, &state).await;

        assert_eq!(gov.current_level, 2);
    }

    #[test]
    fn test_observe_psi_stability_counts_stable_and_resets_on_jump() {
        let mut gov = make_temp_gov_with(|_| {});

        gov.observe_psi_stability(&psi(1.0, 0.5));
        assert_eq!(gov.stable_psi_ticks, 0);

        gov.observe_psi_stability(&psi(1.2, 0.7));
        assert_eq!(gov.stable_psi_ticks, 1);

        gov.observe_psi_stability(&psi(3.0, 0.7));
        assert_eq!(gov.stable_psi_ticks, 0);
    }

    #[tokio::test]
    async fn test_tick_with_readings_applies_profile_and_updates_shared_state() {
        let mut gov = make_temp_gov_with(|c| {
            c.stabilization_secs = 30;
            c.min_level_duration_secs = 0;
        });
        let state = new_shared_state();
        {
            let mut s = state.write().await;
            s.last_governor_action = Instant::now() - Duration::from_secs(31);
        }

        gov.tick_with_readings(&state, psi(30.0, 25.0), ksm_stats(1234, 5678, 9))
            .await;

        assert_eq!(gov.current_level, 5);
        let s = state.read().await;
        assert_eq!(s.current_pressure, PressureLevel::Critical);
        assert_eq!(s.ksm_level, 5);
        assert_eq!(s.pages_sharing, 1234);
        assert_eq!(s.general_profit, 5678);
        assert!(s.last_governor_action.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_tick_with_readings_defers_profile_inside_stabilization_window() {
        let mut gov = make_temp_gov_with(|c| c.stabilization_secs = 30);
        let state = new_shared_state();
        {
            let mut s = state.write().await;
            s.last_governor_action = Instant::now();
        }

        gov.tick_with_readings(&state, psi(30.0, 25.0), ksm_stats(10, 20, 1))
            .await;

        assert_eq!(gov.current_level, 0);
        let s = state.read().await;
        assert_eq!(s.current_pressure, PressureLevel::Critical);
        assert_eq!(s.ksm_level, 0);
        assert_eq!(s.pages_sharing, 10);
        assert_eq!(s.general_profit, 20);
    }

    #[tokio::test]
    async fn test_tick_with_readings_reduces_level_on_sustained_negative_profit() {
        let mut gov = make_temp_gov_with(|c| {
            c.stabilization_secs = 0;
            c.min_level_duration_secs = 0;
        });
        let state = new_shared_state();
        gov.current_level = 4;
        gov.full_scans_at_level = 1;

        gov.tick_with_readings(&state, psi(12.0, 8.0), ksm_stats(10, -50, 20))
            .await;

        assert_eq!(gov.current_level, 3);
        let s = state.read().await;
        assert_eq!(s.ksm_level, 3);
        assert_eq!(s.general_profit, -50);
    }

    #[tokio::test]
    async fn test_run_exits_on_shutdown_signal() {
        let gov = make_temp_gov_with(|c| c.use_advisor = false);
        let state = new_shared_state();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = tokio::spawn(gov.run(state, shutdown_rx));
        shutdown_tx.send(true).unwrap();

        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    /// Seed a temp sysfs so its `sleep_millisecs` / `max_page_sharing` hold the
    /// values of the level-3 profile. Starting from a level-3 baseline means
    /// any later observation of level-4 values proves a write happened, rather
    /// than the level-3 file simply being left at its initial value.
    fn seed_level_three_params(dir: &std::path::Path) {
        std::fs::write(dir.join("sleep_millisecs"), "20").unwrap();
        std::fs::write(dir.join("max_page_sharing"), "512").unwrap();
    }

    fn read_param(dir: &std::path::Path, name: &str) -> String {
        std::fs::read_to_string(dir.join(name))
            .unwrap()
            .trim()
            .to_string()
    }

    // ── tick(): real PSI, real KSM stats, real sysfs ───────────────────

    /// `tick()` end-to-end against a real KSM directory: read the live PSI,
    /// classify it, drive the governor once, and require the resulting level
    /// *and* the sysfs files to match what the transition logic chose.
    ///
    /// Both PSI thresholds are set to 0.0, so classification collapses to
    /// `score >= 20 → Critical, else High` — the `full.avg10 >= 0.0` half of
    /// the High rule is always true. The test therefore cannot be perturbed by
    /// whatever pressure the host happens to be under, and never depends on a
    /// specific number from `/proc/pressure/memory`.
    #[tokio::test]
    async fn test_tick_applies_selected_profile_writes_sysfs_from_real_psi() {
        let (mut gov, dir) = seeded_gov(|c| {
            c.stabilization_secs = 0;
            c.psi_some_threshold = 0.0;
            c.psi_full_threshold = 0.0;
        });
        // Level 0 with a jump of at least two levels ramps immediately, so one
        // tick is enough to reach the classified target.
        gov.current_level = 0;
        seed_level_three_params(dir.path());
        let state = new_shared_state();

        // Read the same live PSI `tick()` will read, so the expected level is
        // derived rather than assumed.
        let psi_now = PsiStats::read_memory().expect("live PSI must be readable");
        let expected_pressure = psi_now.classify(0.0, 0.0);
        let expected_level = gov.pressure_to_level(expected_pressure);

        // The classify() rules above leave exactly one boundary — the 20.0
        // score separating Critical from High. If the host sits near it, the
        // tick's own reading could land on the other side of the boundary and
        // the assertion would be testing the read, not the governor. Skip in
        // that band, and also skip if a second read reclassifies differently.
        let score = 0.7 * psi_now.full.avg10 + 0.3 * psi_now.some.avg10;
        if (score - 20.0).abs() < 8.0 {
            return;
        }
        if PsiStats::read_memory()
            .expect("live PSI must be readable")
            .classify(0.0, 0.0)
            != expected_pressure
        {
            return;
        }

        gov.tick(&state).await;

        // The level the transition logic chose, reached through the real tick.
        assert_eq!(gov.current_level, expected_level);
        assert!(
            matches!(
                expected_pressure,
                PressureLevel::High | PressureLevel::Critical
            ),
            "zero thresholds must classify as High or Critical, got {expected_pressure:?}"
        );

        // The non-vacuity anchors: `tick()` must have actually read the KSM
        // stats, and propagated them into the shared state. These are values
        // that appear nowhere in the governor's logic.
        let s = state.read().await;
        assert_eq!(s.pages_sharing, 20, "tick must publish KSM pages_sharing");
        assert_eq!(s.general_profit, 4096, "tick must publish KSM profit");
        assert_eq!(s.current_pressure, expected_pressure);
        assert_eq!(s.ksm_level, expected_level);
        assert!(s.last_adjustment.elapsed() < Duration::from_secs(5));
        drop(s);

        // The selected profile must have been written to sysfs. In advisor
        // mode the governor owns only the two bias knobs, so `pages_to_scan`
        // must keep its seeded value — otherwise the daemon would be fighting
        // the kernel's advisor for that parameter.
        let profile = &PROFILES[expected_level as usize];
        assert_eq!(
            read_param(dir.path(), "sleep_millisecs"),
            profile.sleep_millisecs.to_string(),
            "profile {expected_level} sleep_millisecs must be applied"
        );
        assert_eq!(
            read_param(dir.path(), "max_page_sharing"),
            profile.max_page_sharing.to_string(),
            "profile {expected_level} max_page_sharing must be applied"
        );
        assert_eq!(
            read_param(dir.path(), "pages_to_scan"),
            "100",
            "advisor mode must not write pages_to_scan"
        );
    }

    /// `tick()` must return before touching anything when the KSM stats cannot
    /// be read: a missing sysfs directory is the daemon being run on a kernel
    /// without KSM, and publishing stale-looking zeros for a dead subsystem is
    /// worse than publishing nothing.
    #[tokio::test]
    async fn test_tick_aborts_without_mutating_state_when_ksm_reads_fail() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctrl = KsmController::new(&dir.path().to_string_lossy()).unwrap();
        ctrl.set_dry_run(false);
        let mut gov = Governor::new(GovernorConfig::default(), ctrl);

        // Preconditions that make this test non-vacuous: the KSM read must fail
        // (the code path under test) and the PSI read must succeed (otherwise
        // the tick would bail out earlier and every sentinel would trivially
        // survive, flattering the assertion).
        assert!(
            gov.ksm.read_stats().is_err(),
            "an empty KSM directory must fail the stats read"
        );
        assert!(
            PsiStats::read_memory().is_ok(),
            "PSI must be readable or this test proves nothing"
        );

        let state = new_shared_state();
        {
            let mut s = state.write().await;
            s.current_pressure = PressureLevel::High;
            s.ksm_level = 3;
            s.pages_sharing = 777;
            s.general_profit = -999;
            s.last_adjustment = Instant::now() - Duration::from_secs(10);
        }
        let last_adjustment_before = state.read().await.last_adjustment;

        gov.tick(&state).await;

        let s = state.read().await;
        assert_eq!(
            s.current_pressure,
            PressureLevel::High,
            "pressure must not be overwritten by a failed tick"
        );
        assert_eq!(s.ksm_level, 3);
        assert_eq!(s.pages_sharing, 777);
        assert_eq!(s.general_profit, -999);
        assert_eq!(
            s.last_adjustment, last_adjustment_before,
            "last_adjustment is written inside tick_with_readings, so its \
             survival proves the tick returned before that block"
        );
        // And the governor itself never saw a reading, so it never classified
        // or transitioned either.
        assert_eq!(gov.current_level, 0);
        assert!(gov.last_psi.is_none());
    }

    /// The negative-profit step-down, observed in sysfs rather than in RAM.
    ///
    /// `compact` loses its meaning if the governor stops at the level change
    /// without writing the new profile: the daemon's whole effect on the host
    /// is the sysfs writes, so an in-memory level change that never lands is a
    /// no-op for every other consumer.
    #[tokio::test]
    async fn test_negative_profit_step_down_writes_lower_profile_to_sysfs() {
        let (mut gov, dir) = seeded_gov(|c| {
            c.stabilization_secs = 0;
            c.hysteresis_readings = 2;
            // Keep the default 30 s `min_level_duration_secs`: the Idle
            // classification below wants to step 5 -> 4 via the ramp-down path,
            // which is blocked by that cooldown on the first tick. So any level
            // change observed here is attributable to the profit monitor and
            // nothing else.
        });
        gov.current_level = 5;
        gov.full_scans_at_level = 0;
        seed_level_three_params(dir.path());
        let state = new_shared_state();

        // Idle PSI (score 0.07) and a loss of 500 bytes well past the
        // 10-full-scan guard: the profit monitor must step down one level.
        gov.tick_with_readings(&state, psi(0.0, 0.1), ksm_stats(100, -500, 20))
            .await;

        assert_eq!(
            gov.current_level, 4,
            "negative profit after sustained scanning must reduce aggressiveness"
        );
        // The level-4 profile reached the kernel, not just the struct.
        assert_eq!(
            read_param(dir.path(), "sleep_millisecs"),
            "10",
            "level 4 sleep_millisecs must be written on step-down"
        );
        assert_eq!(
            read_param(dir.path(), "max_page_sharing"),
            "768",
            "level 4 max_page_sharing must be written on step-down"
        );
        assert_eq!(
            read_param(dir.path(), "pages_to_scan"),
            "100",
            "advisor mode must not write pages_to_scan"
        );

        let s = state.read().await;
        assert_eq!(s.ksm_level, 4);
        assert_eq!(s.general_profit, -500);
        assert_eq!(s.pages_sharing, 100);
    }

    /// When only the profit monitor moves the level, the stabilization window
    /// must not swallow the write either — a KSM run that loses memory while
    /// thrashing CPU cannot afford to wait for the cooldown to expire.
    #[tokio::test]
    async fn test_negative_profit_step_down_ignores_stabilization_window() {
        let (mut gov, dir) = seeded_gov(|c| {
            // A long window, and a governor action that just happened: every
            // stabilization path is closed.
            c.stabilization_secs = 3600;
            c.min_level_duration_secs = 3600;
            c.hysteresis_readings = 2;
        });
        gov.current_level = 5;
        gov.full_scans_at_level = 0;
        seed_level_three_params(dir.path());
        let state = new_shared_state();
        {
            let mut s = state.write().await;
            s.last_governor_action = Instant::now();
        }

        gov.tick_with_readings(&state, psi(30.0, 25.0), ksm_stats(100, -500, 20))
            .await;

        assert_eq!(gov.current_level, 4);
        assert_eq!(
            read_param(dir.path(), "sleep_millisecs"),
            "10",
            "the profit step-down must not be deferred by stabilization"
        );
    }

    /// Stabilization deferral, observed in sysfs.
    ///
    /// The existing test asserts only that the in-memory level and the shared
    /// state survived; this one pins the stronger property that the *files*
    /// still hold the old profile, so a deferred level change genuinely leaves
    /// the host untouched rather than writing a profile the governor will not
    /// report having applied.
    #[tokio::test]
    async fn test_stabilization_deferral_leaves_sysfs_files_untouched() {
        let (mut gov, dir) = seeded_gov(|c| c.stabilization_secs = 30);
        gov.current_level = 0;
        seed_level_three_params(dir.path());
        let state = new_shared_state();
        {
            let mut s = state.write().await;
            s.last_governor_action = Instant::now();
            s.last_global_action = Instant::now();
        }
        let governor_action_before = state.read().await.last_governor_action;

        // Score 26.5 → Critical → target 5 → a two-level jump from level 0, so
        // the transition is immediate and the only thing gating it is the
        // stabilization window.
        gov.tick_with_readings(&state, psi(30.0, 25.0), ksm_stats(10, 20, 1))
            .await;

        assert_eq!(
            gov.current_level, 0,
            "level must not move inside the window"
        );
        assert_eq!(
            read_param(dir.path(), "sleep_millisecs"),
            "20",
            "a deferred transition must not rewrite sysfs"
        );
        assert_eq!(
            read_param(dir.path(), "max_page_sharing"),
            "512",
            "a deferred transition must not rewrite sysfs"
        );

        let s = state.read().await;
        assert_eq!(s.current_pressure, PressureLevel::Critical);
        assert_eq!(s.ksm_level, 0);
        assert_eq!(s.pages_sharing, 10);
        assert_eq!(s.general_profit, 20);
        assert_eq!(
            s.last_governor_action, governor_action_before,
            "no profile write, so the governor timestamp must be untouched"
        );
        assert!(s.last_adjustment.elapsed() < Duration::from_secs(5));
    }

    // ── Fault injection: the kernel / proc boundary FAILS ──────────────
    //
    // Everything above drives the governor with readings handed to it. The
    // production loop reads those readings from two sources that can fail
    // independently: `/proc/pressure/memory` and the KSM sysfs directory.
    // The tests below pin what the governor does when one of them does.

    /// A missing PSI file must surface as `Err` — the governor's only cue to
    /// bail out. This is the exact shape `tick()` receives when
    /// `/proc/pressure/memory` cannot be opened, established through
    /// `PsiStats::read_from` (the same helper `read_memory` delegates to, with
    /// the live path swapped for a temp one).
    #[test]
    fn test_psi_read_from_missing_file_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("memory");

        let result = PsiStats::read_from(&missing);

        assert!(
            result.is_err(),
            "a missing PSI file must be an Err, otherwise tick() would act on zeros"
        );
        // Not a panic, and not a silently-defaulted struct either.
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("memory"),
            "the error must name the file it failed on, got: {err}"
        );
    }

    /// An *empty* PSI file is not an unreadable one, and the distinction
    /// matters: `tick()` only returns early on `Err`, so an empty file reaches
    /// the governor as all-zero readings. Documented here so the
    /// "empty != missing" contract cannot drift unnoticed — an empty file
    /// parses Ok with every field at zero.
    #[test]
    fn test_psi_read_from_empty_file_is_ok_with_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let psi_file = dir.path().join("memory");
        std::fs::write(&psi_file, "").unwrap();

        let stats = PsiStats::read_from(&psi_file).expect("an empty PSI file parses fine");
        assert_eq!(stats.some.avg10, 0.0);
        assert_eq!(stats.full.avg10, 0.0);
        assert_eq!(stats.some.total, 0);
        assert_eq!(stats.full.total, 0);
    }

    /// A PSI file whose lines cannot be parsed must not crash the governor.
    /// The parser is total over any text, so the governor sees zeros — which
    /// is the same shape as a stalled sensor, and is classified Idle rather
    /// than as pressure. (The parse contract is `tuned_common::psi`'s, but the
    /// governor is the consumer that must expect it.)
    #[test]
    fn test_psi_parse_garbage_yields_zeros_not_error() {
        let parsed = PsiStats::parse("some garbage\nfull nonsense\n").expect("garbage parses");

        assert_eq!(
            parsed.some.avg10, 0.0,
            "unparsed lines must not become pressure"
        );
        assert_eq!(parsed.full.avg10, 0.0);

        // And the governor's own view of that shape: zero-score readings are
        // Idle, so they classify to target level 0, never upward.
        let gov = make_temp_gov_with(|_| {});
        assert_eq!(parsed.classify(5.0, 2.0), PressureLevel::Idle);
        assert_eq!(
            gov.pressure_to_level(PressureLevel::Idle),
            0,
            "a stalled PSI sensor must map to Idle, not to aggressiveness"
        );
    }

    /// `PsiStats::default()` is the shape of a subsystem that reports nothing:
    /// every counter zero. The governor must treat it as Idle — score 0.0 is
    /// below the 0.5 floor — and therefore as target level 0, the profile that
    /// stops the scanner in manual mode. Driven through the real tick path, not
    /// just through `classify`, because the tick is what publishes it to shared
    /// state.
    #[tokio::test]
    async fn test_zero_psi_classifies_idle_and_maps_to_level_zero() {
        let mut gov = make_temp_gov_with(|c| {
            c.stabilization_secs = 0;
            c.min_level_duration_secs = 0;
        });
        gov.current_level = 1;
        let state = new_shared_state();

        gov.tick_with_readings(&state, PsiStats::default(), ksm_stats(10, 20, 1))
            .await;

        assert_eq!(
            PsiStats::default()
                .classify(gov.config.psi_some_threshold, gov.config.psi_full_threshold),
            PressureLevel::Idle,
            "all-zero PSI must classify Idle with the production thresholds"
        );
        assert_eq!(
            gov.pressure_to_level(PressureLevel::Idle),
            0,
            "Idle must map to level 0 (the run=0 profile)"
        );
        // Held at 1 by the idle dwell, but the *target* is 0, so the shared
        // pressure record says Idle and the dwell is accumulating.
        assert_eq!(gov.current_level, 1);
        assert_eq!(
            gov.idle_dwell_count, 1,
            "one zero reading accumulates dwell"
        );
        let s = state.read().await;
        assert_eq!(
            s.current_pressure,
            PressureLevel::Idle,
            "the tick must publish the classified pressure, not the raw score"
        );
    }

    /// Zero PSI held long enough must actually reach level 0 — the level-0
    /// profile stops the scanner, so a null sensor must not leave the daemon
    /// frozen at level 1 forever.
    #[tokio::test]
    async fn test_sustained_zero_psi_reaches_level_zero_via_tick() {
        let mut gov = make_temp_gov_with(|c| {
            c.stabilization_secs = 0;
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 2;
        });
        gov.current_level = 1;
        let state = new_shared_state();

        // 2 * IDLE_DWELL_FACTOR = 6 consecutive zero readings are required for
        // the 1 → 0 step; feed a comfortable margin.
        for _ in 0..12 {
            gov.tick_with_readings(&state, PsiStats::default(), ksm_stats(10, 20, 1))
                .await;
        }

        assert_eq!(
            gov.current_level, 0,
            "a persistently idle (zero) PSI sensor must reach level 0"
        );
        let s = state.read().await;
        assert_eq!(s.current_pressure, PressureLevel::Idle);
        assert_eq!(s.ksm_level, 0);
    }

    /// PSI flapping across the Idle/Low boundary must not move the level. This
    /// pins the debounce as a *mechanism*, not as an outcome: the assertions
    /// are on the state-machine counters after every flap, so removing the
    /// hysteresis/dwell logic fails the test even if the level happened to
    /// stay where it is.
    #[tokio::test]
    async fn test_psi_flapping_does_not_move_the_level() {
        let mut gov = make_temp_gov_with(|c| {
            c.stabilization_secs = 0;
            c.min_level_duration_secs = 0;
            c.hysteresis_readings = 2;
        });
        gov.current_level = 1;
        let state = new_shared_state();
        let action_before = state.read().await.last_governor_action;

        for tick in 0..12 {
            // Idle reading (score 0.07) then Low reading (score 0.65) — the
            // pair straddles the 0.5 classification floor.
            gov.tick_with_readings(&state, psi(0.0, 0.1), ksm_stats(10, 20, 1))
                .await;

            // The idle tick must not start stepping toward level 0 on its own.
            assert_eq!(gov.current_level, 1, "idle tick {tick} must not stop KSM");
            assert_eq!(
                gov.idle_dwell_count, 1,
                "a single idle reading is one dwell tick, not a decision"
            );
            assert_eq!(
                gov.ramp_up_count, 0,
                "flapping up and down must never accumulate ramp-up credit"
            );
            assert_eq!(
                gov.stable_psi_ticks, 0,
                "a flap larger than 0.5 in either PSI line must reset stability"
            );

            // The trailing Low tick resets the dwell, so the next idle tick
            // starts from one again rather than from two.
            gov.tick_with_readings(&state, psi(1.0, 0.5), ksm_stats(10, 20, 1))
                .await;
            assert_eq!(gov.current_level, 1, "low tick {tick} must not move either");
            assert_eq!(
                gov.idle_dwell_count, 0,
                "the Low reading must reset the idle dwell — this is the debounce"
            );
            assert_eq!(gov.ramp_up_count, 0);
            assert_eq!(gov.hysteresis_count, 0);
            assert_eq!(gov.stable_psi_ticks, 0);
        }

        // Non-vacuity: 12 flaps means 12 full idle readings accumulated, which
        // with hysteresis_readings = 2 would need only 6. The level never moved,
        // so what held it must have been the reset, not the count.
        assert_eq!(gov.current_level, 1);
        assert_eq!(
            state.read().await.last_governor_action,
            action_before,
            "no level change, so no profile write and no timestamp update"
        );
    }
}
