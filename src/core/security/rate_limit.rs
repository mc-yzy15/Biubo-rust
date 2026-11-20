use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use ahash::AHashSet;
use dashmap::DashMap;
use parking_lot::Mutex;

use crate::config::settings::Settings;
use crate::data::storage::manager::get_db;

struct RateEntry {
    timestamps: VecDeque<Instant>,
}

static RATE_DATA: once_cell::sync::Lazy<DashMap<String, Arc<Mutex<RateEntry>>>> =
    once_cell::sync::Lazy::new(DashMap::new);

/// CC attack detection window (seconds): distinct URLs / UAs are tracked
/// within this sliding window. Fixed by design decision (AGENTS.md).
const CC_WINDOW_SECS: u64 = 10;

/// Strikes (and idle CC windows) expire after this much inactivity.
const CC_STRIKE_TTL_SECS: u64 = 600;

/// Gray-zone violation counters expire after this much inactivity.
const GRAY_ZONE_TTL_SECS: u64 = 600;

/// Per-IP CC attack observation window.
///
/// Tracks distinct URLs and distinct User-Agents seen within a 10 second
/// window. Sets are bounded: once a set reaches its threshold we stop
/// inserting (membership is only counted, the exact content no longer
/// matters), which caps per-window memory at ~`cc_url_threshold` URLs and
/// ~`cc_ua_threshold` UAs.
struct CcWindow {
    window_start: Instant,
    last_seen: Instant,
    urls: AHashSet<String>,
    user_agents: AHashSet<String>,
    /// Accumulated CC-feature strikes. Persisted across window resets until
    /// the IP is banned or the entry expires via GC.
    strikes: u32,
}

impl CcWindow {
    fn new(now: Instant) -> Self {
        CcWindow {
            window_start: now,
            last_seen: now,
            urls: AHashSet::new(),
            user_agents: AHashSet::new(),
            strikes: 0,
        }
    }

    fn reset_window(&mut self, now: Instant) {
        self.window_start = now;
        self.urls.clear();
        self.user_agents.clear();
    }
}

static CC_DATA: once_cell::sync::Lazy<DashMap<String, Arc<Mutex<CcWindow>>>> =
    once_cell::sync::Lazy::new(DashMap::new);

/// Gray-zone repeat-offender state, fully independent from both the CC
/// channel (CC_DATA) and the rate-ban channel (RATE_DATA).
struct GrayZoneEntry {
    violations: u32,
    last_seen: Instant,
}

static GRAY_ZONE_DATA: once_cell::sync::Lazy<DashMap<String, Arc<Mutex<GrayZoneEntry>>>> =
    once_cell::sync::Lazy::new(DashMap::new);

#[derive(Debug, Clone, PartialEq)]
pub enum BlockReason {
    Banned,
    TemporaryBanned,
    RateLimit,
    GrayZoneBan,
}

pub struct RateLimitResult {
    pub blocked: bool,
    pub reason: Option<BlockReason>,
}

pub async fn check_rate_limit(ip: &str, host: &str, settings: &Settings) -> RateLimitResult {
    let db = get_db(host);

    if db.is_banned(ip) && !db.is_temporary_banned(ip) {
        return RateLimitResult {
            blocked: true,
            reason: Some(BlockReason::Banned),
        };
    }

    let now = Instant::now();

    // Check ban threshold and get current count atomically.
    // IMPORTANT: parking_lot::MutexGuard is !Send, so we must NOT hold it across .await.
    // We structure the inner block so guard is dropped before any async call.
    let should_ban = {
        let entry = RATE_DATA
            .entry(ip.to_string())
            .or_insert_with(|| {
                Arc::new(Mutex::new(RateEntry {
                    timestamps: VecDeque::new(),
                }))
            })
            .clone();

        let mut guard = entry.lock();

        // Remove expired timestamps (older than 1 second window)
        while let Some(&front) = guard.timestamps.front() {
            if now.duration_since(front).as_secs_f64() > 1.0 {
                guard.timestamps.pop_front();
            } else {
                break;
            }
        }

        let raw_count = guard.timestamps.len();
        if raw_count >= settings.rate_ban_threshold as usize {
            // Trigger ban: clear the counter; guard drops here.
            guard.timestamps.clear();
            drop(guard);
            // Signal caller to ban the IP (async call happens outside the !Send scope)
            (true, 0)
        } else {
            // Atomically record this request
            guard.timestamps.push_back(now);
            let count = guard.timestamps.len();
            drop(guard);
            (false, count)
        }
    };

    let (banned, count) = should_ban;

    if banned {
        db.ban_ip(
            ip,
            "Rate limit exceeded (Ban)",
            Some(settings.rate_ban_duration_min as u32),
        )
        .await;

        return RateLimitResult {
            blocked: true,
            reason: Some(BlockReason::Banned),
        };
    }

    if count > settings.rate_limit_per_sec as usize {
        // Gray zone: above the pass line (rate_limit_per_sec), below the
        // rate-ban threshold (e.g. 16-29 req/s with defaults 15/30).
        // Independent accumulation channel: each second that first crosses
        // the pass line counts as one violation; 5 violations -> 5 min ban.
        if count < settings.rate_ban_threshold as usize {
            let crossed_into_gray_zone = count == settings.rate_limit_per_sec as usize + 1;

            // IMPORTANT: guard is dropped before the async ban_ip call below.
            let gray_zone_ban = {
                let entry = GRAY_ZONE_DATA
                    .entry(ip.to_string())
                    .or_insert_with(|| {
                        Arc::new(Mutex::new(GrayZoneEntry {
                            violations: 0,
                            last_seen: now,
                        }))
                    })
                    .clone();

                let mut guard = entry.lock();
                guard.last_seen = now;
                if crossed_into_gray_zone {
                    guard.violations = guard.violations.saturating_add(1);
                }
                let violations = guard.violations;
                let reached_limit = violations >= settings.gray_zone_violation_limit as u32;
                if reached_limit {
                    // Reset the accumulator: the ban itself is handled by the
                    // independent ban channel below.
                    guard.violations = 0;
                }
                drop(guard);
                reached_limit
            };

            if gray_zone_ban {
                db.ban_ip(
                    ip,
                    "gray_zone_repeat_offender",
                    Some(settings.gray_zone_ban_duration_min as u32),
                )
                .await;
                tracing::warn!(
                    "[GRAY_ZONE] {} banned for repeated gray-zone violations ({} min)",
                    ip,
                    settings.gray_zone_ban_duration_min
                );
                return RateLimitResult {
                    blocked: true,
                    reason: Some(BlockReason::GrayZoneBan),
                };
            }
        }

        tracing::info!("[RATE] {} rate limited ({} req/s)", ip, count);
        return RateLimitResult {
            blocked: true,
            reason: Some(BlockReason::RateLimit),
        };
    }

    if db.is_temporary_banned(ip) {
        return RateLimitResult {
            blocked: true,
            reason: Some(BlockReason::TemporaryBanned),
        };
    }

    RateLimitResult {
        blocked: false,
        reason: None,
    }
}

/// Starts a background garbage-collection worker for expired rate-limit,
/// gray-zone and CC-strike entries.
///
/// # Design rationale: why `std::thread::spawn` instead of `tokio::task::spawn`
///
/// - This worker performs purely synchronous operations (DashMap iteration and
///   parking_lot::Mutex locking) with no `.await` points -- there is nothing
///   for the async runtime to schedule.
/// - Running it as a dedicated OS thread keeps long-lived, blocking GC work off
///   the tokio worker pool, preventing interference with async request handling.
/// - The sleeping loop (`std::thread::sleep`) would block a tokio task if spawned
///   inside the runtime, which is precisely what we want to avoid.
pub fn start_rate_gc_worker(gc_interval: u64) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(gc_interval));
            let now = Instant::now();
            RATE_DATA.retain(|_, entry| {
                let mut entry = entry.lock();
                while let Some(&front) = entry.timestamps.front() {
                    if now.duration_since(front).as_secs() > 2 {
                        entry.timestamps.pop_front();
                    } else {
                        break;
                    }
                }
                !entry.timestamps.is_empty()
            });

            // CC channel GC: idle windows are cleared after the 10s window,
            // strikes expire entirely after CC_STRIKE_TTL_SECS of inactivity.
            CC_DATA.retain(|_, entry| {
                let mut entry = entry.lock();
                let idle = now.duration_since(entry.last_seen).as_secs();
                if idle > CC_STRIKE_TTL_SECS {
                    return false;
                }
                if idle > CC_WINDOW_SECS {
                    entry.urls.clear();
                    entry.user_agents.clear();
                }
                true
            });

            // Gray-zone channel GC: independent from the other two channels.
            GRAY_ZONE_DATA.retain(|_, entry| {
                let entry = entry.lock();
                now.duration_since(entry.last_seen).as_secs() <= GRAY_ZONE_TTL_SECS
            });
        }
    });
}

/// Result type for CC attack detection.
pub struct CcAttackResult {
    pub is_attack: bool,
    pub strike_count: u32,
    pub should_ban: bool,
    pub reason: Option<BlockReason>,
}

/// Check for CC (Challenge Collapsar) attack patterns.
///
/// Design decision (AGENTS.md): within a 10 second window, if the number of
/// distinct URLs >= `cc_url_threshold` (default 50) AND the number of
/// distinct User-Agents >= `cc_ua_threshold` (default 10), one CC-feature
/// strike is recorded and the window resets. After `cc_strike_limit`
/// (default 3) accumulated strikes the IP must be banned (10 minutes).
///
/// This function is fully synchronous and never awaits; the caller performs
/// the async ban outside. The parking_lot guard is confined to an inner
/// block and dropped before returning.
pub fn check_cc_attack(
    ip: &str,
    url: &str,
    user_agent: &str,
    settings: &Settings,
) -> CcAttackResult {
    let url_threshold = settings.cc_url_threshold.max(1) as usize;
    let ua_threshold = settings.cc_ua_threshold.max(1) as usize;
    let strike_limit = settings.cc_strike_limit.max(1) as u32;

    let now = Instant::now();

    // IMPORTANT: parking_lot::MutexGuard is !Send; it is created and dropped
    // entirely inside this synchronous block.
    let (is_attack, strikes) = {
        let entry = CC_DATA
            .entry(ip.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(CcWindow::new(now))))
            .clone();

        let mut window = entry.lock();

        // Window expired -> reset (strikes are kept across resets).
        if now.duration_since(window.window_start).as_secs() > CC_WINDOW_SECS {
            window.reset_window(now);
        }
        window.last_seen = now;

        // Bounded insertion: stop once the set reached its threshold to cap
        // per-window memory. Length alone is enough for the decision below.
        if window.urls.len() < url_threshold {
            window.urls.insert(url.to_string());
        }
        if !user_agent.is_empty() && window.user_agents.len() < ua_threshold {
            window.user_agents.insert(user_agent.to_string());
        }

        if window.urls.len() >= url_threshold && window.user_agents.len() >= ua_threshold {
            // One CC feature detected: strike + reset window.
            window.strikes = window.strikes.saturating_add(1);
            window.reset_window(now);
            (true, window.strikes)
        } else {
            (false, window.strikes)
        }
    };

    if is_attack {
        let should_ban = strikes >= strike_limit;
        CcAttackResult {
            is_attack: true,
            strike_count: strikes,
            should_ban,
            reason: if should_ban {
                Some(BlockReason::Banned)
            } else {
                None
            },
        }
    } else {
        CcAttackResult {
            is_attack: false,
            strike_count: strikes,
            should_ban: false,
            reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_settings() -> Settings {
        Settings::default()
    }

    fn unique_test_ip() -> String {
        let id = uuid::Uuid::new_v4();
        let bytes = id.as_bytes();
        format!("10.{}.{}.{}", bytes[1], bytes[2], bytes[3])
    }

    /// Feed `n` requests with distinct URLs and `ua_count` rotating UAs,
    /// returning how many calls were flagged as CC attacks.
    fn feed_cc_traffic(
        ip: &str,
        n: usize,
        ua_count: usize,
        settings: &Settings,
    ) -> Vec<CcAttackResult> {
        (0..n)
            .map(|i| {
                let url = format!("/path/{}", i);
                let ua = format!("UA-{}", i % ua_count);
                check_cc_attack(ip, &url, &ua, settings)
            })
            .collect()
    }

    #[test]
    fn cc_window_diversity_marks_strike() {
        let settings = test_settings(); // 50 urls / 10 uas / 3 strikes
        let ip = "10.99.0.1";

        let results = feed_cc_traffic(ip, 60, 12, &settings);
        let attacks: Vec<_> = results.iter().filter(|r| r.is_attack).collect();

        assert_eq!(attacks.len(), 1, "exactly one strike within one window");
        assert_eq!(attacks[0].strike_count, 1);
        assert!(!attacks[0].should_ban, "first strike must not ban");
    }

    #[test]
    fn cc_three_strikes_trigger_ban() {
        let settings = test_settings();
        let ip = "10.99.0.2";

        let mut last_attack = None;
        for round in 0..3 {
            let results = feed_cc_traffic(ip, 60, 12, &settings);
            let attacks: Vec<(u32, bool)> = results
                .iter()
                .filter(|r| r.is_attack)
                .map(|r| (r.strike_count, r.should_ban))
                .collect();
            assert_eq!(attacks.len(), 1, "round {} must yield one strike", round);
            assert_eq!(attacks[0].0, (round + 1) as u32);
            last_attack = Some(attacks[0]);
        }

        let (strike_count, should_ban) = last_attack.unwrap();
        assert_eq!(strike_count, 3);
        assert!(should_ban, "3 accumulated strikes must ban");
    }

    #[test]
    fn cc_window_expiry_resets_diversity() {
        let settings = test_settings();
        let ip = "10.99.0.3";

        // Fill the window below thresholds.
        for i in 0..40 {
            let result = check_cc_attack(ip, &format!("/a/{}", i), "UA-0", &settings);
            assert!(!result.is_attack);
        }

        // Force window expiry by rewinding window_start (test-only access).
        {
            let entry = CC_DATA.get(ip).unwrap();
            let mut window = entry.value().lock();
            window.window_start = Instant::now() - Duration::from_secs(CC_WINDOW_SECS + 1);
        }

        // Next request resets the window: previous diversity is discarded.
        for i in 0..40 {
            let result = check_cc_attack(ip, &format!("/b/{}", i), "UA-0", &settings);
            assert!(
                !result.is_attack,
                "expired window must restart diversity counting"
            );
            assert_eq!(result.strike_count, 0);
        }
    }

    #[test]
    fn cc_normal_traffic_not_flagged() {
        let settings = test_settings();
        let ip = "10.99.0.4";

        // Few URLs, single UA: well below thresholds.
        for i in 0..200 {
            let result = check_cc_attack(ip, &format!("/page/{}", i % 5), "Mozilla/5.0", &settings);
            assert!(!result.is_attack);
            assert!(!result.should_ban);
        }
    }

    /// Helper: clear the 1-second sliding window for an IP so bursts do not
    /// need real-time sleeps between them.
    fn reset_rate_window(ip: &str) {
        if let Some(entry) = RATE_DATA.get(ip) {
            entry.value().lock().timestamps.clear();
        }
    }

    #[tokio::test]
    async fn gray_zone_five_violations_trigger_ban() {
        let mut settings = test_settings();
        settings.rate_limit_per_sec = 2;
        settings.rate_ban_threshold = 6;
        settings.gray_zone_violation_limit = 5;
        settings.gray_zone_ban_duration_min = 5;

        // Storage bans persist across test runs, so use a unique IP to keep
        // this test independent from prior runs and developer data.
        let ip = unique_test_ip();
        let host = "gray-zone-test.local";

        for round in 0..5 {
            // Burst of 3 requests: counts 1, 2 pass; count 3 crosses the
            // pass line (rate_limit_per_sec + 1) -> one gray-zone violation.
            let mut last = None;
            for _ in 0..3 {
                last = Some(check_rate_limit(&ip, host, &settings).await);
            }
            let last = last.unwrap();
            reset_rate_window(&ip);

            if round < 4 {
                assert_eq!(
                    last.reason,
                    Some(BlockReason::RateLimit),
                    "round {} should be rate-limited, not banned",
                    round
                );
            } else {
                assert_eq!(
                    last.reason,
                    Some(BlockReason::GrayZoneBan),
                    "5th violation must trigger gray-zone ban"
                );
            }
        }

        // Ban must be recorded in storage (5 minute duration ban).
        let db = get_db(host);
        assert!(db.is_banned(&ip));
    }

    #[tokio::test]
    async fn gray_zone_normal_traffic_not_punished() {
        let settings = test_settings();
        let ip = unique_test_ip();
        let host = "gray-zone-normal.local";

        // 10 requests within the pass line (default rate_limit_per_sec = 15).
        for _ in 0..10 {
            let result = check_rate_limit(&ip, host, &settings).await;
            assert!(!result.blocked);
            assert_eq!(result.reason, None);
        }

        // No gray-zone accumulation must have happened.
        let entry = GRAY_ZONE_DATA.get(&ip);
        assert!(entry.is_none() || entry.unwrap().value().lock().violations == 0);
    }
}
