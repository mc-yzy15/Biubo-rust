use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::Mutex;

use crate::config::settings::Settings;
use crate::data::storage::manager::get_db;

// ---------------------------------------------------------------------------
// Task 3.1: Sliding-log rate limiter with gray-zone escalation
// ---------------------------------------------------------------------------

/// Sliding-window rate entry per IP.
///
/// - `timestamps`: request arrival times within the sliding window (1 s).
/// - `gray_violations`: how many times this IP entered the gray zone
///   (between `rate_limit_per_sec` and `rate_ban_threshold`).
/// - `banned_until`: if set, the IP is gray-banned until this instant.
struct RateEntry {
    timestamps: VecDeque<Instant>,
    gray_violations: u32,
    banned_until: Option<Instant>,
}

/// Gray-zone violation threshold → triggers a 5-minute ban.
const GRAY_VIOLATION_LIMIT: u32 = 5;
/// Gray-zone ban duration in seconds (5 minutes).
const GRAY_BAN_DURATION_SECS: u64 = 300;

static RATE_DATA: once_cell::sync::Lazy<DashMap<String, Arc<Mutex<RateEntry>>>> =
    once_cell::sync::Lazy::new(DashMap::new);

// ---------------------------------------------------------------------------
// Task 3.2: CC attack detection
// ---------------------------------------------------------------------------

/// Per-IP CC attack tracker.
///
/// Tracks URLs and User-Agents within a 10-second sliding window.
/// If unique URLs ≥ 50 AND unique UAs ≥ 10, a CC attack pattern is detected.
struct CcTracker {
    urls: Vec<String>,
    uas: Vec<String>,
    timestamps: VecDeque<Instant>,
    cc_violations: u32,
    banned_until: Option<Instant>,
}

impl CcTracker {
    fn new() -> Self {
        CcTracker {
            urls: Vec::new(),
            uas: Vec::new(),
            timestamps: VecDeque::new(),
            cc_violations: 0,
            banned_until: None,
        }
    }
}

/// CC detection window in seconds.
const CC_WINDOW_SECS: u64 = 10;
/// Unique-URL threshold for CC detection.
const CC_URL_THRESHOLD: usize = 50;
/// Unique-UA threshold for CC detection.
const CC_UA_THRESHOLD: usize = 10;
/// CC violation count that triggers a ban.
const CC_VIOLATION_LIMIT: u32 = 3;
/// CC ban duration in seconds (10 minutes).
const CC_BAN_DURATION_SECS: u64 = 600;

static CC_TRACKERS: once_cell::sync::Lazy<DashMap<String, Arc<Mutex<CcTracker>>>> =
    once_cell::sync::Lazy::new(DashMap::new);

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum BlockReason {
    Banned,
    TemporaryBanned,
    RateLimit,
    GrayZoneBan,
    CcAttack,
}

pub struct RateLimitResult {
    pub blocked: bool,
    pub reason: Option<BlockReason>,
}

pub struct CcCheckResult {
    pub blocked: bool,
    pub reason: Option<BlockReason>,
}

// ---------------------------------------------------------------------------
// Task 3.1: Sliding-log rate limit check
// ---------------------------------------------------------------------------

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
    let action = {
        let entry = RATE_DATA
            .entry(ip.to_string())
            .or_insert_with(|| {
                Arc::new(Mutex::new(RateEntry {
                    timestamps: VecDeque::new(),
                    gray_violations: 0,
                    banned_until: None,
                }))
            })
            .clone();

        let mut guard = entry.lock();

        // Check if currently gray-banned
        if let Some(until) = guard.banned_until {
            if now < until {
                let remaining = until.duration_since(now).as_secs();
                drop(guard);
                tracing::info!(
                    "[RATE] {} gray-zone banned (remaining {}s)",
                    ip,
                    remaining
                );
                return RateLimitResult {
                    blocked: true,
                    reason: Some(BlockReason::GrayZoneBan),
                };
            }
            // Ban expired, reset
            guard.banned_until = None;
            guard.gray_violations = 0;
        }

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
            // Hard ban threshold hit: clear timestamps, signal ban
            guard.timestamps.clear();
            drop(guard);
            RateAction::HardBan
        } else {
            // Record this request
            guard.timestamps.push_back(now);
            let count = guard.timestamps.len();

            if count > settings.rate_limit_per_sec as usize {
                // In the gray zone (between rate_limit_per_sec and rate_ban_threshold)
                guard.gray_violations += 1;
                let violations = guard.gray_violations;

                if violations >= GRAY_VIOLATION_LIMIT {
                    // Escalate to gray-zone ban
                    guard.banned_until = Some(now + std::time::Duration::from_secs(GRAY_BAN_DURATION_SECS));
                    guard.timestamps.clear();
                    drop(guard);
                    tracing::warn!(
                        "[RATE] {} gray-zone escalated to {}s ban ({} violations)",
                        ip,
                        GRAY_BAN_DURATION_SECS,
                        violations
                    );
                    RateAction::GrayBan
                } else {
                    drop(guard);
                    tracing::info!(
                        "[RATE] {} in gray zone ({} req/s, violation {}/{})",
                        ip,
                        count,
                        violations,
                        GRAY_VIOLATION_LIMIT
                    );
                    RateAction::RateLimit(count)
                }
            } else {
                drop(guard);
                RateAction::Pass
            }
        }
    };

    match action {
        RateAction::HardBan => {
            db.ban_ip(
                ip,
                "Rate limit exceeded (Ban)",
                Some(settings.rate_ban_duration_min as u32),
            )
            .await;

            RateLimitResult {
                blocked: true,
                reason: Some(BlockReason::Banned),
            }
        }
        RateAction::GrayBan => RateLimitResult {
            blocked: true,
            reason: Some(BlockReason::GrayZoneBan),
        },
        RateAction::RateLimit(_count) => RateLimitResult {
            blocked: true,
            reason: Some(BlockReason::RateLimit),
        },
        RateAction::Pass => {
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
    }
}

enum RateAction {
    HardBan,
    GrayBan,
    RateLimit(usize),
    Pass,
}

// ---------------------------------------------------------------------------
// Task 3.2: CC attack detection
// ---------------------------------------------------------------------------

/// Check whether the given IP exhibits CC attack characteristics.
///
/// Call this from `proxy.rs` **before** the WAF engine check, passing the
/// request URL and User-Agent so the tracker can maintain a sliding window.
///
/// Returns `CcCheckResult` indicating whether the IP should be blocked.
pub fn check_cc_attack(ip: &str, url: &str, user_agent: &str) -> CcCheckResult {
    let now = Instant::now();

    let entry = CC_TRACKERS
        .entry(ip.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(CcTracker::new())))
        .clone();

    let mut guard = entry.lock();

    // Check if currently CC-banned
    if let Some(until) = guard.banned_until {
        if now < until {
            return CcCheckResult {
                blocked: true,
                reason: Some(BlockReason::CcAttack),
            };
        }
        // Ban expired, reset
        guard.banned_until = None;
        guard.cc_violations = 0;
    }

    // Evict entries outside the 10-second window
    while let Some(&front) = guard.timestamps.front() {
        if now.duration_since(front).as_secs() >= CC_WINDOW_SECS {
            guard.timestamps.pop_front();
            if let Some(url) = guard.urls.pop() {
                let _ = url; // evict
            }
            if let Some(ua) = guard.uas.pop() {
                let _ = ua; // evict
            }
        } else {
            break;
        }
    }

    // Record current request
    guard.urls.push(url.to_string());
    guard.uas.push(user_agent.to_string());
    guard.timestamps.push_back(now);

    // Compute unique counts
    let unique_urls = guard.urls.iter().collect::<HashSet<_>>().len();
    let unique_uas = guard.uas.iter().collect::<HashSet<_>>().len();

    if unique_urls >= CC_URL_THRESHOLD && unique_uas >= CC_UA_THRESHOLD {
        guard.cc_violations += 1;
        let violations = guard.cc_violations;

        if violations >= CC_VIOLATION_LIMIT {
            guard.banned_until = Some(now + std::time::Duration::from_secs(CC_BAN_DURATION_SECS));
            tracing::warn!(
                "[CC] {} CC attack ban triggered ({} violations, {} unique URLs, {} unique UAs)",
                ip,
                violations,
                unique_urls,
                unique_uas
            );
            CcCheckResult {
                blocked: true,
                reason: Some(BlockReason::CcAttack),
            }
        } else {
            tracing::info!(
                "[CC] {} CC pattern detected (violation {}/{}, {} unique URLs, {} unique UAs)",
                ip,
                violations,
                CC_VIOLATION_LIMIT,
                unique_urls,
                unique_uas
            );
            CcCheckResult {
                blocked: false,
                reason: None,
            }
        }
    } else {
        CcCheckResult {
            blocked: false,
            reason: None,
        }
    }
}

// ---------------------------------------------------------------------------
// GC workers
// ---------------------------------------------------------------------------

/// Starts a background garbage-collection worker for expired rate-limit entries.
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

            // GC rate-limit entries
            RATE_DATA.retain(|_, entry| {
                let mut entry = entry.lock();

                // Check if gray ban has expired
                if let Some(until) = entry.banned_until {
                    if now >= until {
                        entry.banned_until = None;
                        entry.gray_violations = 0;
                    }
                }

                while let Some(&front) = entry.timestamps.front() {
                    if now.duration_since(front).as_secs() > 2 {
                        entry.timestamps.pop_front();
                    } else {
                        break;
                    }
                }

                // Keep entry if it has active timestamps or an active ban
                !entry.timestamps.is_empty() || entry.banned_until.is_some()
            });

            // GC CC tracker entries
            CC_TRACKERS.retain(|_, entry| {
                let mut entry = entry.lock();

                // Check if CC ban has expired
                if let Some(until) = entry.banned_until {
                    if now >= until {
                        entry.banned_until = None;
                        entry.cc_violations = 0;
                    }
                }

                // Evict expired timestamps and their corresponding URL/UA entries
                while let Some(&front) = entry.timestamps.front() {
                    if now.duration_since(front).as_secs() >= CC_WINDOW_SECS {
                        entry.timestamps.pop_front();
                        entry.urls.pop();
                        entry.uas.pop();
                    } else {
                        break;
                    }
                }

                // Keep entry if it has active data or an active ban
                !entry.timestamps.is_empty() || entry.banned_until.is_some()
            });
        }
    });
}
