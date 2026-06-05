use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::Mutex;

use crate::config::settings::Settings;
use crate::data::storage::manager::get_db;
use crate::error::WafError;

struct RateEntry {
    timestamps: VecDeque<Instant>,
}

static RATE_DATA: once_cell::sync::Lazy<DashMap<String, Arc<Mutex<RateEntry>>>> =
    once_cell::sync::Lazy::new(DashMap::new);

#[derive(Debug, Clone, PartialEq)]
pub enum BlockReason {
    Banned,
    TemporaryBanned,
    RateLimit,
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
        }
    });
}
