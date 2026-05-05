use std::collections::VecDeque;
use std::time::Instant;

use dashmap::DashMap;

use crate::config::settings::Settings;
use crate::data::storage::manager::get_db;

struct RateEntry {
    timestamps: VecDeque<Instant>,
}

static RATE_DATA: once_cell::sync::Lazy<DashMap<String, RateEntry>> =
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

    let count = {
        let mut entry = RATE_DATA
            .entry(ip.to_string())
            .or_insert_with(|| RateEntry {
                timestamps: VecDeque::new(),
            });

        while let Some(&front) = entry.timestamps.front() {
            if now.duration_since(front).as_secs_f64() > 1.0 {
                entry.timestamps.pop_front();
            } else {
                break;
            }
        }

        let current_count = entry.timestamps.len();

        if current_count >= settings.rate_ban_threshold as usize {
            entry.timestamps.clear();
            drop(entry);

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

        entry.timestamps.push_back(now);
        current_count + 1
    };

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

pub fn start_rate_gc_worker(gc_interval: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(gc_interval));
        let now = Instant::now();
        RATE_DATA.retain(|_, entry| {
            while let Some(&front) = entry.timestamps.front() {
                if now.duration_since(front).as_secs() > 2 {
                    entry.timestamps.pop_front();
                } else {
                    break;
                }
            }
            !entry.timestamps.is_empty()
        });
    });
}
