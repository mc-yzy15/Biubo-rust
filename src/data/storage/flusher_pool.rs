use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::data::storage::storage_utils;

struct FlushEntry {
    data: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    dirty: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    path: PathBuf,
    auto_backup: bool,
    max_backup: usize,
}

/// Shared flusher pool that replaces per-Database dedicated OS threads.
///
/// N worker threads (default = CPU count) handle flushing for all registered
/// databases. Reduces OS threads from O(databases) to O(CPU cores).
pub struct FlusherPool {
    registry: Arc<Mutex<Vec<FlushEntry>>>,
}

/// Dropping this handle marks the database as dead so the pool skips it.
pub struct FlushHandle {
    alive: Arc<AtomicBool>,
}

impl FlushHandle {
    fn new(alive: Arc<AtomicBool>) -> Self {
        Self { alive }
    }
}

impl Drop for FlushHandle {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
    }
}

impl FlusherPool {
    pub fn new(worker_count: usize, flush_interval: Duration) -> Self {
        let registry: Arc<Mutex<Vec<FlushEntry>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        for i in 0..worker_count {
            let reg = registry.clone();
            let stp = stop.clone();

            let _handle = std::thread::Builder::new()
                .name(format!("flusher-{}", i))
                .spawn(move || loop {
                    if stp.load(Ordering::Acquire) {
                        break;
                    }
                    std::thread::sleep(flush_interval);
                    if stp.load(Ordering::Acquire) {
                        break;
                    }

                    let batch: Vec<(
                        Arc<Mutex<HashMap<String, serde_json::Value>>>,
                        Arc<AtomicBool>,
                        PathBuf,
                        bool,
                        usize,
                    )> = {
                        let mut guard = reg.lock();
                        guard.retain(|e| e.alive.load(Ordering::Acquire));
                        guard
                            .iter()
                            .filter(|e| e.dirty.load(Ordering::Acquire))
                            .map(|e| {
                                (
                                    e.data.clone(),
                                    e.dirty.clone(),
                                    e.path.clone(),
                                    e.auto_backup,
                                    e.max_backup,
                                )
                            })
                            .collect()
                    };

                    for entry in batch {
                        let guard = entry.0.lock();
                        if entry.3 {
                            let _ = storage_utils::create_backup(&entry.2, entry.4);
                        }
                        if let Err(e) = storage_utils::write_to_disk(&guard, &entry.2) {
                            tracing::error!("[FlusherPool] Flush error {:?}: {}", entry.2, e);
                        }
                        entry.1.store(false, Ordering::Release);
                    }
                })
                .expect("Failed to spawn flusher worker");
        }

        Self {
            registry,
        }
    }

    pub fn register(
        &self,
        data: Arc<Mutex<HashMap<String, serde_json::Value>>>,
        dirty: Arc<AtomicBool>,
        path: PathBuf,
        auto_backup: bool,
        max_backup: usize,
    ) -> FlushHandle {
        let alive = Arc::new(AtomicBool::new(true));
        self.registry.lock().push(FlushEntry {
            data,
            dirty,
            alive: alive.clone(),
            path,
            auto_backup,
            max_backup,
        });
        FlushHandle::new(alive)
    }

}

// Global singleton: lazily initialized with CPU-count workers.
static POOL: std::sync::OnceLock<FlusherPool> = std::sync::OnceLock::new();

pub fn global_pool() -> &'static FlusherPool {
    POOL.get_or_init(|| {
        let count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .max(2);
        FlusherPool::new(count, Duration::from_secs(5))
    })
}
