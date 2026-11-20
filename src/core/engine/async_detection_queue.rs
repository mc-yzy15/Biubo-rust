use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::config::settings::SharedSettings;
use crate::core::engine::waf_engine::{detect_request, DetectionResult};

#[derive(Debug, Clone)]
pub struct DetectionTask {
    pub request_id: String,
    pub host: String,
    pub url: String,
    pub method: String,
    pub headers: Arc<HashMap<String, String>>,
    pub cookies: Arc<HashMap<String, String>>,
    pub body: Arc<Vec<u8>>,
    pub args: Arc<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncDetectionResult {
    pub request_id: String,
    pub detection: DetectionResult,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Lock-free async detection queue using N independent mpsc channels
/// with atomic round-robin dispatch. Each worker exclusively owns its
/// own Receiver — no Mutex contention on the receive path.
#[derive(Default)]
struct DetectionQueueStats {
    submitted: AtomicUsize,
    completed: AtomicUsize,
    rejected: AtomicUsize,
    in_flight: AtomicUsize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionQueueSnapshot {
    pub capacity: usize,
    pub queued: usize,
    pub in_flight: usize,
    pub submitted: usize,
    pub completed: usize,
    pub rejected: usize,
}

pub struct AsyncDetectionQueue {
    senders: Vec<mpsc::Sender<DetectionTask>>,
    next_worker: AtomicUsize,
    stats: Arc<DetectionQueueStats>,
    #[cfg(test)]
    pub results: Arc<DashMap<String, AsyncDetectionResult>>,
}

impl AsyncDetectionQueue {
    /// Submit a detection task to the queue (non-blocking).
    ///
    /// Uses atomic round-robin to pick a target worker channel, then
    /// tries `try_send`. If that channel is full, falls through to the
    /// next worker. Returns an error only when *all* worker channels
    /// are full or closed.
    pub async fn submit(&self, task: DetectionTask) -> Result<(), String> {
        let worker_count = self.senders.len();
        if worker_count == 0 {
            return Err("No detection workers available".to_string());
        }

        let start = self.next_worker.fetch_add(1, Ordering::Relaxed) % worker_count;
        let mut task = Some(task);

        for i in 0..worker_count {
            let idx = (start + i) % worker_count;
            if let Some(t) = task.take() {
                match self.senders[idx].try_send(t) {
                    Ok(()) => {
                        self.stats.submitted.fetch_add(1, Ordering::Relaxed);
                        return Ok(());
                    }
                    Err(mpsc::error::TrySendError::Full(t)) => {
                        task = Some(t);
                        continue;
                    }
                    Err(mpsc::error::TrySendError::Closed(t)) => {
                        task = Some(t);
                        continue;
                    }
                }
            }
        }

        self.stats.rejected.fetch_add(1, Ordering::Relaxed);
        Err("All detection worker channels are full".to_string())
    }

    /// Snapshot queue pressure and lifetime counters without exposing request data.
    pub fn snapshot(&self) -> DetectionQueueSnapshot {
        let capacity = self.senders.iter().map(mpsc::Sender::max_capacity).sum();
        let available = self
            .senders
            .iter()
            .map(mpsc::Sender::capacity)
            .sum::<usize>();
        DetectionQueueSnapshot {
            capacity,
            queued: capacity.saturating_sub(available),
            in_flight: self.stats.in_flight.load(Ordering::Relaxed),
            submitted: self.stats.submitted.load(Ordering::Relaxed),
            completed: self.stats.completed.load(Ordering::Relaxed),
            rejected: self.stats.rejected.load(Ordering::Relaxed),
        }
    }

    #[cfg(test)]
    pub fn get_result(&self, request_id: &str) -> Option<AsyncDetectionResult> {
        self.results
            .get(request_id)
            .map(|entry| entry.value().clone())
    }

    #[cfg(test)]
    pub fn remove_result(&self, request_id: &str) {
        self.results.remove(request_id);
    }
}

/// Auto-detect a sensible worker count: physical cores − 2, minimum 1.
pub fn default_worker_count() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    cores.saturating_sub(2).max(1)
}

#[cfg(test)]
pub async fn detection_worker(
    mut receiver: mpsc::Receiver<DetectionTask>,
    settings: SharedSettings,
    results: Arc<DashMap<String, AsyncDetectionResult>>,
) {
    tracing::info!("Async detection worker started");

    loop {
        match receiver.recv().await {
            Some(task) => {
                let settings_snapshot = settings.read().clone();
                let request_id = task.request_id.clone();

                let detection = detect_request(
                    &task.url,
                    &task.method,
                    &task.headers,
                    &task.cookies,
                    &task.body,
                    &task.args,
                    &settings_snapshot,
                    &task.host,
                )
                .await;

                let result = AsyncDetectionResult {
                    request_id: request_id.clone(),
                    detection,
                    timestamp: chrono::Utc::now(),
                };

                tracing::debug!("Async detection completed for request: {}", request_id);

                results.insert(result.request_id.clone(), result);
            }
            None => {
                tracing::warn!("Detection worker channel closed, shutting down");
                break;
            }
        }
    }
}

/// Start N independent detection workers, each with its own lock-free
/// mpsc channel. Tasks are dispatched via atomic round-robin in
/// [`AsyncDetectionQueue::submit`].
pub fn start_async_detection_workers(
    worker_count: usize,
    queue_size: usize,
    settings: SharedSettings,
) -> AsyncDetectionQueue {
    let worker_count = worker_count.max(1);
    let per_worker_capacity = std::cmp::max(1, queue_size / worker_count);
    let mut senders = Vec::with_capacity(worker_count);
    let results = Arc::new(DashMap::new());
    let stats = Arc::new(DetectionQueueStats::default());

    for i in 0..worker_count {
        let (sender, receiver) = mpsc::channel::<DetectionTask>(per_worker_capacity);
        senders.push(sender);

        let settings_clone = settings.clone();
        let results_clone = results.clone();
        let stats_clone = stats.clone();

        tokio::spawn(async move {
            tracing::info!("Async detection worker {} started (lock-free)", i);
            let mut rx = receiver;

            loop {
                match rx.recv().await {
                    Some(task) => {
                        stats_clone.in_flight.fetch_add(1, Ordering::Relaxed);
                        let settings_snapshot = settings_clone.read().clone();
                        let request_id = task.request_id.clone();

                        let detection = detect_request(
                            &task.url,
                            &task.method,
                            &task.headers,
                            &task.cookies,
                            &task.body,
                            &task.args,
                            &settings_snapshot,
                            &task.host,
                        )
                        .await;

                        let result = AsyncDetectionResult {
                            request_id: request_id.clone(),
                            detection,
                            timestamp: chrono::Utc::now(),
                        };

                        tracing::debug!("Async detection completed for request: {}", request_id);

                        results_clone.insert(result.request_id.clone(), result);
                        stats_clone.in_flight.fetch_sub(1, Ordering::Relaxed);
                        stats_clone.completed.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {
                        tracing::warn!("Detection worker {} channel closed", i);
                        break;
                    }
                }
            }
        });
    }

    tracing::info!(
        "Started {} async detection workers (lock-free) with per-worker queue size {}",
        worker_count,
        per_worker_capacity
    );

    AsyncDetectionQueue {
        senders,
        next_worker: AtomicUsize::new(0),
        stats,
        #[cfg(test)]
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str) -> DetectionTask {
        DetectionTask {
            request_id: id.to_string(),
            host: "example.test".to_string(),
            url: "/".to_string(),
            method: "GET".to_string(),
            headers: Arc::new(HashMap::new()),
            cookies: Arc::new(HashMap::new()),
            body: Arc::new(Vec::new()),
            args: Arc::new(HashMap::new()),
        }
    }

    #[tokio::test]
    async fn snapshot_reports_capacity_depth_and_rejections() {
        let (sender, _receiver) = mpsc::channel(1);
        let queue = AsyncDetectionQueue {
            senders: vec![sender],
            next_worker: AtomicUsize::new(0),
            stats: Arc::new(DetectionQueueStats::default()),
            results: Arc::new(DashMap::new()),
        };

        assert_eq!(queue.snapshot().queued, 0);
        queue.submit(task("first")).await.unwrap();
        assert_eq!(queue.snapshot().queued, 1);
        assert!(queue.submit(task("second")).await.is_err());

        let snapshot = queue.snapshot();
        assert_eq!(snapshot.capacity, 1);
        assert_eq!(snapshot.queued, 1);
        assert_eq!(snapshot.submitted, 1);
        assert_eq!(snapshot.rejected, 1);
    }
}
