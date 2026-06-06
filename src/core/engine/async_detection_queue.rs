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
pub struct AsyncDetectionQueue {
    senders: Vec<mpsc::Sender<DetectionTask>>,
    next_worker: AtomicUsize,
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
                    Ok(()) => return Ok(()),
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

        Err("All detection worker channels are full".to_string())
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
    let per_worker_capacity = std::cmp::max(1, queue_size / worker_count);
    let mut senders = Vec::with_capacity(worker_count);
    let results = Arc::new(DashMap::new());

    for i in 0..worker_count {
        let (sender, receiver) = mpsc::channel::<DetectionTask>(per_worker_capacity);
        senders.push(sender);

        let settings_clone = settings.clone();
        let results_clone = results.clone();

        tokio::spawn(async move {
            tracing::info!("Async detection worker {} started (lock-free)", i);
            let mut rx = receiver;

            loop {
                match rx.recv().await {
                    Some(task) => {
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

                        tracing::debug!(
                            "Async detection completed for request: {}",
                            request_id
                        );

                        results_clone.insert(result.request_id.clone(), result);
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
        #[cfg(test)]
        results,
    }
}
