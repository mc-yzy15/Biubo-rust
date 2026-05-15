use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::config::settings::Settings;
use crate::core::engine::waf_engine::{detect_request, DetectionResult};

#[derive(Debug, Clone)]
pub struct DetectionTask {
    pub request_id: String,
    pub host: String,
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub body: Vec<u8>,
    pub args: HashMap<String, String>,
    pub client_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncDetectionResult {
    pub request_id: String,
    pub detection: DetectionResult,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct AsyncDetectionQueue {
    sender: mpsc::Sender<DetectionTask>,
    pub results: Arc<DashMap<String, AsyncDetectionResult>>,
}

impl AsyncDetectionQueue {
    pub fn new(queue_size: usize) -> (Self, mpsc::Receiver<DetectionTask>) {
        let (sender, receiver) = mpsc::channel::<DetectionTask>(queue_size);
        let results = Arc::new(DashMap::new());

        let queue = Self { sender, results };
        (queue, receiver)
    }

    pub async fn submit(&self, task: DetectionTask) -> Result<(), String> {
        self.sender
            .send(task)
            .await
            .map_err(|e| format!("Failed to submit detection task: {}", e))
    }

    pub fn get_result(&self, request_id: &str) -> Option<DetectionResult> {
        self.results
            .get(request_id)
            .map(|entry| entry.detection.clone())
    }

    pub fn remove_result(&self, request_id: &str) {
        self.results.remove(request_id);
    }
}

pub async fn detection_worker(
    mut receiver: mpsc::Receiver<DetectionTask>,
    settings: Arc<parking_lot::RwLock<Settings>>,
    results: Arc<DashMap<String, AsyncDetectionResult>>,
) {
    tracing::info!("Async detection worker started");

    loop {
        match receiver.recv().await {
            Some(task) => {
                let settings_clone = settings.read().clone();
                let results_clone = results.clone();
                let request_id = task.request_id.clone();

                tokio::spawn(async move {
                    let detection = detect_request(
                        &task.url,
                        &task.method,
                        &task.headers,
                        &task.cookies,
                        &task.body,
                        &task.args,
                        &settings_clone,
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
                });
            }
            None => {
                tracing::warn!("Detection worker channel closed, shutting down");
                break;
            }
        }
    }
}

pub fn start_async_detection_workers(
    worker_count: usize,
    queue_size: usize,
    settings: Arc<parking_lot::RwLock<Settings>>,
) -> AsyncDetectionQueue {
    let (queue, receiver) = AsyncDetectionQueue::new(queue_size);

    let receiver = Arc::new(tokio::sync::Mutex::new(receiver));

    for i in 0..worker_count {
        let receiver_clone = receiver.clone();
        let settings_clone = settings.clone();
        let results_clone = queue.results.clone();

        tokio::spawn(async move {
            tracing::info!("Async detection worker {} started", i);
            loop {
                let task = {
                    let mut rx = receiver_clone.lock().await;
                    rx.recv().await
                };

                match task {
                    Some(task) => {
                        let settings_clone = settings_clone.read().clone();
                        let results_clone = results_clone.clone();
                        let request_id = task.request_id.clone();

                        tokio::spawn(async move {
                            let detection = detect_request(
                                &task.url,
                                &task.method,
                                &task.headers,
                                &task.cookies,
                                &task.body,
                                &task.args,
                                &settings_clone,
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
                        });
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
        "Started {} async detection workers with queue size {}",
        worker_count,
        queue_size
    );

    queue
}
