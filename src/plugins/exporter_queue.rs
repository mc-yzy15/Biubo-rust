use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::plugins::types::LogExporterConfig;

const DEFAULT_QUEUE_CAPACITY: usize = 1000;
const DEFAULT_BATCH_SIZE: usize = 10;
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 1000;
const MAX_RETRY_ATTEMPTS: u32 = 3;
const INITIAL_RETRY_DELAY_MS: u64 = 500;

pub struct ExporterQueue {
    sender: mpsc::Sender<serde_json::Value>,
}

impl ExporterQueue {
    pub fn new(capacity: Option<usize>) -> (Self, mpsc::Receiver<serde_json::Value>) {
        let cap = capacity.unwrap_or(DEFAULT_QUEUE_CAPACITY);
        let (sender, receiver) = mpsc::channel(cap);
        (Self { sender }, receiver)
    }

    pub fn enqueue(&self, log_entry: serde_json::Value) -> bool {
        self.sender.try_send(log_entry).is_ok()
    }
}

#[derive(Clone)]
struct ExportTarget {
    config: LogExporterConfig,
    client: reqwest::Client,
}

pub async fn run_exporter_worker(
    mut receiver: mpsc::Receiver<serde_json::Value>,
    exporters: Vec<(String, LogExporterConfig)>,
) {
    if exporters.is_empty() {
        tracing::info!("No exporters registered, exporter worker exiting");
        return;
    }

    tracing::info!("Starting exporter worker with {} exporter(s)", exporters.len());

    let export_targets: Vec<ExportTarget> = exporters
        .into_iter()
        .map(|(_name, config)| {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default();
            ExportTarget { config, client }
        })
        .collect();

    let flush_interval = Duration::from_millis(DEFAULT_FLUSH_INTERVAL_MS);
    let mut buffer: Vec<serde_json::Value> = Vec::new();

    loop {
        let collect_result = tokio::select! {
            Some(entry) = receiver.recv() => {
                buffer.push(entry);
                false
            }
            _ = sleep(flush_interval) => {
                true
            }
        };

        if collect_result && !buffer.is_empty() {
            let batch: Vec<serde_json::Value> = buffer.drain(..).collect();
            dispatch_batch(&export_targets, &batch).await;
        }

        for target in &export_targets {
            let batch_size = if target.config.batch_size > 0 {
                target.config.batch_size
            } else {
                DEFAULT_BATCH_SIZE
            };

            if buffer.len() >= batch_size {
                let batch: Vec<serde_json::Value> = buffer.drain(..batch_size).collect();
                dispatch_batch(&[target.clone()], &batch).await;
            }
        }
    }
}

async fn dispatch_batch(targets: &[ExportTarget], batch: &[serde_json::Value]) {
    if batch.is_empty() {
        return;
    }

    for target in targets {
        let payload = serde_json::Value::Array(batch.to_vec());

        match send_with_retry(target, &payload).await {
            Ok(_) => {
                tracing::debug!(
                    "Exported {} log entries to {}",
                    batch.len(),
                    target.config.export_endpoint
                );
            }
            Err(e) => {
                tracing::error!(
                    "Failed to export {} log entries to {} after retries: {}",
                    batch.len(),
                    target.config.export_endpoint,
                    e
                );
            }
        }
    }
}

async fn send_with_retry(target: &ExportTarget, payload: &serde_json::Value) -> Result<(), String> {
    let mut attempt = 0;
    let mut delay_ms = INITIAL_RETRY_DELAY_MS;

    loop {
        attempt += 1;

        match send_export(target, payload).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                if attempt >= MAX_RETRY_ATTEMPTS {
                    return Err(format!("Failed after {} attempts: {}", attempt, e));
                }

                tracing::warn!(
                    "Export attempt {} failed for {}, retrying in {}ms: {}",
                    attempt,
                    target.config.export_endpoint,
                    delay_ms,
                    e
                );

                sleep(Duration::from_millis(delay_ms)).await;
                delay_ms *= 2;
            }
        }
    }
}

async fn send_export(target: &ExportTarget, payload: &serde_json::Value) -> Result<(), String> {
    let response = target
        .client
        .post(&target.config.export_endpoint)
        .json(payload)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read body>".to_string());
        return Err(format!("HTTP {}: {}", status, body));
    }

    Ok(())
}
