use std::time::Duration;

use async_trait::async_trait;
use redis::AsyncCommands;
use tracing;

use super::{StorageDriver, StorageDriverError};

const REDIS_KEY_PREFIX: &str = "biubo:waf:";
const MAX_RETRY_ATTEMPTS: u32 = 3;
const INITIAL_RETRY_DELAY_MS: u64 = 50;

pub struct RedisDriver {
    manager: redis::aio::ConnectionManager,
}

impl RedisDriver {
    pub async fn new(url: &str) -> Result<Self, StorageDriverError> {
        let client = redis::Client::open(url).map_err(|e| {
            StorageDriverError::ConnectionError(format!("Invalid Redis URL: {}", e))
        })?;

        let mut last_error = None;
        for attempt in 1..=MAX_RETRY_ATTEMPTS {
            match client.get_connection_manager().await {
                Ok(manager) => {
                    tracing::info!("[RedisDriver] Connected to Redis at {}", url);
                    return Ok(Self { manager });
                }
                Err(e) => {
                    tracing::warn!("[RedisDriver] Connection attempt {} failed: {}", attempt, e);
                    last_error = Some(e);
                    if attempt < MAX_RETRY_ATTEMPTS {
                        let delay =
                            Duration::from_millis(INITIAL_RETRY_DELAY_MS * 2u64.pow(attempt - 1));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(StorageDriverError::ConnectionError(format!(
            "Failed to connect to Redis after {} attempts: {:?}",
            MAX_RETRY_ATTEMPTS, last_error
        )))
    }

    fn make_key(key: &str) -> String {
        format!("{}{}", REDIS_KEY_PREFIX, key)
    }

    async fn with_retry<F, Fut, T>(&self, operation: F) -> Result<T, StorageDriverError>
    where
        F: Fn(redis::aio::ConnectionManager) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<T, redis::RedisError>> + Send,
    {
        let mut last_error = None;
        for attempt in 1..=MAX_RETRY_ATTEMPTS {
            match operation(self.manager.clone()).await {
                Ok(value) => return Ok(value),
                Err(e) => {
                    tracing::warn!("[RedisDriver] Operation attempt {} failed: {}", attempt, e);
                    last_error = Some(e);
                    if attempt < MAX_RETRY_ATTEMPTS {
                        let delay =
                            Duration::from_millis(INITIAL_RETRY_DELAY_MS * 2u64.pow(attempt - 1));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(StorageDriverError::OperationError(format!(
            "Operation failed after {} attempts: {:?}",
            MAX_RETRY_ATTEMPTS, last_error
        )))
    }
}

#[async_trait]
impl StorageDriver for RedisDriver {
    async fn get(&self, key: &str) -> Option<serde_json::Value> {
        let redis_key = Self::make_key(key);
        match self
            .with_retry(|mgr| {
                let redis_key = redis_key.clone();
                async move {
                    let mut conn = mgr;
                    let result: Option<String> = conn.get(&redis_key).await?;
                    Ok(result)
                }
            })
            .await
        {
            Ok(Some(value_str)) => match serde_json::from_str(&value_str) {
                Ok(value) => Some(value),
                Err(e) => {
                    tracing::error!(
                        "[RedisDriver] Failed to deserialize value for key '{}': {}",
                        key,
                        e
                    );
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                tracing::error!(
                    "[RedisDriver] GET operation failed for key '{}': {}",
                    key,
                    e
                );
                None
            }
        }
    }

    async fn set(&self, key: &str, value: serde_json::Value) {
        let redis_key = Self::make_key(key);
        let value_str = match serde_json::to_string(&value) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    "[RedisDriver] Failed to serialize value for key '{}': {}",
                    key,
                    e
                );
                return;
            }
        };

        if let Err(e) = self
            .with_retry(|mgr| {
                let redis_key = redis_key.clone();
                let value_str = value_str.clone();
                async move {
                    let mut conn = mgr;
                    let _: () = conn.set(&redis_key, &value_str).await?;
                    Ok(())
                }
            })
            .await
        {
            tracing::error!(
                "[RedisDriver] SET operation failed for key '{}': {}",
                key,
                e
            );
        }
    }

    async fn delete(&self, key: &str) -> bool {
        let redis_key = Self::make_key(key);
        match self
            .with_retry(|mgr| {
                let redis_key = redis_key.clone();
                async move {
                    let mut conn = mgr;
                    let result: i32 = conn.del(&redis_key).await?;
                    Ok(result)
                }
            })
            .await
        {
            Ok(count) => count > 0,
            Err(e) => {
                tracing::error!(
                    "[RedisDriver] DELETE operation failed for key '{}': {}",
                    key,
                    e
                );
                false
            }
        }
    }

    async fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }

    async fn contains_key(&self, key: &str) -> bool {
        let redis_key = Self::make_key(key);
        match self
            .with_retry(|mgr| {
                let redis_key = redis_key.clone();
                async move {
                    let mut conn = mgr;
                    let result: bool = conn.exists(&redis_key).await?;
                    Ok(result)
                }
            })
            .await
        {
            Ok(exists) => exists,
            Err(e) => {
                tracing::error!(
                    "[RedisDriver] EXISTS operation failed for key '{}': {}",
                    key,
                    e
                );
                false
            }
        }
    }

    async fn keys(&self) -> Vec<String> {
        let pattern = format!("{}*", REDIS_KEY_PREFIX);
        match self
            .with_retry(|mgr| {
                let pattern = pattern.clone();
                async move {
                    let mut conn = mgr;
                    let mut cursor: u64 = 0;
                    let mut all_keys: Vec<String> = Vec::new();

                    loop {
                        let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                            .arg(cursor)
                            .arg("MATCH")
                            .arg(&pattern)
                            .arg("COUNT")
                            .arg(100)
                            .query_async(&mut conn)
                            .await?;

                        all_keys.extend(keys);
                        if next_cursor == 0 {
                            break;
                        }
                        cursor = next_cursor;
                    }

                    Ok(all_keys)
                }
            })
            .await
        {
            Ok(keys) => keys
                .into_iter()
                .filter_map(|k| k.strip_prefix(REDIS_KEY_PREFIX).map(String::from))
                .collect(),
            Err(e) => {
                tracing::error!("[RedisDriver] SCAN operation failed: {}", e);
                Vec::new()
            }
        }
    }
}
