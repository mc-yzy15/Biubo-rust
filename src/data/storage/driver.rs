use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{redis_driver::RedisDriver, postgres_driver::PostgreSQLDriver};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageDriverType {
    MsgPack,
    Redis,
    PostgreSQL,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub driver_type: StorageDriverType,
    pub redis_url: Option<String>,
    pub postgres_url: Option<String>,
    pub msgpack_path: Option<String>,
    pub flush_interval: Option<u64>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            driver_type: StorageDriverType::MsgPack,
            redis_url: None,
            postgres_url: None,
            msgpack_path: None,
            flush_interval: Some(5),
        }
    }
}

#[derive(Debug)]
pub enum StorageDriverError {
    ConnectionError(String),
    OperationError(String),
    IoError(std::io::Error),
}

impl std::fmt::Display for StorageDriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            Self::OperationError(msg) => write!(f, "Operation error: {}", msg),
            Self::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for StorageDriverError {}

impl From<std::io::Error> for StorageDriverError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

#[async_trait]
pub trait StorageDriver: Send + Sync {
    async fn get(&self, key: &str) -> Option<serde_json::Value>;
    async fn set(&self, key: &str, value: serde_json::Value);
    async fn delete(&self, key: &str) -> bool;
    async fn flush(&self) -> std::io::Result<()>;
    async fn contains_key(&self, key: &str) -> bool;
    async fn keys(&self) -> Vec<String>;
}

pub async fn create_driver_async(config: StorageConfig) -> Result<Arc<dyn StorageDriver>, StorageDriverError> {
    match config.driver_type {
        StorageDriverType::MsgPack => {
            let path = config.msgpack_path.unwrap_or_else(|| "data.msgpack".to_string());
            let flush_interval = config.flush_interval.unwrap_or(5);
            let driver = MsgPackDriver::new(&path, flush_interval)?;
            Ok(Arc::new(driver))
        }
        StorageDriverType::Redis => {
            let url = config
                .redis_url
                .ok_or_else(|| StorageDriverError::ConnectionError(
                    "Redis URL is required for Redis driver".to_string()
                ))?;
            let driver = RedisDriver::new(&url).await?;
            Ok(Arc::new(driver))
        }
        StorageDriverType::PostgreSQL => {
            let url = config
                .postgres_url
                .ok_or_else(|| StorageDriverError::ConnectionError(
                    "PostgreSQL URL is required for PostgreSQL driver".to_string()
                ))?;
            let driver = PostgreSQLDriver::new(&url).await?;
            Ok(Arc::new(driver))
        }
    }
}

pub struct MsgPackDriver {
    inner: crate::data::storage::base::Database,
}

impl MsgPackDriver {
    pub fn new(path: &str, flush_interval_secs: u64) -> std::io::Result<Self> {
        let inner = crate::data::storage::base::Database::new(
            path,
            false,
            5,
            Duration::from_secs(flush_interval_secs),
        )?;
        Ok(Self { inner })
    }
}

#[async_trait]
impl StorageDriver for MsgPackDriver {
    async fn get(&self, key: &str) -> Option<serde_json::Value> {
        self.inner.get(key)
    }

    async fn set(&self, key: &str, value: serde_json::Value) {
        self.inner.set(key, value)
    }

    async fn delete(&self, key: &str) -> bool {
        self.inner.delete(key)
    }

    async fn flush(&self) -> std::io::Result<()> {
        self.inner.flush()
    }

    async fn contains_key(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }

    async fn keys(&self) -> Vec<String> {
        self.inner.keys()
    }
}
