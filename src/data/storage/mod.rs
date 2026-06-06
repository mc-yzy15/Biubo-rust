pub mod base;
pub mod flusher_pool;
pub mod manager;
pub mod storage_utils;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageDriverType {
    MsgPack,
    #[cfg(feature = "redis-support")]
    Redis,
    #[cfg(feature = "postgres-support")]
    PostgreSQL,
}
