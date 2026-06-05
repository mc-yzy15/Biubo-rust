pub mod base;
pub mod flusher_pool;
pub mod manager;
pub mod storage_utils;

use serde::{Deserialize, Serialize};

#[cfg(any(feature = "redis-support", feature = "postgres-support"))]
pub mod driver;

#[cfg(feature = "redis-support")]
pub mod redis_driver;

#[cfg(feature = "postgres-support")]
pub mod postgres_driver;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageDriverType {
    MsgPack,
    #[cfg(feature = "redis-support")]
    Redis,
    #[cfg(feature = "postgres-support")]
    PostgreSQL,
}

#[cfg(any(feature = "redis-support", feature = "postgres-support"))]
pub use driver::{
    StorageDriver, StorageDriverError,
};
