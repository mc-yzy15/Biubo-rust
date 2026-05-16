pub mod base;
pub mod manager;

use serde::{Deserialize, Serialize};

#[cfg(any(feature = "redis-support", feature = "postgres-support"))]
pub mod driver;

#[cfg(feature = "redis-support")]
pub mod redis_driver;

#[cfg(feature = "postgres-support")]
pub mod postgres_driver;

#[allow(unused_imports)]
pub use base::Database;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageDriverType {
    MsgPack,
    #[cfg(feature = "redis-support")]
    Redis,
    #[cfg(feature = "postgres-support")]
    PostgreSQL,
}

#[cfg(any(feature = "redis-support", feature = "postgres-support"))]
#[allow(unused_imports)]
pub use driver::{
    create_driver_async, StorageConfig, StorageDriver, StorageDriverError,
};
