use async_trait::async_trait;
use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod};
use serde_json;
use tokio_postgres::{NoTls, Row};
use tracing;

use super::{StorageDriver, StorageDriverError};

const TABLE_NAME: &str = "biubo_kv_store";
const MAX_POOL_SIZE: usize = 16;

fn row_to_value(row: &Row) -> Option<serde_json::Value> {
    row.try_get::<_, serde_json::Value>("value").ok()
}

pub struct PostgreSQLDriver {
    pool: Pool,
}

impl PostgreSQLDriver {
    pub async fn new(url: &str) -> Result<Self, StorageDriverError> {
        let config = Self::parse_url(url)?;
        let pool = config
            .create_pool(Some(deadpool_postgres::Runtime::Tokio1), NoTls)
            .map_err(|e| {
                StorageDriverError::ConnectionError(format!(
                    "Failed to create PostgreSQL connection pool: {}",
                    e
                ))
            })?;

        let driver = Self { pool };
        driver.run_migration().await?;

        tracing::info!(
            "[PostgreSQLDriver] Connected to PostgreSQL and migration applied"
        );
        Ok(driver)
    }

    fn parse_url(url: &str) -> Result<Config, StorageDriverError> {
        let config = Config::new(url).map_err(|e| {
            StorageDriverError::ConnectionError(format!("Invalid PostgreSQL URL: {}", e))
        })?;

        Ok(Config {
            manager: Some(ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            }),
            max_size: Some(MAX_POOL_SIZE),
            ..config
        })
    }

    async fn run_migration(&self) -> Result<(), StorageDriverError> {
        let create_table_sql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                id SERIAL PRIMARY KEY,
                key TEXT UNIQUE NOT NULL,
                value JSONB NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            "#,
            TABLE_NAME
        );

        let create_index_sql = format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_key ON {} (key);",
            TABLE_NAME, TABLE_NAME
        );

        let client = self.pool.get().await.map_err(|e| {
            StorageDriverError::OperationError(format!(
                "Failed to get connection from pool for migration: {}",
                e
            ))
        })?;

        client
            .batch_execute(&create_table_sql)
            .await
            .map_err(|e| {
                StorageDriverError::OperationError(format!(
                    "Failed to create table '{}': {}",
                    TABLE_NAME, e
                ))
            })?;

        client
            .batch_execute(&create_index_sql)
            .await
            .map_err(|e| {
                StorageDriverError::OperationError(format!(
                    "Failed to create index on '{}': {}",
                    TABLE_NAME, e
                ))
            })?;

        Ok(())
    }
}

#[async_trait]
impl StorageDriver for PostgreSQLDriver {
    async fn get(&self, key: &str) -> Option<serde_json::Value> {
        let client = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "[PostgreSQLDriver] Failed to get connection for GET '{}': {}",
                    key,
                    e
                );
                return None;
            }
        };

        let query = format!(
            "SELECT value FROM {} WHERE key = $1",
            TABLE_NAME
        );

        match client.query_opt(&query, &[&key]).await {
            Ok(Some(row)) => row_to_value(&row),
            Ok(None) => None,
            Err(e) => {
                tracing::error!(
                    "[PostgreSQLDriver] GET operation failed for key '{}': {}",
                    key,
                    e
                );
                None
            }
        }
    }

    async fn set(&self, key: &str, value: serde_json::Value) {
        let client = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "[PostgreSQLDriver] Failed to get connection for SET '{}': {}",
                    key,
                    e
                );
                return;
            }
        };

        let query = format!(
            r#"
            INSERT INTO {} (key, value)
            VALUES ($1, $2)
            ON CONFLICT (key)
            DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP
            "#,
            TABLE_NAME
        );

        if let Err(e) = client.execute(&query, &[&key, &value]).await {
            tracing::error!(
                "[PostgreSQLDriver] SET operation failed for key '{}': {}",
                key,
                e
            );
        }
    }

    async fn delete(&self, key: &str) -> bool {
        let client = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "[PostgreSQLDriver] Failed to get connection for DELETE '{}': {}",
                    key,
                    e
                );
                return false;
            }
        };

        let query = format!("DELETE FROM {} WHERE key = $1", TABLE_NAME);

        match client.execute(&query, &[&key]).await {
            Ok(count) => count > 0,
            Err(e) => {
                tracing::error!(
                    "[PostgreSQLDriver] DELETE operation failed for key '{}': {}",
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
        let client = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "[PostgreSQLDriver] Failed to get connection for EXISTS '{}': {}",
                    key,
                    e
                );
                return false;
            }
        };

        let query = format!("SELECT 1 FROM {} WHERE key = $1", TABLE_NAME);

        match client.query_opt(&query, &[&key]).await {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                tracing::error!(
                    "[PostgreSQLDriver] EXISTS operation failed for key '{}': {}",
                    key,
                    e
                );
                false
            }
        }
    }

    async fn keys(&self) -> Vec<String> {
        let client = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "[PostgreSQLDriver] Failed to get connection for KEYS: {}",
                    e
                );
                return Vec::new();
            }
        };

        let query = format!("SELECT key FROM {} ORDER BY key", TABLE_NAME);

        match client.query(&query, &[]).await {
            Ok(rows) => rows
                .into_iter()
                .filter_map(|row| row.try_get::<_, String>("key").ok())
                .collect(),
            Err(e) => {
                tracing::error!("[PostgreSQLDriver] KEYS operation failed: {}", e);
                Vec::new()
            }
        }
    }
}
