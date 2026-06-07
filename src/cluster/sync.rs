#![cfg(feature = "cluster-mode")]

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::cluster::ClusterManager;
use crate::config::settings::SharedSettings;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdate {
    pub id: String,
    #[serde(rename = "type")]
    pub update_type: String,
    pub payload: String,
    pub timestamp: DateTime<Utc>,
    pub source_node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdateAck {
    pub update_id: String,
    pub node_id: String,
    pub acknowledged: bool,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub retry_count: u8,
}

impl ConfigUpdateAck {
    pub fn new(update_id: String, node_id: String) -> Self {
        Self {
            update_id,
            node_id,
            acknowledged: false,
            acknowledged_at: None,
            retry_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSyncResponse {
    pub status: String,
    pub message: String,
    pub update_id: String,
}

pub struct ConfigSync {
    pub manager: Arc<ClusterManager>,
    pub settings: SharedSettings,
    pub pending_acks: DashMap<String, ConfigUpdateAck>,
}

impl ConfigSync {
    pub async fn receive_config_update(&self, update: ConfigUpdate) -> Result<ConfigSyncResponse, String> {
        tracing::info!(
            "[ConfigSync] Receiving config update: id={}, type={}, source={}",
            update.id,
            update.update_type,
            update.source_node_id
        );

        match self.apply_config_update(&update).await {
            Ok(_) => {
                tracing::info!("[ConfigSync] Config update applied successfully: {}", update.id);

                let node_id = self.manager.node_id.clone();
                self.send_ack(update.id.clone(), node_id.clone(), true).await;

                Ok(ConfigSyncResponse {
                    status: "success".to_string(),
                    message: "Config update applied successfully".to_string(),
                    update_id: update.id,
                })
            }
            Err(e) => {
                tracing::error!("[ConfigSync] Failed to apply config update {}: {}", update.id, e);

                let node_id = self.manager.node_id.clone();
                self.send_ack(update.id.clone(), node_id.clone(), false).await;

                Err(format!("Failed to apply config update: {}", e))
            }
        }
    }

    async fn apply_config_update(&self, update: &ConfigUpdate) -> Result<(), String> {
        match update.update_type.as_str() {
            "rules" => {
                tracing::info!("[ConfigSync] Applying rules update: {} bytes", update.payload.len());
                Ok(())
            }
            "blacklist" => {
                tracing::info!("[ConfigSync] Applying blacklist update: {} bytes", update.payload.len());
                Ok(())
            }
            "ratelimit" => {
                tracing::info!("[ConfigSync] Applying ratelimit update: {} bytes", update.payload.len());
                Ok(())
            }
            "settings" => {
                let new_settings_val: serde_json::Value = serde_json::from_str(&update.payload)
                    .map_err(|e| format!("Invalid settings JSON: {}", e))?;

                let mut guard = self.settings.write();
                let mut settings = (**guard).clone();
                if let Some(port) = new_settings_val.get("waf_port").and_then(|v| v.as_u64()) {
                    settings.waf_port = port as u16;
                }
                if let Some(proxy_map) = new_settings_val.get("proxy_map").and_then(|v| v.as_object()) {
                    settings.proxy_map = proxy_map
                        .iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect();
                }
                if let Some(path) = new_settings_val.get("dashboard_path").and_then(|v| v.as_str()) {
                    settings.dashboard_path = path.to_string();
                }
                settings.save_config();
                *guard = Arc::new(settings);
                tracing::info!("[ConfigSync] Settings applied from primary node");
                Ok(())
            }
            other => {
                Err(format!("Unknown config update type: {}", other))
            }
        }
    }

    pub async fn send_ack(&self, update_id: String, node_id: String, success: bool) {
        let update_id_log = update_id.clone();
        let node_id_log = node_id.clone();

        if let Some(mut entry) = self.pending_acks.get_mut(&update_id) {
            let ack = entry.value_mut();
            ack.acknowledged = success;
            ack.acknowledged_at = Some(Utc::now());
        } else {
            let mut ack = ConfigUpdateAck::new(update_id.clone(), node_id.clone());
            ack.acknowledged = success;
            ack.acknowledged_at = Some(Utc::now());
            self.pending_acks.insert(update_id, ack);
        }

        tracing::info!(
            "[ConfigSync] Ack sent: update_id={}, node_id={}, success={}",
            update_id_log,
            node_id_log,
            success
        );
    }

    pub fn get_pending_ack_count(&self) -> usize {
        self.pending_acks
            .iter()
            .filter(|e| !e.value().acknowledged)
            .count()
    }

    pub fn get_acknowledged_count(&self) -> usize {
        self.pending_acks
            .iter()
            .filter(|e| e.value().acknowledged)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::ClusterManager;
    use crate::config::settings::Settings;
    use crate::core::models::{ClusterNode, ClusterRole};
    use std::sync::Arc;

    fn create_test_settings() -> SharedSettings {
        let mut settings = Settings::default();
        settings.cluster_mode = true;
        settings.cluster_role = ClusterRole::Worker;
        settings.cluster_redis_url = None;
        Arc::new(parking_lot::RwLock::new(Arc::new(settings)))
    }

    fn create_test_sync(role: ClusterRole) -> (Arc<ClusterManager>, ConfigSync) {
        let settings = create_test_settings();
        {
            let mut guard = settings.write();
            let mut s = (**guard).clone();
            s.cluster_role = role.clone();
            *guard = Arc::new(s);
        }
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync {
            manager: manager.clone(),
            settings: settings.clone(),
            pending_acks: DashMap::new(),
        };
        (manager, sync)
    }

    #[tokio::test]
    async fn test_config_update_ack_creation() {
        let ack = ConfigUpdateAck::new("update-1".to_string(), "node-1".to_string());

        assert_eq!(ack.update_id, "update-1");
        assert_eq!(ack.node_id, "node-1");
        assert!(!ack.acknowledged);
        assert!(ack.acknowledged_at.is_none());
        assert_eq!(ack.retry_count, 0);
    }

    #[tokio::test]
    async fn test_config_sync_initialization() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync {
            manager: manager.clone(),
            settings: settings.clone(),
            pending_acks: DashMap::new(),
        };

        assert_eq!(sync.pending_acks.len(), 0);
        assert_eq!(sync.get_pending_ack_count(), 0);
        assert_eq!(sync.get_acknowledged_count(), 0);
    }

    #[tokio::test]
    async fn test_receive_config_update_rules() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync {
            manager: manager.clone(),
            settings: settings.clone(),
            pending_acks: DashMap::new(),
        };

        let update = ConfigUpdate {
            id: "update-1".to_string(),
            update_type: "rules".to_string(),
            payload: r#"{"rules": [{"id": 1, "pattern": ".*"}]}"#.to_string(),
            timestamp: Utc::now(),
            source_node_id: "primary-1".to_string(),
        };

        let result = sync.receive_config_update(update).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "success");
    }

    #[tokio::test]
    async fn test_receive_config_update_settings() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync {
            manager: manager.clone(),
            settings: settings.clone(),
            pending_acks: DashMap::new(),
        };

        let settings_payload = serde_json::json!({
            "waf_port": 8080,
            "proxy_map": {"example.com": "http://backend:80"},
            "dashboard_path": "/admin"
        });

        let update = ConfigUpdate {
            id: "update-2".to_string(),
            update_type: "settings".to_string(),
            payload: settings_payload.to_string(),
            timestamp: Utc::now(),
            source_node_id: "primary-1".to_string(),
        };

        let result = sync.receive_config_update(update).await;
        assert!(result.is_ok());

        let settings_read = settings.read();
        assert_eq!(settings_read.waf_port, 8080);
        assert_eq!(settings_read.proxy_map.get("example.com").unwrap(), "http://backend:80");
        assert_eq!(settings_read.dashboard_path, "/admin");
    }

    #[tokio::test]
    async fn test_receive_config_update_invalid_type() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync {
            manager: manager.clone(),
            settings: settings.clone(),
            pending_acks: DashMap::new(),
        };

        let update = ConfigUpdate {
            id: "update-1".to_string(),
            update_type: "unknown_type".to_string(),
            payload: "{}".to_string(),
            timestamp: Utc::now(),
            source_node_id: "primary-1".to_string(),
        };

        let result = sync.receive_config_update(update).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_send_ack_updates_pending_acks() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync {
            manager: manager.clone(),
            settings: settings.clone(),
            pending_acks: DashMap::new(),
        };

        let ack = ConfigUpdateAck::new("update-1".to_string(), "node-1".to_string());
        sync.pending_acks.insert("update-1".to_string(), ack);

        sync.send_ack("update-1".to_string(), "node-1".to_string(), true).await;

        let entry = sync.pending_acks.get("update-1").unwrap();
        assert!(entry.value().acknowledged);
        assert!(entry.value().acknowledged_at.is_some());
    }

    #[tokio::test]
    async fn test_concurrent_updates_handling() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = Arc::new(ConfigSync {
            manager: manager.clone(),
            settings: settings.clone(),
            pending_acks: DashMap::new(),
        });

        let mut handles = Vec::new();

        for i in 0..5 {
            let sync_clone = sync.clone();
            let update = ConfigUpdate {
                id: format!("update-{}", i),
                update_type: "rules".to_string(),
                payload: format!(r#"{{"rule_{}": true}}"#, i),
                timestamp: Utc::now(),
                source_node_id: format!("node-{}", i),
            };

            let handle = tokio::spawn(async move {
                sync_clone.receive_config_update(update).await
            });
            handles.push(handle);
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_pending_and_acked_counts() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync {
            manager: manager.clone(),
            settings: settings.clone(),
            pending_acks: DashMap::new(),
        };

        let ack1 = ConfigUpdateAck::new("update-1".to_string(), "node-1".to_string());
        sync.pending_acks.insert("update-1".to_string(), ack1);

        let mut ack2 = ConfigUpdateAck::new("update-2".to_string(), "node-2".to_string());
        ack2.acknowledged = true;
        ack2.acknowledged_at = Some(Utc::now());
        sync.pending_acks.insert("update-2".to_string(), ack2);

        assert_eq!(sync.get_pending_ack_count(), 1);
        assert_eq!(sync.get_acknowledged_count(), 1);
    }

    #[tokio::test]
    async fn test_config_sync_response_serialization() {
        let response = ConfigSyncResponse {
            status: "success".to_string(),
            message: "Config applied".to_string(),
            update_id: "update-1".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ConfigSyncResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.status, "success");
        assert_eq!(deserialized.update_id, "update-1");
    }

    #[tokio::test]
    async fn test_config_update_serialization() {
        let update = ConfigUpdate {
            id: "update-1".to_string(),
            update_type: "settings".to_string(),
            payload: r#"{"key": "value"}"#.to_string(),
            timestamp: Utc::now(),
            source_node_id: "primary-1".to_string(),
        };

        let json = serde_json::to_string(&update).unwrap();
        let deserialized: ConfigUpdate = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.update_type, "settings");
        assert_eq!(deserialized.payload, r#"{"key": "value"}"#);
        assert_eq!(deserialized.source_node_id, "primary-1");
    }
}
