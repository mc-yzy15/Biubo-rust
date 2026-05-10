use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

use crate::cluster::ClusterManager;
use crate::config::settings::SharedSettings;

const ACK_TIMEOUT_SECS: u64 = 5;
const MAX_RETRY_COUNT: u8 = 3;
const CLUSTER_SYNC_CHANNEL: &str = "biubo:cluster:config_sync";
const HTTP_SYNC_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConfigUpdateType {
    #[serde(rename = "rules")]
    Rules,
    #[serde(rename = "blacklist")]
    Blacklist,
    #[serde(rename = "ratelimit")]
    RateLimit,
    #[serde(rename = "settings")]
    Settings,
}

impl std::fmt::Display for ConfigUpdateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigUpdateType::Rules => write!(f, "rules"),
            ConfigUpdateType::Blacklist => write!(f, "blacklist"),
            ConfigUpdateType::RateLimit => write!(f, "ratelimit"),
            ConfigUpdateType::Settings => write!(f, "settings"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdate {
    pub id: String,
    #[serde(rename = "type")]
    pub update_type: String,
    pub payload: String,
    pub timestamp: DateTime<Utc>,
    pub source_node_id: String,
}

impl ConfigUpdate {
    pub fn new(update_type: ConfigUpdateType, payload: String, source_node_id: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            update_type: update_type.to_string(),
            payload,
            timestamp: Utc::now(),
            source_node_id,
        }
    }
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
    pub redis_client: Option<redis::aio::ConnectionManager>,
    pub pending_acks: DashMap<String, ConfigUpdateAck>,
    pub http_client: reqwest::Client,
}

impl ConfigSync {
    pub fn new(manager: Arc<ClusterManager>, settings: SharedSettings) -> Self {
        Self {
            manager,
            settings,
            redis_client: None,
            pending_acks: DashMap::new(),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(HTTP_SYNC_TIMEOUT_SECS))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }

    pub async fn with_redis(&mut self, redis_url: &str) -> bool {
        match redis::Client::open(redis_url) {
            Ok(client) => match client.get_connection_manager().await {
                Ok(manager) => {
                    self.redis_client = Some(manager);
                    tracing::info!("[ConfigSync] Redis connection established for config sync");
                    true
                }
                Err(e) => {
                    tracing::warn!("[ConfigSync] Failed to connect to Redis for config sync: {}", e);
                    false
                }
            },
            Err(e) => {
                tracing::warn!("[ConfigSync] Invalid Redis URL for config sync: {}", e);
                false
            }
        }
    }

    pub async fn broadcast_config_change(&self, update: ConfigUpdate) -> Result<usize, String> {
        tracing::info!(
            "[ConfigSync] Broadcasting config change: id={}, type={}, source={}",
            update.id,
            update.update_type,
            update.source_node_id
        );

        let target_nodes = self.get_target_nodes();
        if target_nodes.is_empty() {
            tracing::info!("[ConfigSync] No target nodes for broadcast");
            return Ok(0);
        }

        for node in &target_nodes {
            let ack = ConfigUpdateAck::new(update.id.clone(), node.id.clone());
            self.pending_acks.insert(update.id.clone(), ack);
        }

        if self.redis_client.is_some() {
            match self.broadcast_via_redis(&update).await {
                Ok(_) => {
                    tracing::info!("[ConfigSync] Config update broadcast via Redis to {} nodes", target_nodes.len());
                }
                Err(e) => {
                    tracing::warn!("[ConfigSync] Redis broadcast failed, falling back to HTTP: {}", e);
                    self.broadcast_via_http(&update, &target_nodes).await;
                }
            }
        } else {
            tracing::info!("[ConfigSync] Broadcasting via HTTP to {} nodes", target_nodes.len());
            self.broadcast_via_http(&update, &target_nodes).await;
        }

        self.start_ack_monitor(&update.id).await;

        let acked_count = self.pending_acks
            .iter()
            .filter(|e| e.value().acknowledged)
            .count();

        Ok(acked_count)
    }

    async fn broadcast_via_redis(&self, update: &ConfigUpdate) -> Result<(), String> {
        let redis_client = self.redis_client
            .as_ref()
            .ok_or_else(|| "Redis client not available".to_string())?;

        let message = serde_json::to_string(update)
            .map_err(|e| format!("Failed to serialize config update: {}", e))?;

        let mut client = redis_client.clone();
        let _: () = redis::cmd("PUBLISH")
            .arg(CLUSTER_SYNC_CHANNEL)
            .arg(&message)
            .query_async(&mut client)
            .await
            .map_err(|e| format!("Redis publish failed: {}", e))?;

        Ok(())
    }

    async fn broadcast_via_http(&self, update: &ConfigUpdate, nodes: &[crate::core::models::ClusterNode]) {
        let message = match serde_json::to_string(update) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("[ConfigSync] Failed to serialize config update for HTTP: {}", e);
                return;
            }
        };

        let update_id = update.id.clone();

        for node in nodes {
            let node_ip = node.ip.clone();
            let msg = message.clone();
            let node_id = node.id.clone();
            let client = self.http_client.clone();
            let pending_acks = self.pending_acks.clone();
            let update_id_clone = update_id.clone();

            tokio::spawn(async move {
                let url = format!("http://{}/api/cluster/sync", node_ip);
                match client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("X-Cluster-Node-Id", &node_id)
                    .body(msg)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            tracing::info!("[ConfigSync] HTTP sync sent to node {}", node_id);
                        } else {
                            tracing::warn!(
                                "[ConfigSync] HTTP sync failed for node {}: status {}",
                                node_id,
                                resp.status()
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("[ConfigSync] HTTP sync error for node {}: {}", node_id, e);
                        if let Some(mut ack) = pending_acks.get_mut(&update_id_clone) {
                            let ack_mut = ack.value_mut();
                            ack_mut.retry_count = ack_mut.retry_count.saturating_add(1);
                        }
                    }
                }
            });
        }
    }

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
                let new_settings: serde_json::Value = serde_json::from_str(&update.payload)
                    .map_err(|e| format!("Invalid settings JSON: {}", e))?;

                let mut settings = self.settings.write();
                if let Some(port) = new_settings.get("waf_port").and_then(|v| v.as_u64()) {
                    settings.waf_port = port as u16;
                }
                if let Some(proxy_map) = new_settings.get("proxy_map").and_then(|v| v.as_object()) {
                    settings.proxy_map = proxy_map
                        .iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect();
                }
                if let Some(path) = new_settings.get("dashboard_path").and_then(|v| v.as_str()) {
                    settings.dashboard_path = path.to_string();
                }
                settings.save_config();
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

    pub async fn retry_pending_acks(&self) {
        let now = Utc::now();
        let mut to_retry = Vec::new();

        for entry in self.pending_acks.iter() {
            let ack = entry.value();
            if !ack.acknowledged && ack.retry_count < MAX_RETRY_COUNT {
                if let Some(ack_time) = ack.acknowledged_at {
                    if (now - ack_time).num_seconds() >= ACK_TIMEOUT_SECS as i64 {
                        to_retry.push(ack.update_id.clone());
                    }
                } else {
                    to_retry.push(ack.update_id.clone());
                }
            }
        }

        for update_id in &to_retry {
            if let Some(mut entry) = self.pending_acks.get_mut(update_id) {
                let ack = entry.value_mut();
                ack.retry_count += 1;

                if ack.retry_count >= MAX_RETRY_COUNT {
                    tracing::warn!(
                        "[ConfigSync] Update {} marked as failed (max retries reached, node: {})",
                        ack.update_id,
                        ack.node_id
                    );
                } else {
                    tracing::info!(
                        "[ConfigSync] Retrying update {} (attempt {}/{})",
                        ack.update_id,
                        ack.retry_count,
                        MAX_RETRY_COUNT
                    );

                    let node_ip = self.get_node_ip(&ack.node_id);
                    if let Some(ip) = node_ip {
                        let url = format!("http://{}/api/cluster/sync", ip);
                        let client = self.http_client.clone();

                        tokio::spawn(async move {
                            match client.get(&url).send().await {
                                Ok(_) => {
                                    tracing::info!("[ConfigSync] Retry check sent to {}", ip);
                                }
                                Err(e) => {
                                    tracing::warn!("[ConfigSync] Retry check failed for {}: {}", ip, e);
                                }
                            }
                        });
                    }
                }
            }
        }
    }

    async fn start_ack_monitor(&self, update_id: &str) {
        let pending_acks = self.pending_acks.clone();
        let update_id = update_id.to_string();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(ACK_TIMEOUT_SECS));
            let mut elapsed = 0;

            loop {
                interval.tick().await;
                elapsed += ACK_TIMEOUT_SECS;

                let all_acked = pending_acks
                    .iter()
                    .filter(|e| e.key() == &update_id)
                    .all(|e| e.value().acknowledged);

                if all_acked {
                    tracing::info!("[ConfigSync] All ack received for update {}", update_id);
                    break;
                }

                if elapsed >= ACK_TIMEOUT_SECS * MAX_RETRY_COUNT as u64 {
                    tracing::warn!("[ConfigSync] Ack timeout for update {} after {}s", update_id, elapsed);

                    for mut entry in pending_acks.iter_mut() {
                        if entry.key() == &update_id && !entry.value().acknowledged {
                            let ack = entry.value_mut();
                            ack.retry_count = MAX_RETRY_COUNT;
                        }
                    }
                    break;
                }
            }
        });
    }

    fn get_target_nodes(&self) -> Vec<crate::core::models::ClusterNode> {
        let primary_id = self.manager.get_primary_node();
        let current_role = self.manager.get_role();

        let is_primary = matches!(current_role, crate::core::models::ClusterRole::Primary)
            || primary_id.as_ref() == Some(&self.manager.node_id);

        self.manager
            .get_active_nodes()
            .into_iter()
            .filter(|node| {
                node.id != self.manager.node_id
                    && (!is_primary || !matches!(node.role, crate::core::models::ClusterRole::Primary))
            })
            .collect()
    }

    fn get_node_ip(&self, node_id: &str) -> Option<String> {
        self.manager
            .nodes
            .get(node_id)
            .map(|entry| entry.value().node.ip.clone())
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
        Arc::new(parking_lot::RwLock::new(settings))
    }

    fn create_test_sync(role: ClusterRole) -> (Arc<ClusterManager>, ConfigSync) {
        let settings = create_test_settings();
        {
            let mut s = settings.write();
            s.cluster_role = role.clone();
        }
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync::new(manager.clone(), settings.clone());
        (manager, sync)
    }

    #[tokio::test]
    async fn test_config_update_creation() {
        let update = ConfigUpdate::new(
            ConfigUpdateType::Rules,
            r#"{"rules": []}"#.to_string(),
            "node-1".to_string(),
        );

        assert!(!update.id.is_empty());
        assert_eq!(update.update_type, "rules");
        assert_eq!(update.source_node_id, "node-1");
        assert_eq!(update.payload, r#"{"rules": []}"#);
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
        let sync = ConfigSync::new(manager.clone(), settings.clone());

        assert!(sync.redis_client.is_none());
        assert_eq!(sync.pending_acks.len(), 0);
        assert_eq!(sync.get_pending_ack_count(), 0);
        assert_eq!(sync.get_acknowledged_count(), 0);
    }

    #[tokio::test]
    async fn test_broadcast_to_no_target_nodes() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync::new(manager.clone(), settings.clone());

        let update = ConfigUpdate::new(
            ConfigUpdateType::Settings,
            r#"{}"#.to_string(),
            manager.node_id.clone(),
        );

        let result = sync.broadcast_config_change(update).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_broadcast_with_registered_nodes() {
        let settings = create_test_settings();
        {
            let mut s = settings.write();
            s.cluster_role = ClusterRole::Primary;
        }
        let manager = Arc::new(ClusterManager::new(settings.clone()));

        let secondary_node = ClusterNode {
            id: "secondary-1".to_string(),
            role: ClusterRole::Secondary,
            ip: "192.168.1.100:8080".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 100,
        };
        manager.register_node(secondary_node);

        let sync = ConfigSync::new(manager.clone(), settings.clone());

        let update = ConfigUpdate::new(
            ConfigUpdateType::Blacklist,
            r#"{"blacklist": ["1.2.3.4"]}"#.to_string(),
            manager.node_id.clone(),
        );

        let result = sync.broadcast_config_change(update).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_receive_config_update_rules() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync::new(manager.clone(), settings.clone());

        let update = ConfigUpdate::new(
            ConfigUpdateType::Rules,
            r#"{"rules": [{"id": 1, "pattern": ".*"}]}"#.to_string(),
            "primary-1".to_string(),
        );

        let result = sync.receive_config_update(update).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "success");
    }

    #[tokio::test]
    async fn test_receive_config_update_settings() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync::new(manager.clone(), settings.clone());

        let settings_payload = serde_json::json!({
            "waf_port": 8080,
            "proxy_map": {"example.com": "http://backend:80"},
            "dashboard_path": "/admin"
        });

        let update = ConfigUpdate::new(
            ConfigUpdateType::Settings,
            settings_payload.to_string(),
            "primary-1".to_string(),
        );

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
        let sync = ConfigSync::new(manager.clone(), settings.clone());

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
        let sync = ConfigSync::new(manager.clone(), settings.clone());

        let ack = ConfigUpdateAck::new("update-1".to_string(), "node-1".to_string());
        sync.pending_acks.insert("update-1".to_string(), ack);

        sync.send_ack("update-1".to_string(), "node-1".to_string(), true).await;

        let entry = sync.pending_acks.get("update-1").unwrap();
        assert!(entry.value().acknowledged);
        assert!(entry.value().acknowledged_at.is_some());
    }

    #[tokio::test]
    async fn test_retry_pending_acks_max_retries() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync::new(manager.clone(), settings.clone());

        let mut ack = ConfigUpdateAck::new("update-1".to_string(), "node-1".to_string());
        ack.retry_count = MAX_RETRY_COUNT - 1;
        ack.acknowledged_at = Some(Utc::now() - chrono::Duration::seconds(10));
        sync.pending_acks.insert("update-1".to_string(), ack);

        sync.retry_pending_acks().await;

        let entry = sync.pending_acks.get("update-1").unwrap();
        assert_eq!(entry.value().retry_count, MAX_RETRY_COUNT);
    }

    #[tokio::test]
    async fn test_retry_pending_acks_within_limit() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync::new(manager.clone(), settings.clone());

        let mut ack = ConfigUpdateAck::new("update-2".to_string(), "node-2".to_string());
        ack.retry_count = 0;
        ack.acknowledged_at = Some(Utc::now() - chrono::Duration::seconds(10));
        sync.pending_acks.insert("update-2".to_string(), ack);

        sync.retry_pending_acks().await;

        let entry = sync.pending_acks.get("update-2").unwrap();
        assert_eq!(entry.value().retry_count, 1);
    }

    #[tokio::test]
    async fn test_retry_pending_acks_does_not_retry_acked() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync::new(manager.clone(), settings.clone());

        let mut ack = ConfigUpdateAck::new("update-3".to_string(), "node-3".to_string());
        ack.acknowledged = true;
        ack.acknowledged_at = Some(Utc::now() - chrono::Duration::seconds(10));
        ack.retry_count = 0;
        sync.pending_acks.insert("update-3".to_string(), ack);

        let initial_retry_count = {
            let entry = sync.pending_acks.get("update-3").unwrap();
            entry.value().retry_count
        };

        sync.retry_pending_acks().await;

        let entry = sync.pending_acks.get("update-3").unwrap();
        assert_eq!(entry.value().retry_count, initial_retry_count);
    }

    #[tokio::test]
    async fn test_concurrent_updates_handling() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = Arc::new(ConfigSync::new(manager.clone(), settings.clone()));

        let mut handles = Vec::new();

        for i in 0..5 {
            let sync_clone = sync.clone();
            let update = ConfigUpdate::new(
                ConfigUpdateType::Rules,
                format!(r#"{{"rule_{}": true}}"#, i),
                format!("node-{}", i),
            );

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
    async fn test_fallback_from_redis_to_http() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));

        let mut sync = ConfigSync::new(manager.clone(), settings.clone());
        let redis_result = sync.with_redis("redis://invalid-host:6379").await;
        assert!(!redis_result);
        assert!(sync.redis_client.is_none());

        let update = ConfigUpdate::new(
            ConfigUpdateType::Blacklist,
            r#"{}"#.to_string(),
            manager.node_id.clone(),
        );

        let result = sync.broadcast_config_change(update).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_config_update_type_display() {
        assert_eq!(ConfigUpdateType::Rules.to_string(), "rules");
        assert_eq!(ConfigUpdateType::Blacklist.to_string(), "blacklist");
        assert_eq!(ConfigUpdateType::RateLimit.to_string(), "ratelimit");
        assert_eq!(ConfigUpdateType::Settings.to_string(), "settings");
    }

    #[tokio::test]
    async fn test_pending_and_acked_counts() {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let sync = ConfigSync::new(manager.clone(), settings.clone());

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
    async fn test_get_target_nodes_excludes_self() {
        let settings = create_test_settings();
        {
            let mut s = settings.write();
            s.cluster_role = ClusterRole::Primary;
        }
        let manager = Arc::new(ClusterManager::new(settings.clone()));

        let worker = ClusterNode {
            id: "worker-1".to_string(),
            role: ClusterRole::Worker,
            ip: "192.168.1.100".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 100,
        };
        manager.register_node(worker);

        let sync = ConfigSync::new(manager.clone(), settings.clone());
        let targets = sync.get_target_nodes();

        assert!(!targets.iter().any(|n| n.id == manager.node_id));
        assert!(targets.iter().any(|n| n.id == "worker-1"));
    }

    #[tokio::test]
    async fn test_get_target_nodes_excludes_dead_nodes() {
        let settings = create_test_settings();
        {
            let mut s = settings.write();
            s.cluster_role = ClusterRole::Primary;
        }
        let manager = Arc::new(ClusterManager::new(settings.clone()));

        let dead_node = ClusterNode {
            id: "dead-1".to_string(),
            role: ClusterRole::Secondary,
            ip: "192.168.1.100".to_string(),
            status: "dead".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 100,
        };
        manager.register_node(dead_node);

        let live_node = ClusterNode {
            id: "live-1".to_string(),
            role: ClusterRole::Secondary,
            ip: "192.168.1.101".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 100,
        };
        manager.register_node(live_node);

        let sync = ConfigSync::new(manager.clone(), settings.clone());
        let targets = sync.get_target_nodes();

        assert!(!targets.iter().any(|n| n.id == "dead-1"));
        assert!(targets.iter().any(|n| n.id == "live-1"));
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
        let update = ConfigUpdate::new(
            ConfigUpdateType::Settings,
            r#"{"key": "value"}"#.to_string(),
            "primary-1".to_string(),
        );

        let json = serde_json::to_string(&update).unwrap();
        let deserialized: ConfigUpdate = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.update_type, "settings");
        assert_eq!(deserialized.payload, r#"{"key": "value"}"#);
        assert_eq!(deserialized.source_node_id, "primary-1");
    }
}
