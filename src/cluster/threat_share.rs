use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

use crate::cluster::ClusterManager;
use crate::config::settings::SharedSettings;

const THREAT_SHARE_CHANNEL: &str = "biubo:cluster:threat_share";
const MAX_THREAT_EVENTS: usize = 1000;
const IP_BLOCKLIST_TTL_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub ip: String,
    pub attack_type: String,
    pub severity: String,
    pub timestamp: DateTime<Utc>,
    pub source_node_id: String,
    pub correlation_id: String,
}

impl ThreatEvent {
    pub fn new(ip: String, attack_type: String, severity: String, source_node_id: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            ip,
            attack_type,
            severity,
            timestamp: Utc::now(),
            source_node_id,
            correlation_id: Uuid::new_v4().to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct BlockedIPEntry {
    pub ip: String,
    pub attack_type: String,
    pub blocked_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub source_node_id: String,
    pub event_id: String,
}

pub struct ThreatIntelligenceShare {
    pub manager: Arc<ClusterManager>,
    pub settings: SharedSettings,
    pub redis_client: Option<redis::aio::ConnectionManager>,
    pub local_blocklist: DashMap<String, BlockedIPEntry>,
    pub event_log: DashMap<String, ThreatEvent>,
    pub event_count: AtomicUsize,
    pub http_client: reqwest::Client,
}

impl ThreatIntelligenceShare {
    pub fn new(manager: Arc<ClusterManager>, settings: SharedSettings) -> Self {
        Self {
            manager,
            settings,
            redis_client: None,
            local_blocklist: DashMap::new(),
            event_log: DashMap::new(),
            event_count: AtomicUsize::new(0),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to build HTTP client for threat sharing"),
        }
    }

    pub async fn with_redis(&mut self, redis_url: &str) -> bool {
        match redis::Client::open(redis_url) {
            Ok(client) => match client.get_connection_manager().await {
                Ok(manager) => {
                    self.redis_client = Some(manager);
                    tracing::info!("[ThreatShare] Redis connection established for threat intelligence sharing");
                    true
                }
                Err(e) => {
                    tracing::warn!("[ThreatShare] Failed to connect to Redis for threat sharing: {}", e);
                    false
                }
            },
            Err(e) => {
                tracing::warn!("[ThreatShare] Invalid Redis URL for threat sharing: {}", e);
                false
            }
        }
    }

    pub async fn broadcast_threat_event(&self, event: &ThreatEvent) -> Result<usize, String> {
        tracing::info!(
            "[ThreatShare] Broadcasting threat event: ip={}, attack_type={}, severity={}, correlation_id={}",
            event.ip,
            event.attack_type,
            event.severity,
            event.correlation_id
        );

        self.log_threat_event(event.clone());

        self.local_blocklist.insert(event.ip.clone(), BlockedIPEntry {
            ip: event.ip.clone(),
            attack_type: event.attack_type.clone(),
            blocked_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(IP_BLOCKLIST_TTL_SECS as i64),
            source_node_id: event.source_node_id.clone(),
            event_id: event.id.clone(),
        });

        let target_nodes = self.manager.get_active_nodes()
            .into_iter()
            .filter(|node| node.id != self.manager.node_id)
            .collect::<Vec<_>>();

        if target_nodes.is_empty() {
            tracing::info!("[ThreatShare] No target nodes for threat broadcast");
            return Ok(0);
        }

        if self.redis_client.is_some() {
            match self.broadcast_via_redis(event).await {
                Ok(_) => {
                    tracing::info!("[ThreatShare] Threat event broadcast via Redis to {} nodes", target_nodes.len());
                }
                Err(e) => {
                    tracing::warn!("[ThreatShare] Redis broadcast failed, falling back to HTTP: {}", e);
                    self.broadcast_via_http(event, &target_nodes).await;
                }
            }
        } else {
            tracing::info!("[ThreatShare] Broadcasting threat event via HTTP to {} nodes", target_nodes.len());
            self.broadcast_via_http(event, &target_nodes).await;
        }

        Ok(target_nodes.len())
    }

    async fn broadcast_via_redis(&self, event: &ThreatEvent) -> Result<(), String> {
        let redis_client = self.redis_client
            .as_ref()
            .ok_or_else(|| "Redis client not available".to_string())?;

        let message = serde_json::to_string(event)
            .map_err(|e| format!("Failed to serialize threat event: {}", e))?;

        let mut client = redis_client.clone();
        let _: () = redis::cmd("PUBLISH")
            .arg(THREAT_SHARE_CHANNEL)
            .arg(&message)
            .query_async(&mut client)
            .await
            .map_err(|e| format!("Redis publish failed: {}", e))?;

        Ok(())
    }

    async fn broadcast_via_http(&self, event: &ThreatEvent, nodes: &[crate::core::models::ClusterNode]) {
        let message = match serde_json::to_string(event) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("[ThreatShare] Failed to serialize threat event for HTTP: {}", e);
                return;
            }
        };

        for node in nodes {
            let node_ip = node.ip.clone();
            let msg = message.clone();
            let client = self.http_client.clone();

            tokio::spawn(async move {
                let url = format!("http://{}/api/cluster/threat-event", node_ip);
                match client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("X-Cluster-Node-Id", &node.id)
                    .body(msg)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            tracing::info!("[ThreatShare] Threat event sent to node {}", node.id);
                        } else {
                            tracing::warn!(
                                "[ThreatShare] HTTP threat share failed for node {}: status {}",
                                node.id,
                                resp.status()
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("[ThreatShare] HTTP threat share error for node {}: {}", node.id, e);
                    }
                }
            });
        }
    }

    pub fn receive_threat_event(&self, event: &ThreatEvent) {
        tracing::info!(
            "[ThreatShare] Received threat event from node {}: ip={}, attack_type={}, correlation_id={}",
            event.source_node_id,
            event.ip,
            event.attack_type,
            event.correlation_id
        );

        self.log_threat_event(event.clone());

        self.local_blocklist.insert(event.ip.clone(), BlockedIPEntry {
            ip: event.ip.clone(),
            attack_type: event.attack_type.clone(),
            blocked_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(IP_BLOCKLIST_TTL_SECS as i64),
            source_node_id: event.source_node_id.clone(),
            event_id: event.id.clone(),
        });

        tracing::info!(
            "[ThreatShare] IP {} added to local blocklist from threat event {}",
            event.ip,
            event.id
        );
    }

    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        if let Some(entry) = self.local_blocklist.get(ip) {
            let is_expired = Utc::now() > entry.expires_at;
            if is_expired {
                self.local_blocklist.remove(ip);
                false
            } else {
                true
            }
        } else {
            false
        }
    }

    pub fn get_blocked_ips(&self) -> Vec<String> {
        let now = Utc::now();
        let mut blocked = Vec::new();

        self.local_blocklist.retain(|_ip, entry| {
            if now > entry.expires_at {
                false
            } else {
                blocked.push(entry.ip.clone());
                true
            }
        });

        blocked
    }

    pub async fn sync_ip_blocklist(&self) -> Result<usize, String> {
        let blocked_ips = self.get_blocked_ips();

        if blocked_ips.is_empty() {
            tracing::info!("[ThreatShare] No blocked IPs to sync");
            return Ok(0);
        }

        let sync_payload = serde_json::json!({
            "node_id": self.manager.node_id,
            "blocked_ips": blocked_ips,
            "timestamp": Utc::now(),
        });

        let payload_string = serde_json::to_string(&sync_payload)
            .map_err(|e| format!("Failed to serialize blocklist: {}", e))?;

        let update = crate::cluster::sync::ConfigUpdate::new(
            crate::cluster::sync::ConfigUpdateType::Blacklist,
            payload_string,
            self.manager.node_id.clone(),
        );

        let config_sync = crate::cluster::sync::ConfigSync::new(
            self.manager.clone(),
            self.settings.clone(),
        );

        let acked_count = config_sync.broadcast_config_change(update).await?;

        tracing::info!(
            "[ThreatShare] Synced {} blocked IPs to cluster, {} nodes acknowledged",
            blocked_ips.len(),
            acked_count
        );

        Ok(blocked_ips.len())
    }

    pub fn generate_correlation_id() -> String {
        Uuid::new_v4().to_string()
    }

    fn log_threat_event(&self, event: ThreatEvent) {
        if self.event_log.len() >= MAX_THREAT_EVENTS {
            let keys: Vec<String> = self.event_log
                .iter()
                .take(MAX_THREAT_EVENTS / 2)
                .map(|e| e.key().clone())
                .collect();
            for key in keys {
                self.event_log.remove(&key);
            }
        }

        self.event_log.insert(event.id.clone(), event);
        self.event_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_recent_events(&self, limit: usize) -> Vec<ThreatEvent> {
        let mut events: Vec<ThreatEvent> = self.event_log
            .iter()
            .map(|e| e.value().clone())
            .collect();

        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        events.into_iter().take(limit).collect()
    }

    pub fn get_event_count(&self) -> usize {
        self.event_count.load(Ordering::Relaxed)
    }

    pub fn get_blocked_ip_count(&self) -> usize {
        self.local_blocklist.len()
    }

    pub fn cleanup_expired_blocklist(&self) -> usize {
        let now = Utc::now();
        let mut removed_count = 0;

        self.local_blocklist.retain(|_ip, entry| {
            if now > entry.expires_at {
                removed_count += 1;
                false
            } else {
                true
            }
        });

        if removed_count > 0 {
            tracing::info!(
                "[ThreatShare] Cleaned up {} expired blocklist entries",
                removed_count
            );
        }

        removed_count
    }

    pub fn start_blocklist_gc_worker(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let share = Arc::clone(self);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                share.cleanup_expired_blocklist();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::ClusterManager;
    use crate::config::settings::Settings;
    use crate::core::models::ClusterRole;
    use std::sync::Arc;

    fn create_test_settings() -> SharedSettings {
        let mut settings = Settings::default();
        settings.cluster_mode = true;
        settings.cluster_role = ClusterRole::Worker;
        settings.cluster_redis_url = None;
        Arc::new(parking_lot::RwLock::new(settings))
    }

    fn create_test_share() -> (Arc<ClusterManager>, ThreatIntelligenceShare) {
        let settings = create_test_settings();
        let manager = Arc::new(ClusterManager::new(settings.clone()));
        let share = ThreatIntelligenceShare::new(manager.clone(), settings.clone());
        (manager, share)
    }

    #[test]
    fn test_threat_event_creation() {
        let event = ThreatEvent::new(
            "192.168.1.100".to_string(),
            "sql_injection".to_string(),
            "high".to_string(),
            "node-1".to_string(),
        );

        assert!(!event.id.is_empty());
        assert_eq!(event.ip, "192.168.1.100");
        assert_eq!(event.attack_type, "sql_injection");
        assert_eq!(event.severity, "high");
        assert_eq!(event.source_node_id, "node-1");
        assert!(!event.correlation_id.is_empty());
    }

    #[test]
    fn test_correlation_id_generation() {
        let id1 = ThreatIntelligenceShare::generate_correlation_id();
        let id2 = ThreatIntelligenceShare::generate_correlation_id();

        assert!(!id1.is_empty());
        assert!(!id2.is_empty());
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_threat_intelligence_share_initialization() {
        let (_manager, share) = create_test_share();

        assert!(share.redis_client.is_none());
        assert_eq!(share.local_blocklist.len(), 0);
        assert_eq!(share.event_log.len(), 0);
        assert_eq!(share.get_event_count(), 0);
    }

    #[tokio::test]
    async fn test_receive_threat_event_blocks_ip() {
        let (_manager, share) = create_test_share();

        let event = ThreatEvent::new(
            "10.0.0.50".to_string(),
            "xss".to_string(),
            "medium".to_string(),
            "node-2".to_string(),
        );

        share.receive_threat_event(&event);

        assert!(share.is_ip_blocked("10.0.0.50"));
        assert_eq!(share.get_blocked_ip_count(), 1);
        assert_eq!(share.get_event_count(), 1);
    }

    #[tokio::test]
    async fn test_receive_multiple_threat_events() {
        let (_manager, share) = create_test_share();

        let ips = vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"];

        for ip in &ips {
            let event = ThreatEvent::new(
                ip.to_string(),
                "scanner".to_string(),
                "low".to_string(),
                "node-3".to_string(),
            );
            share.receive_threat_event(&event);
        }

        assert_eq!(share.get_blocked_ip_count(), 3);
        assert_eq!(share.get_event_count(), 3);

        for ip in &ips {
            assert!(share.is_ip_blocked(ip));
        }
    }

    #[tokio::test]
    async fn test_blocked_ip_expiration() {
        let (_manager, share) = create_test_share();

        let event = ThreatEvent::new(
            "10.0.0.100".to_string(),
            "rce".to_string(),
            "critical".to_string(),
            "node-4".to_string(),
        );

        share.receive_threat_event(&event);
        assert!(share.is_ip_blocked("10.0.0.100"));

        let entry = share.local_blocklist.get_mut("10.0.0.100").unwrap();
        entry.value_mut().expires_at = Utc::now() - chrono::Duration::seconds(100);
        drop(entry);

        assert!(!share.is_ip_blocked("10.0.0.100"));
    }

    #[tokio::test]
    async fn test_get_recent_events() {
        let (_manager, share) = create_test_share();

        for i in 0..5 {
            let event = ThreatEvent::new(
                format!("10.0.0.{}", i),
                format!("attack_type_{}", i),
                "high".to_string(),
                "node-5".to_string(),
            );
            share.receive_threat_event(&event);
        }

        let recent = share.get_recent_events(3);
        assert_eq!(recent.len(), 3);

        let all = share.get_recent_events(10);
        assert_eq!(all.len(), 5);
    }

    #[tokio::test]
    async fn test_cleanup_expired_blocklist() {
        let (_manager, share) = create_test_share();

        let event1 = ThreatEvent::new(
            "10.0.0.200".to_string(),
            "sqli".to_string(),
            "high".to_string(),
            "node-6".to_string(),
        );
        share.receive_threat_event(&event1);

        let entry = share.local_blocklist.get_mut("10.0.0.200").unwrap();
        entry.value_mut().expires_at = Utc::now() - chrono::Duration::seconds(100);
        drop(entry);

        let event2 = ThreatEvent::new(
            "10.0.0.201".to_string(),
            "xss".to_string(),
            "medium".to_string(),
            "node-6".to_string(),
        );
        share.receive_threat_event(&event2);

        let cleaned = share.cleanup_expired_blocklist();
        assert_eq!(cleaned, 1);
        assert_eq!(share.get_blocked_ip_count(), 1);
        assert!(share.is_ip_blocked("10.0.0.201"));
    }

    #[tokio::test]
    async fn test_broadcast_threat_event_with_no_nodes() {
        let (_manager, share) = create_test_share();

        let event = ThreatEvent::new(
            "10.0.0.50".to_string(),
            "scanner".to_string(),
            "low".to_string(),
            share.manager.node_id.clone(),
        );

        let result = share.broadcast_threat_event(&event).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
        assert!(share.is_ip_blocked("10.0.0.50"));
    }
}