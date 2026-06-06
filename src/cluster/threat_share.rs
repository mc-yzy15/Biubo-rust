#![cfg(feature = "cluster-mode")]

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};

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
    #[cfg(test)]
    fn new(ip: String, attack_type: String, severity: String, source_node_id: String) -> Self {
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
pub struct BlockedIPEntry {
    pub ip: String,
    pub expires_at: DateTime<Utc>,
}

pub struct ThreatIntelligenceShare {
    pub local_blocklist: DashMap<String, BlockedIPEntry>,
    pub event_log: DashMap<String, ThreatEvent>,
    pub event_count: AtomicUsize,
}

impl ThreatIntelligenceShare {
    pub fn receive_threat_event(&self, event: &ThreatEvent) {
        tracing::info!(
            "[ThreatShare] Received threat event from node {}: ip={}, attack_type={}, correlation_id={}",
            event.source_node_id,
            event.ip,
            event.attack_type,
            event.correlation_id
        );

        self.log_threat_event(event.clone());

        self.local_blocklist.insert(
            event.ip.clone(),
            BlockedIPEntry {
                ip: event.ip.clone(),
                expires_at: Utc::now() + chrono::Duration::seconds(IP_BLOCKLIST_TTL_SECS as i64),
            },
        );

        tracing::info!(
            "[ThreatShare] IP {} added to local blocklist from threat event {}",
            event.ip,
            event.id
        );
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

    fn log_threat_event(&self, event: ThreatEvent) {
        if self.event_log.len() >= MAX_THREAT_EVENTS {
            let keys: Vec<String> = self
                .event_log
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
        let mut events: Vec<ThreatEvent> =
            self.event_log.iter().map(|e| e.value().clone()).collect();

        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        events.into_iter().take(limit).collect()
    }

    pub fn get_event_count(&self) -> usize {
        self.event_count.load(Ordering::Relaxed)
    }

    pub fn get_blocked_ip_count(&self) -> usize {
        self.local_blocklist.len()
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn create_test_share() -> ThreatIntelligenceShare {
        ThreatIntelligenceShare {
            local_blocklist: DashMap::new(),
            event_log: DashMap::new(),
            event_count: AtomicUsize::new(0),
        }
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

    #[tokio::test]
    async fn test_threat_intelligence_share_initialization() {
        let share = create_test_share();

        assert_eq!(share.local_blocklist.len(), 0);
        assert_eq!(share.event_log.len(), 0);
        assert_eq!(share.get_event_count(), 0);
    }

    #[tokio::test]
    async fn test_receive_threat_event_blocks_ip() {
        let share = create_test_share();

        let event = ThreatEvent::new(
            "10.0.0.50".to_string(),
            "xss".to_string(),
            "medium".to_string(),
            "node-2".to_string(),
        );

        share.receive_threat_event(&event);

        assert_eq!(share.get_blocked_ip_count(), 1);
        assert_eq!(share.get_event_count(), 1);
    }

    #[tokio::test]
    async fn test_receive_multiple_threat_events() {
        let share = create_test_share();

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
    }

    #[tokio::test]
    async fn test_get_recent_events() {
        let share = create_test_share();

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
}
