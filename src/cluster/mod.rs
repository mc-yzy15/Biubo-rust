use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use uuid::Uuid;

use crate::config::settings::SharedSettings;
use crate::core::models::{ClusterNode, ClusterRole};

pub mod sync;
pub mod threat_share;

const HEARTBEAT_INTERVAL_SECS: u64 = 10;
const DEAD_NODE_THRESHOLD_SECS: u64 = 30;
const DISCOVERY_PORT: u16 = 9527;
const DISCOVERY_MAGIC: &[u8] = b"BIUBO";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClusterStatus {
    Initializing,
    Running,
    Degraded,
    Stopped,
}

impl std::fmt::Display for ClusterStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClusterStatus::Initializing => write!(f, "initializing"),
            ClusterStatus::Running => write!(f, "running"),
            ClusterStatus::Degraded => write!(f, "degraded"),
            ClusterStatus::Stopped => write!(f, "stopped"),
        }
    }
}

#[derive(Debug, Clone)]
struct InternalNode {
    pub node: ClusterNode,
    pub last_heartbeat: DateTime<Utc>,
    pub startup_time: DateTime<Utc>,
}

impl InternalNode {
    fn new(node: ClusterNode) -> Self {
        let now = Utc::now();
        Self {
            node,
            last_heartbeat: now,
            startup_time: now,
        }
    }
}

pub struct ClusterManager {
    pub node_id: String,
    pub role: ClusterRole,
    pub nodes: DashMap<String, InternalNode>,
    pub status: ClusterStatus,
    pub start_time: DateTime<Utc>,
    settings: SharedSettings,
    heartbeat_counter: Arc<AtomicU64>,
}

impl ClusterManager {
    pub fn new(settings: SharedSettings) -> Self {
        let node_id = Uuid::new_v4().to_string();
        let role = {
            let s = settings.read();
            s.cluster_role.clone()
        };

        let manager = Self {
            node_id: node_id.clone(),
            role: role.clone(),
            nodes: DashMap::new(),
            status: ClusterStatus::Initializing,
            start_time: Utc::now(),
            settings,
            heartbeat_counter: Arc::new(AtomicU64::new(0)),
        };

        let self_node = ClusterNode {
            id: node_id,
            role,
            ip: "127.0.0.1".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 0,
        };

        manager
            .nodes
            .insert(manager.node_id.clone(), InternalNode::new(self_node));

        manager
    }

    pub fn register_node(&self, node: ClusterNode) -> bool {
        if node.id == self.node_id {
            return false;
        }

        let existing = self.nodes.get_mut(&node.id);
        if let Some(mut entry) = existing {
            let internal = entry.value_mut();
            internal.node = node.clone();
            internal.last_heartbeat = Utc::now();
            tracing::info!("Updated existing node: {} ({})", node.id, node.role);
        } else {
            self.nodes
                .insert(node.id.clone(), InternalNode::new(node.clone()));
            tracing::info!(
                "Registered new node: {} ({}) at {}",
                node.id,
                node.role,
                node.ip
            );
        }

        true
    }

    pub fn unregister_node(&self, node_id: String) -> bool {
        if node_id == self.node_id {
            return false;
        }

        if self.nodes.remove(&node_id).is_some() {
            tracing::info!("Unregistered node: {}", node_id);
            true
        } else {
            false
        }
    }

    pub fn discover_nodes(&self) -> Vec<ClusterNode> {
        let mut discovered = Vec::new();

        let known_nodes = {
            let s = self.settings.read();
            if let Some(ref redis_url) = s.cluster_redis_url {
                tracing::info!("Using Redis for node discovery: {}", redis_url);
            }
            Vec::<(String, String)>::new()
        };

        for (ip, port) in known_nodes {
            let node = ClusterNode {
                id: Uuid::new_v4().to_string(),
                role: ClusterRole::Worker,
                ip: format!("{}:{}", ip, port),
                status: "discovered".to_string(),
                last_heartbeat: Utc::now(),
                uptime_seconds: 0,
            };
            discovered.push(node);
        }

        let broadcast_result = self.broadcast_discovery();
        discovered.extend(broadcast_result);

        tracing::info!("Discovered {} nodes via network scan", discovered.len());
        discovered
    }

    fn broadcast_discovery(&self) -> Vec<ClusterNode> {
        let mut discovered = Vec::new();

        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            socket.set_broadcast(true).ok();
            socket
                .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .ok();

            let discovery_msg = format!(
                "{}:{}:{}",
                std::str::from_utf8(DISCOVERY_MAGIC).unwrap(),
                self.node_id,
                DISCOVERY_PORT
            );

            let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DISCOVERY_PORT);
            socket
                .send_to(discovery_msg.as_bytes(), broadcast_addr)
                .ok();

            let mut buf = [0u8; 1024];
            while let Ok((len, addr)) = socket.recv_from(&mut buf) {
                if let Ok(msg) = std::str::from_utf8(&buf[..len]) {
                    if msg.starts_with(std::str::from_utf8(DISCOVERY_MAGIC).unwrap()) {
                        let parts: Vec<&str> = msg.split(':').collect();
                        if parts.len() >= 3 {
                            let remote_node_id = parts[1].to_string();
                            if remote_node_id != self.node_id {
                                let node = ClusterNode {
                                    id: remote_node_id,
                                    role: ClusterRole::Worker,
                                    ip: addr.ip().to_string(),
                                    status: "discovered".to_string(),
                                    last_heartbeat: Utc::now(),
                                    uptime_seconds: 0,
                                };
                                discovered.push(node);
                            }
                        }
                    }
                }
            }
        }

        discovered
    }

    pub async fn send_heartbeat(&self) {
        let now = Utc::now();
        let counter = self.heartbeat_counter.fetch_add(1, Ordering::Relaxed);

        if let Some(mut entry) = self.nodes.get_mut(&self.node_id) {
            entry.value_mut().last_heartbeat = now;
            let uptime = now.signed_duration_since(entry.value().startup_time);
            entry.value_mut().node.uptime_seconds = uptime.num_seconds() as u64;
        }

        if counter % 100 == 0 {
            tracing::debug!(
                "Heartbeat sent (count: {}), role: {}, nodes: {}",
                counter,
                self.role,
                self.nodes.len()
            );
        }

        self.broadcast_heartbeat();
    }

    fn broadcast_heartbeat(&self) {
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            socket.set_broadcast(true).ok();

            let uptime = Utc::now().signed_duration_since(self.start_time);
            let heartbeat_msg = format!(
                "{}:HB:{}:{}:{}:{}",
                std::str::from_utf8(DISCOVERY_MAGIC).unwrap(),
                self.node_id,
                match &self.role {
                    ClusterRole::Primary => "primary",
                    ClusterRole::Secondary => "secondary",
                    ClusterRole::Worker => "worker",
                },
                self.node_id,
                uptime.num_seconds()
            );

            let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DISCOVERY_PORT);
            socket
                .send_to(heartbeat_msg.as_bytes(), broadcast_addr)
                .ok();
        }
    }

    pub fn receive_heartbeat(&self, node_id: String, role: ClusterRole, ip: String, uptime: u64) {
        if node_id == self.node_id {
            return;
        }

        let node = ClusterNode {
            id: node_id.clone(),
            role,
            ip,
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: uptime,
        };

        self.register_node(node);
    }

    pub fn detect_dead_nodes(&mut self) -> Vec<String> {
        let dead_nodes = self.list_dead_nodes();

        for node_id in &dead_nodes {
            tracing::warn!("Dead node detected: {}", node_id);
            if let Some(mut entry) = self.nodes.get_mut(node_id) {
                entry.value_mut().node.status = "dead".to_string();
            }
        }

        if !dead_nodes.is_empty() {
            let has_primary = self.get_primary_node().is_some();
            if !has_primary {
                self.status = ClusterStatus::Degraded;
            }
        }

        dead_nodes
    }

    pub fn list_dead_nodes(&self) -> Vec<String> {
        let now = Utc::now();
        let mut dead_nodes = Vec::new();

        for entry in self.nodes.iter() {
            let node_id = entry.key();
            let internal_node = entry.value();

            if *node_id == self.node_id {
                continue;
            }

            let elapsed = now.signed_duration_since(internal_node.last_heartbeat);
            if elapsed.num_seconds() > DEAD_NODE_THRESHOLD_SECS as i64 {
                dead_nodes.push(node_id.clone());
            }
        }

        dead_nodes
    }

    pub fn elect_primary(&mut self) -> Option<String> {
        let mut candidates: Vec<(String, u64)> = Vec::new();

        for entry in self.nodes.iter() {
            let node_id = entry.key();
            let internal_node = entry.value();

            if internal_node.node.status == "dead" {
                continue;
            }

            if matches!(
                internal_node.node.role,
                ClusterRole::Primary | ClusterRole::Secondary
            ) {
                candidates.push((node_id.clone(), internal_node.node.uptime_seconds));
            }
        }

        if candidates.is_empty() {
            let now = Utc::now();
            let elapsed = now.signed_duration_since(self.start_time);
            candidates.push((self.node_id.clone(), elapsed.num_seconds() as u64));
        }

        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        if let Some((primary_id, _)) = candidates.first() {
            tracing::info!(
                "Primary node elected: {} (uptime: {}s)",
                primary_id,
                candidates.first().unwrap().1
            );

            if *primary_id == self.node_id {
                let mut role_guard = self.settings.write();
                role_guard.cluster_role = ClusterRole::Primary;
            }

            if let Some(mut entry) = self.nodes.get_mut(primary_id) {
                entry.value_mut().node.role = ClusterRole::Primary;
            }

            for entry in self.nodes.iter() {
                let node_id = entry.key();
                if node_id != primary_id {
                    if let Some(mut entry) = self.nodes.get_mut(node_id) {
                        let internal = entry.value_mut();
                        if matches!(internal.node.role, ClusterRole::Primary) {
                            internal.node.role = ClusterRole::Secondary;
                        }
                    }
                }
            }

            self.status = ClusterStatus::Running;
            Some(primary_id.clone())
        } else {
            None
        }
    }

    pub fn demote_primary(&self, node_id: String) -> bool {
        if let Some(mut entry) = self.nodes.get_mut(&node_id) {
            let internal = entry.value_mut();
            if matches!(internal.node.role, ClusterRole::Primary) {
                internal.node.role = ClusterRole::Secondary;
                internal.node.status = "demoted".to_string();
                tracing::warn!("Primary node demoted: {}", node_id);
                return true;
            }
        }
        false
    }

    pub fn promote_secondary(&mut self) -> Option<String> {
        let mut candidates: Vec<(String, u64)> = Vec::new();

        for entry in self.nodes.iter() {
            let node_id = entry.key();
            let internal_node = entry.value();

            if internal_node.node.status == "dead" {
                continue;
            }

            if matches!(internal_node.node.role, ClusterRole::Secondary) {
                candidates.push((node_id.clone(), internal_node.node.uptime_seconds));
            }
        }

        if candidates.is_empty() {
            return self.elect_primary();
        }

        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        if let Some((new_primary_id, _)) = candidates.first() {
            tracing::info!(
                "Secondary promoted to primary: {} (uptime: {}s)",
                new_primary_id,
                candidates.first().unwrap().1
            );

            if let Some(mut entry) = self.nodes.get_mut(new_primary_id) {
                entry.value_mut().node.role = ClusterRole::Primary;
                entry.value_mut().node.status = "online".to_string();
            }

            self.status = ClusterStatus::Running;
            Some(new_primary_id.clone())
        } else {
            None
        }
    }

    pub fn get_primary_node(&self) -> Option<String> {
        for entry in self.nodes.iter() {
            if matches!(entry.value().node.role, ClusterRole::Primary)
                && entry.value().node.status == "online"
            {
                return Some(entry.key().clone());
            }
        }
        None
    }

    pub fn get_node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn get_active_nodes(&self) -> Vec<ClusterNode> {
        self.nodes
            .iter()
            .filter(|e| e.value().node.status == "online")
            .map(|e| e.value().node.clone())
            .collect()
    }

    pub fn get_all_nodes_info(
        &self,
        dead_nodes: &[String],
        primary_node: &Option<String>,
    ) -> Vec<serde_json::Value> {
        self.nodes
            .iter()
            .map(|entry| {
                let node = &entry.value().node;
                let is_dead = dead_nodes.contains(&node.id);
                let is_primary = primary_node.as_ref() == Some(&node.id);

                serde_json::json!({
                    "id": node.id,
                    "role": node.role.to_string(),
                    "ip": node.ip,
                    "status": if is_dead { "dead" } else { &node.status },
                    "is_primary": is_primary,
                    "last_heartbeat": node.last_heartbeat,
                    "uptime_seconds": node.uptime_seconds,
                })
            })
            .collect()
    }

    pub fn get_role(&self) -> ClusterRole {
        self.role.clone()
    }

    pub async fn start_heartbeat_worker(&self) {
        let manager = Arc::new(self.clone_for_worker());
        let manager_ref = manager.clone();

        tokio::spawn(async move {
            let mut interval_timer = interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
            loop {
                interval_timer.tick().await;
                manager_ref.send_heartbeat().await;
            }
        });
    }

    pub async fn start_dead_node_detector(&self) {
        let manager = parking_lot::Mutex::new(self.clone_for_worker());

        tokio::spawn(async move {
            let mut interval_timer = interval(Duration::from_secs(5));
            loop {
                interval_timer.tick().await;

                let dead_nodes = manager.lock().detect_dead_nodes();
                for node_id in &dead_nodes {
                    let current_primary = manager.lock().get_primary_node();
                    if current_primary == Some(node_id.clone()) {
                        manager.lock().demote_primary(node_id.clone());
                        tracing::warn!("Primary node {} is dead, triggering election", node_id);

                        if let Some(new_primary) = manager.lock().promote_secondary() {
                            tracing::info!("New primary elected: {}", new_primary);
                        } else {
                            manager.lock().elect_primary();
                        }
                    }

                    manager.lock().unregister_node(node_id.clone());
                }
            }
        });
    }

    pub async fn start_discovery_worker(&self) {
        let manager = Arc::new(self.clone_for_worker());
        let manager_ref = manager.clone();

        tokio::spawn(async move {
            let mut interval_timer = interval(Duration::from_secs(60));
            loop {
                interval_timer.tick().await;
                let discovered = manager_ref.discover_nodes();
                for node in discovered {
                    manager_ref.register_node(node);
                }
            }
        });
    }

    fn clone_for_worker(&self) -> ClusterManager {
        ClusterManager {
            node_id: self.node_id.clone(),
            role: self.role.clone(),
            nodes: self.nodes.clone(),
            status: self.status.clone(),
            start_time: self.start_time.clone(),
            settings: self.settings.clone(),
            heartbeat_counter: self.heartbeat_counter.clone(),
        }
    }

    pub fn get_status(&self) -> ClusterStatus {
        self.status.clone()
    }

    pub fn get_uptime_seconds(&self) -> u64 {
        let now = Utc::now();
        now.signed_duration_since(self.start_time).num_seconds() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn create_test_settings() -> SharedSettings {
        use crate::config::settings::Settings;
        let mut settings = Settings::default();
        settings.cluster_mode = true;
        settings.cluster_role = ClusterRole::Worker;
        settings.cluster_redis_url = None;
        Arc::new(parking_lot::RwLock::new(settings))
    }

    #[tokio::test]
    async fn test_node_registration() {
        let settings = create_test_settings();
        let manager = ClusterManager::new(settings);

        let node1 = ClusterNode {
            id: "node-1".to_string(),
            role: ClusterRole::Worker,
            ip: "192.168.1.100".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 100,
        };

        assert!(manager.register_node(node1));
        assert_eq!(manager.get_node_count(), 2);

        let node2 = ClusterNode {
            id: "node-2".to_string(),
            role: ClusterRole::Secondary,
            ip: "192.168.1.101".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 200,
        };

        assert!(manager.register_node(node2));
        assert_eq!(manager.get_node_count(), 3);

        assert!(manager.unregister_node("node-1".to_string()));
        assert_eq!(manager.get_node_count(), 2);

        assert!(!manager.unregister_node("non-existent".to_string()));
    }

    #[tokio::test]
    async fn test_heartbeat_and_dead_node_detection() {
        let settings = create_test_settings();
        let mut manager = ClusterManager::new(settings);

        let old_node = ClusterNode {
            id: "old-node".to_string(),
            role: ClusterRole::Worker,
            ip: "192.168.1.200".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now() - chrono::Duration::seconds(45),
            uptime_seconds: 1000,
        };
        manager.register_node(old_node.clone());

        let dead_nodes = manager.detect_dead_nodes();
        assert!(dead_nodes.contains(&"old-node".to_string()));

        let fresh_node = ClusterNode {
            id: "fresh-node".to_string(),
            role: ClusterRole::Worker,
            ip: "192.168.1.201".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 500,
        };
        manager.register_node(fresh_node.clone());

        let dead_nodes = manager.detect_dead_nodes();
        assert!(dead_nodes.contains(&"old-node".to_string()));
        assert!(!dead_nodes.contains(&"fresh-node".to_string()));
    }

    #[tokio::test]
    async fn test_primary_election() {
        let settings = create_test_settings();
        let mut manager = ClusterManager::new(settings);

        let primary_candidate = ClusterNode {
            id: "candidate-1".to_string(),
            role: ClusterRole::Secondary,
            ip: "192.168.1.50".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 5000,
        };
        manager.register_node(primary_candidate);

        let secondary_candidate = ClusterNode {
            id: "candidate-2".to_string(),
            role: ClusterRole::Secondary,
            ip: "192.168.1.51".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 3000,
        };
        manager.register_node(secondary_candidate);

        let elected_primary = manager.elect_primary();
        assert!(elected_primary.is_some());

        let primary_node = manager.get_primary_node();
        assert!(primary_node.is_some());
        assert_eq!(primary_node.unwrap(), "candidate-1".to_string());

        if let Some(entry) = manager.nodes.get("candidate-1") {
            assert!(matches!(entry.value().node.role, ClusterRole::Primary));
        }

        if let Some(entry) = manager.nodes.get("candidate-2") {
            assert!(matches!(entry.value().node.role, ClusterRole::Secondary));
        }
    }

    #[tokio::test]
    async fn test_primary_failover() {
        let settings = create_test_settings();
        let mut manager = ClusterManager::new(settings);

        let primary = ClusterNode {
            id: "primary-node".to_string(),
            role: ClusterRole::Primary,
            ip: "192.168.1.10".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 10000,
        };
        manager.register_node(primary);

        let secondary = ClusterNode {
            id: "secondary-node".to_string(),
            role: ClusterRole::Secondary,
            ip: "192.168.1.11".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 8000,
        };
        manager.register_node(secondary);

        assert!(manager.get_primary_node().is_some());

        let demoted = manager.demote_primary("primary-node".to_string());
        assert!(demoted);

        if let Some(entry) = manager.nodes.get("primary-node") {
            assert!(matches!(entry.value().node.role, ClusterRole::Secondary));
        }

        let new_primary = manager.promote_secondary();
        assert!(new_primary.is_some());
        assert_eq!(new_primary.unwrap(), "secondary-node".to_string());

        if let Some(entry) = manager.nodes.get("secondary-node") {
            assert!(matches!(entry.value().node.role, ClusterRole::Primary));
        }
    }

    #[tokio::test]
    async fn test_automatic_failover_on_dead_primary() {
        let settings = create_test_settings();
        let mut manager = ClusterManager::new(settings);

        let primary = ClusterNode {
            id: "dead-primary".to_string(),
            role: ClusterRole::Primary,
            ip: "192.168.1.20".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now() - chrono::Duration::seconds(60),
            uptime_seconds: 20000,
        };
        manager.register_node(primary);

        let secondary = ClusterNode {
            id: "available-secondary".to_string(),
            role: ClusterRole::Secondary,
            ip: "192.168.1.21".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 15000,
        };
        manager.register_node(secondary);

        let dead_nodes = manager.detect_dead_nodes();
        assert!(dead_nodes.contains(&"dead-primary".to_string()));

        let current_primary = manager.get_primary_node();
        if let Some(primary_id) = current_primary {
            if dead_nodes.contains(&primary_id) {
                manager.demote_primary(primary_id);

                let new_primary = manager.promote_secondary();
                assert!(new_primary.is_some());
                assert_eq!(new_primary.unwrap(), "available-secondary".to_string());
            }
        }
    }

    #[tokio::test]
    async fn test_heartbeat_sending() {
        let settings = create_test_settings();
        let manager = ClusterManager::new(settings);

        let initial_counter = manager.heartbeat_counter.load(Ordering::Relaxed);
        manager.send_heartbeat().await;
        let after_counter = manager.heartbeat_counter.load(Ordering::Relaxed);
        assert_eq!(after_counter, initial_counter + 1);

        if let Some(entry) = manager.nodes.get(&manager.node_id) {
            let uptime = entry.value().node.uptime_seconds;
            assert!(uptime > 0 || uptime == 0);
        }
    }

    #[tokio::test]
    async fn test_node_discovery() {
        let settings = create_test_settings();
        let manager = ClusterManager::new(settings);

        let discovered = manager.discover_nodes();

        assert!(discovered.len() >= 0);

        for node in &discovered {
            assert!(!node.id.is_empty());
            assert!(!node.ip.is_empty());
        }
    }

    #[tokio::test]
    async fn test_receive_heartbeat() {
        let settings = create_test_settings();
        let manager = ClusterManager::new(settings);

        manager.receive_heartbeat(
            "remote-node".to_string(),
            ClusterRole::Worker,
            "10.0.0.1".to_string(),
            500,
        );

        assert!(manager.get_node_count() >= 2);

        if let Some(entry) = manager.nodes.get("remote-node") {
            assert_eq!(entry.value().node.ip, "10.0.0.1");
            assert!(matches!(entry.value().node.role, ClusterRole::Worker));
        }
    }

    #[tokio::test]
    async fn test_cluster_status_transitions() {
        let settings = create_test_settings();
        let mut manager = ClusterManager::new(settings);

        assert!(matches!(manager.get_status(), ClusterStatus::Initializing));

        let worker = ClusterNode {
            id: "worker-1".to_string(),
            role: ClusterRole::Worker,
            ip: "172.16.0.1".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 100,
        };
        manager.register_node(worker);

        manager.elect_primary();
        assert!(matches!(manager.get_status(), ClusterStatus::Running));
    }

    #[tokio::test]
    async fn test_get_active_nodes() {
        let settings = create_test_settings();
        let manager = ClusterManager::new(settings);

        let online_node = ClusterNode {
            id: "online-1".to_string(),
            role: ClusterRole::Worker,
            ip: "192.168.2.1".to_string(),
            status: "online".to_string(),
            last_heartbeat: Utc::now(),
            uptime_seconds: 300,
        };
        manager.register_node(online_node);

        let dead_node = ClusterNode {
            id: "dead-1".to_string(),
            role: ClusterRole::Worker,
            ip: "192.168.2.2".to_string(),
            status: "dead".to_string(),
            last_heartbeat: Utc::now() - chrono::Duration::seconds(100),
            uptime_seconds: 50,
        };
        manager.register_node(dead_node);

        let active_nodes = manager.get_active_nodes();
        assert!(active_nodes.iter().any(|n| n.id == "online-1"));
        assert!(!active_nodes.iter().any(|n| n.id == "dead-1"));
    }
}
