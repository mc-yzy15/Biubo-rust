use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};

use crate::api::app::AppState;
use crate::api::middleware::api_key_auth::get_api_key_from_headers;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WafEvent {
    Detection {
        ip: String,
        attack_type: String,
        severity: String,
        rule_id: Option<String>,
        timestamp: String,
    },
    Block {
        ip: String,
        reason: String,
        timestamp: String,
    },
    Unblock {
        ip: String,
        timestamp: String,
    },
    ThreatScoreUpdate {
        ip: String,
        score: f64,
        timestamp: String,
    },
    Cluster {
        node_id: String,
        event_type: String,
        timestamp: String,
    },
    ConfigChange {
        config_type: String,
        timestamp: String,
    },
}

impl WafEvent {
    pub fn is_stats_related(&self) -> bool {
        matches!(
            self,
            WafEvent::Detection { .. }
                | WafEvent::Block { .. }
                | WafEvent::Unblock { .. }
                | WafEvent::ThreatScoreUpdate { .. }
        )
    }

    pub fn is_cluster_related(&self) -> bool {
        matches!(self, WafEvent::Cluster { .. })
    }

    pub fn new_detection(
        ip: String,
        attack_type: String,
        severity: String,
        rule_id: Option<String>,
    ) -> Self {
        WafEvent::Detection {
            ip,
            attack_type,
            severity,
            rule_id,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn new_block(ip: String, reason: String) -> Self {
        WafEvent::Block {
            ip,
            reason,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn new_unblock(ip: String) -> Self {
        WafEvent::Unblock {
            ip,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn new_threat_score(ip: String, score: f64) -> Self {
        WafEvent::ThreatScoreUpdate {
            ip,
            score,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn new_cluster(node_id: String, event_type: String) -> Self {
        WafEvent::Cluster {
            node_id,
            event_type,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn new_config_change(config_type: String) -> Self {
        WafEvent::ConfigChange {
            config_type,
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Clone)]
pub struct EventBroadcaster {
    sender: broadcast::Sender<WafEvent>,
    clients: Arc<DashMap<u64, WsClient>>,
    next_client_id: Arc<std::sync::atomic::AtomicU64>,
}

#[derive(Clone)]
pub struct WsClient {
    api_key: String,
    permissions: Vec<String>,
}

impl EventBroadcaster {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1000);
        Self {
            sender,
            clients: Arc::new(DashMap::new()),
            next_client_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub async fn broadcast(&self, event: WafEvent) {
        let _ = self.sender.send(event);
    }

    pub fn add_client(
        &self,
        api_key: String,
        permissions: Vec<String>,
    ) -> (u64, broadcast::Receiver<WafEvent>) {
        let client_id = self
            .next_client_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let perm_count = permissions.len();
        self.clients.insert(
            client_id,
            WsClient {
                api_key,
                permissions,
            },
        );
        let receiver = self.sender.subscribe();
        tracing::info!(
            "WebSocket client connected: id={} with {} permissions",
            client_id,
            perm_count
        );
        (client_id, receiver)
    }

    pub fn remove_client(&self, client_id: u64) {
        self.clients.remove(&client_id);
        tracing::info!("WebSocket client disconnected: id={}", client_id);
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    pub fn should_receive_event(permissions: &[String], event: &WafEvent) -> bool {
        let has_read = permissions.iter().any(|p| p == "read" || p == "*");
        let has_stats = permissions.iter().any(|p| p == "stats" || p == "*");
        let has_events = permissions.iter().any(|p| p == "events" || p == "*");

        if has_read {
            return true;
        }

        if has_stats && event.is_stats_related() {
            return true;
        }

        if has_events {
            if event.is_stats_related() || event.is_cluster_related() {
                return true;
            }
        }

        false
    }
}

#[derive(Deserialize)]
pub struct WebSocketQuery {
    api_key: Option<String>,
}

pub fn websocket_events_handler(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/events", get(handle_websocket_upgrade))
        .with_state(state)
}

async fn handle_websocket_upgrade(
    ws: WebSocketUpgrade,
    Query(query): Query<WebSocketQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let api_key = query
        .api_key
        .or_else(|| get_api_key_from_headers(&headers))
        .unwrap_or_default();

    if api_key.is_empty() {
        return axum::response::Response::builder()
            .status(axum::http::StatusCode::UNAUTHORIZED)
            .body(axum::body::Body::from(
                json!({
                    "status": "error",
                    "message": "Missing API key. Provide X-API-Key header or api_key query parameter."
                })
                .to_string(),
            ))
            .unwrap()
            .into_response();
    }

    let settings = state.settings.read();
    let waf_api_key = settings.waf_api_keys.iter().find(|k| k.key == api_key);

    let waf_api_key = match waf_api_key {
        Some(key) => key,
        None => {
            return axum::response::Response::builder()
                .status(axum::http::StatusCode::FORBIDDEN)
                .body(axum::body::Body::from(
                    json!({
                        "status": "error",
                        "message": "Invalid API key."
                    })
                    .to_string(),
                ))
                .unwrap()
                .into_response();
        }
    };

    if !waf_api_key.is_active {
        return axum::response::Response::builder()
            .status(axum::http::StatusCode::FORBIDDEN)
            .body(axum::body::Body::from(
                json!({
                    "status": "error",
                    "message": "API key is inactive."
                })
                .to_string(),
            ))
            .unwrap()
            .into_response();
    }

    let permissions = waf_api_key.permissions.clone();
    let broadcaster = state.event_broadcaster.clone();

    ws.on_upgrade(move |socket| handle_websocket(socket, addr, api_key, permissions, broadcaster))
}

async fn handle_websocket(
    mut socket: WebSocket,
    client_addr: SocketAddr,
    _api_key: String,
    permissions: Vec<String>,
    broadcaster: EventBroadcaster,
) {
    let (client_id, mut event_receiver) = broadcaster.add_client(
        "anonymous".to_string(),
        permissions.clone(),
    );

    let mut ping_interval = interval(Duration::from_secs(30));
    let mut expecting_pong = false;
    let mut pong_timeout: Option<tokio::time::Sleep> = None;

    loop {
        tokio::select! {
            _ = ping_interval.tick() => {
                if expecting_pong {
                    tracing::warn!(
                        "WebSocket client {} (id={}) did not respond to ping, closing connection",
                        client_addr, client_id
                    );
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }

                if let Err(e) = socket.send(Message::Ping(vec![])).await {
                    tracing::error!("Failed to send ping to {}: {}", client_addr, e);
                    break;
                }
                expecting_pong = true;
                pong_timeout = Some(tokio::time::sleep(Duration::from_secs(10)));
            }
            _ = async {
                if let Some(ref mut timeout) = pong_timeout {
                    timeout.await
                } else {
                    std::future::pending().await
                }
            }, if expecting_pong => {
                tracing::warn!(
                    "WebSocket client {} (id={}) pong timeout, closing connection",
                    client_addr, client_id
                );
                break;
            }
            event = event_receiver.recv() => {
                match event {
                    Ok(waf_event) => {
                        if EventBroadcaster::should_receive_event(&permissions, &waf_event) {
                            let message = match serde_json::to_string(&waf_event) {
                                Ok(json_str) => json_str,
                                Err(e) => {
                                    tracing::error!("Failed to serialize event: {}", e);
                                    continue;
                                }
                            };

                            if let Err(e) = socket.send(Message::Text(message.into())).await {
                                tracing::error!(
                                    "Failed to send event to {}: {}",
                                    client_addr,
                                    e
                                );
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(
                            "WebSocket client {} (id={}) lagged behind, dropped {} events",
                            client_addr, client_id, n
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                            if value.get("type").and_then(|v| v.as_str()) == Some("ping") {
                                let pong_msg = json!({
                                    "type": "pong",
                                    "timestamp": Utc::now().to_rfc3339()
                                });

                                if let Err(e) = socket.send(Message::Text(pong_msg.to_string().into())).await {
                                    tracing::error!(
                                        "Failed to send pong to {}: {}",
                                        client_addr,
                                        e
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Ping(_))) => {
                        if let Err(e) = socket.send(Message::Pong(vec![])).await {
                            tracing::error!("Failed to send pong to {}: {}", client_addr, e);
                            break;
                        }
                        expecting_pong = false;
                        pong_timeout = None;
                    }
                    Some(Ok(Message::Close(_))) => {
                        tracing::info!("WebSocket client {} (id={}) closed connection", client_addr, client_id);
                        break;
                    }
                    Some(Err(e)) => {
                        tracing::error!("WebSocket error for {}: {}", client_addr, e);
                        break;
                    }
                    None => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    broadcaster.remove_client(client_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_broadcaster_creation() {
        let broadcaster = EventBroadcaster::new();
        assert_eq!(broadcaster.client_count(), 0);
    }

    #[test]
    fn test_event_broadcaster_add_remove_client() {
        let broadcaster = EventBroadcaster::new();
        let (client_id, _receiver) = broadcaster.add_client(
            "test-key".to_string(),
            vec!["read".to_string()],
        );
        assert_eq!(broadcaster.client_count(), 1);
        broadcaster.remove_client(client_id);
        assert_eq!(broadcaster.client_count(), 0);
    }

    #[test]
    fn test_should_receive_event_read_permission() {
        let permissions = vec!["read".to_string()];
        let event = WafEvent::new_detection(
            "1.2.3.4".to_string(),
            "sql_injection".to_string(),
            "high".to_string(),
            None,
        );
        assert!(EventBroadcaster::should_receive_event(&permissions, &event));

        let cluster_event = WafEvent::new_cluster("node-1".to_string(), "join".to_string());
        assert!(EventBroadcaster::should_receive_event(&permissions, &cluster_event));
    }

    #[test]
    fn test_should_receive_event_stats_permission() {
        let permissions = vec!["stats".to_string()];
        let detection_event = WafEvent::new_detection(
            "1.2.3.4".to_string(),
            "sql_injection".to_string(),
            "high".to_string(),
            None,
        );
        assert!(EventBroadcaster::should_receive_event(&permissions, &detection_event));

        let block_event = WafEvent::new_block("1.2.3.4".to_string(), "manual".to_string());
        assert!(EventBroadcaster::should_receive_event(&permissions, &block_event));

        let cluster_event = WafEvent::new_cluster("node-1".to_string(), "join".to_string());
        assert!(!EventBroadcaster::should_receive_event(&permissions, &cluster_event));

        let config_event = WafEvent::new_config_change("proxy".to_string());
        assert!(!EventBroadcaster::should_receive_event(&permissions, &config_event));
    }

    #[test]
    fn test_should_receive_event_events_permission() {
        let permissions = vec!["events".to_string()];
        let detection_event = WafEvent::new_detection(
            "1.2.3.4".to_string(),
            "sql_injection".to_string(),
            "high".to_string(),
            None,
        );
        assert!(EventBroadcaster::should_receive_event(&permissions, &detection_event));

        let cluster_event = WafEvent::new_cluster("node-1".to_string(), "join".to_string());
        assert!(EventBroadcaster::should_receive_event(&permissions, &cluster_event));

        let config_event = WafEvent::new_config_change("proxy".to_string());
        assert!(!EventBroadcaster::should_receive_event(&permissions, &config_event));
    }

    #[test]
    fn test_should_receive_event_wildcard_permission() {
        let permissions = vec!["*".to_string()];
        let detection_event = WafEvent::new_detection(
            "1.2.3.4".to_string(),
            "sql_injection".to_string(),
            "high".to_string(),
            None,
        );
        assert!(EventBroadcaster::should_receive_event(&permissions, &detection_event));

        let cluster_event = WafEvent::new_cluster("node-1".to_string(), "join".to_string());
        assert!(EventBroadcaster::should_receive_event(&permissions, &cluster_event));

        let config_event = WafEvent::new_config_change("proxy".to_string());
        assert!(EventBroadcaster::should_receive_event(&permissions, &config_event));
    }

    #[test]
    fn test_should_receive_event_no_permission() {
        let permissions: Vec<String> = vec![];
        let event = WafEvent::new_detection(
            "1.2.3.4".to_string(),
            "sql_injection".to_string(),
            "high".to_string(),
            None,
        );
        assert!(!EventBroadcaster::should_receive_event(&permissions, &event));
    }

    #[test]
    fn test_waf_event_serialization() {
        let event = WafEvent::new_detection(
            "192.168.1.1".to_string(),
            "xss".to_string(),
            "medium".to_string(),
            Some("rule-42".to_string()),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"detection\""));
        assert!(json.contains("\"ip\":\"192.168.1.1\""));
        assert!(json.contains("\"attack_type\":\"xss\""));
        assert!(json.contains("\"severity\":\"medium\""));
        assert!(json.contains("\"rule_id\":\"rule-42\""));
        assert!(json.contains("\"timestamp\""));
    }

    #[test]
    fn test_waf_event_deserialization() {
        let json = r#"{"type":"detection","ip":"10.0.0.1","attack_type":"rce","severity":"critical","rule_id":null,"timestamp":"2024-01-01T00:00:00Z"}"#;
        let event: WafEvent = serde_json::from_str(json).unwrap();
        match event {
            WafEvent::Detection {
                ip,
                attack_type,
                severity,
                rule_id,
                timestamp,
            } => {
                assert_eq!(ip, "10.0.0.1");
                assert_eq!(attack_type, "rce");
                assert_eq!(severity, "critical");
                assert_eq!(rule_id, None);
                assert_eq!(timestamp, "2024-01-01T00:00:00Z");
            }
            _ => panic!("Expected Detection event"),
        }
    }

    #[test]
    fn test_waf_event_block_serialization() {
        let event = WafEvent::new_block("10.0.0.1".to_string(), "rate_limit".to_string());
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"block\""));
        assert!(json.contains("\"ip\":\"10.0.0.1\""));
        assert!(json.contains("\"reason\":\"rate_limit\""));
    }

    #[test]
    fn test_waf_event_unblock_serialization() {
        let event = WafEvent::new_unblock("10.0.0.1".to_string());
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"unblock\""));
        assert!(json.contains("\"ip\":\"10.0.0.1\""));
    }

    #[test]
    fn test_waf_event_threat_score_serialization() {
        let event = WafEvent::new_threat_score("10.0.0.1".to_string(), 85.5);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"threat_score_update\""));
        assert!(json.contains("\"score\":85.5"));
    }

    #[test]
    fn test_waf_event_cluster_serialization() {
        let event = WafEvent::new_cluster("node-1".to_string(), "leave".to_string());
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"cluster\""));
        assert!(json.contains("\"node_id\":\"node-1\""));
        assert!(json.contains("\"event_type\":\"leave\""));
    }

    #[test]
    fn test_waf_event_config_change_serialization() {
        let event = WafEvent::new_config_change("ssl".to_string());
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"config_change\""));
        assert!(json.contains("\"config_type\":\"ssl\""));
    }

    #[test]
    fn test_is_stats_related() {
        assert!(WafEvent::new_detection(
            "1.2.3.4".to_string(),
            "sql".to_string(),
            "high".to_string(),
            None
        )
        .is_stats_related());
        assert!(WafEvent::new_block("1.2.3.4".to_string(), "reason".to_string()).is_stats_related());
        assert!(WafEvent::new_unblock("1.2.3.4".to_string()).is_stats_related());
        assert!(
            WafEvent::new_threat_score("1.2.3.4".to_string(), 50.0).is_stats_related()
        );
        assert!(!WafEvent::new_cluster("node-1".to_string(), "join".to_string()).is_stats_related());
        assert!(
            !WafEvent::new_config_change("proxy".to_string()).is_stats_related()
        );
    }

    #[test]
    fn test_is_cluster_related() {
        assert!(WafEvent::new_cluster("node-1".to_string(), "join".to_string()).is_cluster_related());
        assert!(!WafEvent::new_detection(
            "1.2.3.4".to_string(),
            "sql".to_string(),
            "high".to_string(),
            None
        )
        .is_cluster_related());
    }

    #[test]
    fn test_broadcast_event_to_subscriber() {
        let broadcaster = EventBroadcaster::new();
        let mut receiver = broadcaster.sender.subscribe();

        let event = WafEvent::new_detection(
            "1.2.3.4".to_string(),
            "xss".to_string(),
            "medium".to_string(),
            None,
        );

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            broadcaster.broadcast(event.clone()).await;
            let received = receiver.recv().await.unwrap();
            assert!(matches!(received, WafEvent::Detection { .. }));
        });
    }

    #[test]
    fn test_multiple_clients_receive_events() {
        let broadcaster = EventBroadcaster::new();
        let mut receiver1 = broadcaster.sender.subscribe();
        let mut receiver2 = broadcaster.sender.subscribe();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let event = WafEvent::new_block("1.2.3.4".to_string(), "test".to_string());
            broadcaster.broadcast(event).await;

            let r1 = receiver1.recv().await.unwrap();
            let r2 = receiver2.recv().await.unwrap();

            assert!(matches!(r1, WafEvent::Block { .. }));
            assert!(matches!(r2, WafEvent::Block { .. }));
        });
    }

    #[test]
    fn test_client_id_incremental() {
        let broadcaster = EventBroadcaster::new();
        let (id1, _) = broadcaster.add_client("key1".to_string(), vec![]);
        let (id2, _) = broadcaster.add_client("key2".to_string(), vec![]);
        let (id3, _) = broadcaster.add_client("key3".to_string(), vec![]);
        assert!(id1 < id2);
        assert!(id2 < id3);
    }
}
