use crate::cluster::sync::{ConfigSync, ConfigUpdate};
use crate::cluster::threat_share::ThreatIntelligenceShare;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Extension;
use serde_json::json;
use std::sync::Arc;

use crate::api::app::AppState;

pub fn router(
    _state: Arc<AppState>,
    config_sync: Arc<ConfigSync>,
    threat_share: Arc<ThreatIntelligenceShare>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/cluster/sync", post(receive_config_sync))
        .route("/api/cluster/threat-event", post(receive_threat_event))
        .route("/api/cluster/health", get(cluster_health))
        .route("/api/cluster/nodes", get(cluster_nodes))
        .route("/api/cluster/sync-status", get(cluster_sync_status))
        .layer(Extension(config_sync))
        .layer(Extension(threat_share))
}

async fn receive_config_sync(
    State(_app_state): State<Arc<AppState>>,
    Extension(config_sync): Extension<Arc<ConfigSync>>,
    body: axum::body::Bytes,
) -> Response {

    let update: ConfigUpdate = match serde_json::from_slice(&body) {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "message": format!("Invalid config update payload: {}", e),
                    "update_id": ""
                })),
            )
                .into_response();
        }
    };

    tracing::info!(
        "[ClusterAPI] Received config sync request: id={}, type={}",
        update.id,
        update.update_type
    );

    match config_sync.receive_config_update(update).await {
        Ok(response) => (
            StatusCode::OK,
            Json(json!({
                "status": response.status,
                "message": response.message,
                "update_id": response.update_id
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": e,
                "update_id": ""
            })),
        )
            .into_response(),
    }
}

async fn receive_threat_event(
    State(_app_state): State<Arc<AppState>>,
    Extension(threat_share): Extension<Arc<ThreatIntelligenceShare>>,
    body: axum::body::Bytes,
) -> Response {
    let event: crate::cluster::threat_share::ThreatEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "message": format!("Invalid threat event payload: {}", e),
                })),
            )
                .into_response();
        }
    };

    tracing::info!(
        "[ClusterAPI] Received threat event: ip={}, attack_type={}, correlation_id={}",
        event.ip,
        event.attack_type,
        event.correlation_id
    );

    threat_share.receive_threat_event(&event);

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "message": "Threat event processed",
            "event_id": event.id,
        })),
    )
        .into_response()
}

async fn cluster_health(
    State(_app_state): State<Arc<AppState>>,
    Extension(config_sync): Extension<Arc<ConfigSync>>,
    Extension(threat_share): Extension<Arc<ThreatIntelligenceShare>>,
) -> Response {
    let node_id = config_sync.manager.node_id.clone();
    let role = config_sync.manager.get_role();
    let node_count = config_sync.manager.get_node_count();
    let pending_acks = config_sync.get_pending_ack_count();
    let acknowledged = config_sync.get_acknowledged_count();
    let cluster_status = config_sync.manager.get_status();
    let uptime = config_sync.manager.get_uptime_seconds();

    let active_nodes = config_sync.manager.get_active_nodes();
    let dead_nodes: Vec<_> = config_sync.manager.detect_dead_nodes();

    let blocked_ip_count = threat_share.get_blocked_ip_count();
    let event_count = threat_share.get_event_count();
    let recent_events = threat_share.get_recent_events(5);

    let health_status = if dead_nodes.is_empty() {
        "healthy"
    } else if active_nodes.len() > dead_nodes.len() {
        "degraded"
    } else {
        "critical"
    };

    (
        StatusCode::OK,
        Json(json!({
            "status": health_status,
            "cluster_status": cluster_status.to_string(),
            "node_id": node_id,
            "role": role.to_string(),
            "node_count": node_count,
            "active_nodes": active_nodes.len(),
            "dead_nodes": dead_nodes.len(),
            "pending_acks": pending_acks,
            "acknowledged": acknowledged,
            "uptime_seconds": uptime,
            "threat_intelligence": {
                "blocked_ips": blocked_ip_count,
                "total_events": event_count,
                "recent_events": recent_events.iter().map(|e| json!({
                    "id": e.id,
                    "ip": e.ip,
                    "attack_type": e.attack_type,
                    "severity": e.severity,
                    "source_node_id": e.source_node_id,
                    "correlation_id": e.correlation_id,
                    "timestamp": e.timestamp,
                })).collect::<Vec<_>>(),
            }
        })),
    )
        .into_response()
}

async fn cluster_nodes(
    State(_app_state): State<Arc<AppState>>,
    Extension(config_sync): Extension<Arc<ConfigSync>>,
) -> Response {
    let active_nodes = config_sync.manager.get_active_nodes();
    let dead_nodes = config_sync.manager.detect_dead_nodes();
    let primary_node = config_sync.manager.get_primary_node();

    let all_nodes: Vec<_> = config_sync.manager.nodes
        .iter()
        .map(|entry| {
            let node = &entry.value().node;
            let is_dead = dead_nodes.contains(&node.id);
            let is_primary = primary_node.as_ref() == Some(&node.id);

            json!({
                "id": node.id,
                "role": node.role.to_string(),
                "ip": node.ip,
                "status": if is_dead { "dead" } else { &node.status },
                "is_primary": is_primary,
                "last_heartbeat": node.last_heartbeat,
                "uptime_seconds": node.uptime_seconds,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "total_nodes": all_nodes.len(),
            "active_nodes": active_nodes.len(),
            "dead_nodes": dead_nodes.len(),
            "primary_node": primary_node,
            "nodes": all_nodes,
        })),
    )
        .into_response()
}

async fn cluster_sync_status(
    State(_app_state): State<Arc<AppState>>,
    Extension(config_sync): Extension<Arc<ConfigSync>>,
    Extension(threat_share): Extension<Arc<ThreatIntelligenceShare>>,
) -> Response {
    let node_id = config_sync.manager.node_id.clone();
    let pending_acks = config_sync.get_pending_ack_count();
    let acknowledged = config_sync.get_acknowledged_count();

    let node_sync_status: Vec<_> = config_sync.manager.get_active_nodes()
        .iter()
        .filter(|node| node.id != node_id)
        .map(|node| {
            json!({
                "node_id": node.id,
                "role": node.role.to_string(),
                "ip": node.ip,
                "status": "online",
                "last_sync": node.last_heartbeat,
            })
        })
        .collect();

    let blocked_ips = threat_share.get_blocked_ips();
    let recent_events = threat_share.get_recent_events(100);

    let event_log: Vec<_> = recent_events
        .iter()
        .map(|e| json!({
            "id": e.id,
            "ip": e.ip,
            "attack_type": e.attack_type,
            "severity": e.severity,
            "timestamp": e.timestamp,
            "source_node_id": e.source_node_id,
            "correlation_id": e.correlation_id,
        }))
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "node_id": node_id,
            "sync_status": {
                "pending_acks": pending_acks,
                "acknowledged": acknowledged,
                "node_sync": node_sync_status,
            },
            "threat_sharing": {
                "blocked_ips": blocked_ips,
                "blocked_ip_count": blocked_ips.len(),
                "event_count": recent_events.len(),
                "event_log": event_log,
            }
        })),
    )
        .into_response()
}