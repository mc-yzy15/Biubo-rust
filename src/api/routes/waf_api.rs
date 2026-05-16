use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::api::app::AppState;
use crate::api::middleware::api_key_auth::{check_permission, get_api_key_from_headers};
use crate::data::storage::manager::get_db;

#[derive(Debug, Deserialize)]
struct CheckRequest {
    ip: String,
}

#[derive(Debug, Deserialize)]
struct ReportRequest {
    ip: String,
    event_type: String,
    details: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BlockRequest {
    ip: String,
    reason: Option<String>,
    duration_hours: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct UnblockRequest {
    ip: String,
}

#[derive(Debug, Serialize)]
struct CheckResponse {
    status: String,
    reason: Option<String>,
    score: f64,
}

#[derive(Debug, Serialize)]
struct ReportResponse {
    recommended_action: String,
}

#[derive(Debug, Serialize)]
struct ThreatResponse {
    ip: String,
    reputation_score: f64,
    behavior_score: f64,
    is_blocked: bool,
    block_reason: Option<String>,
    detections: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BlockResponse {
    blocked: bool,
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct UnblockResponse {
    unblocked: bool,
}

#[derive(Debug, Serialize)]
struct StatsResponse {
    total_requests: u64,
    blocked: u64,
    detection_rate: String,
    top_threats: Vec<ThreatEntry>,
}

#[derive(Debug, Serialize, Clone)]
struct ThreatEntry {
    ip: String,
    count: u64,
    threat_type: String,
}

pub fn router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/check", post(handle_check))
        .route("/report", post(handle_report))
        .route("/threat/:ip", get(handle_threat))
        .route("/block", post(handle_block))
        .route("/unblock", post(handle_unblock))
        .route("/stats", get(handle_stats))
        .with_state(state)
}

async fn handle_check(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<CheckRequest>,
) -> Response {
    let api_key = match get_api_key_from_headers(&headers) {
        Some(key) => key,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"status": "error", "message": "Missing API key"})),
            )
                .into_response();
        }
    };

    if !check_permission(&api_key, "read", &state) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "message": "Insufficient permissions"})),
        )
            .into_response();
    }

    if payload.ip.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "IP address is required"})),
        )
            .into_response();
    }

    let host = "default";
    let db = get_db(host);
    let is_blocked = db.is_banned(&payload.ip);
    let is_whitelisted = db.is_whitelisted(&payload.ip);

    if is_whitelisted {
        return Json(CheckResponse {
            status: "clean".to_string(),
            reason: None,
            score: 0.0,
        })
        .into_response();
    }

    let block_reason = if is_blocked {
        let security = db.ram_get("security");
        security
            .as_ref()
            .and_then(|v| v.get("blacklist"))
            .and_then(|bl| bl.get(&payload.ip))
            .and_then(|r| r.get("reason"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    };

    let reputation_score = get_reputation_score(&payload.ip);
    let behavior_score = get_behavior_score(&payload.ip);

    let combined_score = (reputation_score * 0.6 + behavior_score * 0.4).round_to(2);

    let status = if is_blocked {
        "blocked".to_string()
    } else if combined_score > 70.0 {
        "challenge".to_string()
    } else {
        "clean".to_string()
    };

    let reason = block_reason.or_else(|| {
        if combined_score > 70.0 {
            Some(format!("high_threat_score_{}", combined_score))
        } else {
            None
        }
    });

    Json(CheckResponse {
        status,
        reason,
        score: combined_score,
    })
    .into_response()
}

async fn handle_report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<ReportRequest>,
) -> Response {
    let api_key = match get_api_key_from_headers(&headers) {
        Some(key) => key,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"status": "error", "message": "Missing API key"})),
            )
                .into_response();
        }
    };

    if !check_permission(&api_key, "write", &state) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "message": "Insufficient permissions"})),
        )
            .into_response();
    }

    if payload.ip.is_empty() || payload.event_type.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "IP and event_type are required"})),
        )
            .into_response();
    }

    let behavior_score = get_behavior_score(&payload.ip);
    let reputation_score = get_reputation_score(&payload.ip);

    let threat_multiplier = match payload.event_type.as_str() {
        "sql_injection" | "xss" | "rce" => 1.5,
        "brute_force" | "failed_login" => 1.2,
        "scanner" | "bot" => 1.1,
        "ddos" => 1.8,
        _ => 1.0,
    };

    let adjusted_score = (behavior_score * threat_multiplier).min(100.0).round_to(2);

    let recommended_action = if adjusted_score > 80.0 {
        "block"
    } else if adjusted_score > 50.0 {
        "challenge"
    } else {
        "allow"
    };

    let log_entry = json!({
        "request_id": format!("evt_{}", uuid::Uuid::new_v4()),
        "timestamp": Utc::now().to_rfc3339(),
        "ip": payload.ip,
        "event_type": payload.event_type,
        "details": payload.details,
        "behavior_score": adjusted_score,
        "reputation_score": reputation_score,
        "recommended_action": recommended_action,
    });

    let host = "default";
    let db = get_db(host);
    db.write_log(log_entry);

    Json(ReportResponse {
        recommended_action: recommended_action.to_string(),
    })
    .into_response()
}

async fn handle_threat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> Response {
    let api_key = match get_api_key_from_headers(&headers) {
        Some(key) => key,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"status": "error", "message": "Missing API key"})),
            )
                .into_response();
        }
    };

    if !check_permission(&api_key, "read", &state) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "message": "Insufficient permissions"})),
        )
            .into_response();
    }

    if ip.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "IP address is required"})),
        )
            .into_response();
    }

    let host = "default";
    let db = get_db(host);
    let is_blocked = db.is_banned(&ip);

    let block_reason = if is_blocked {
        let security = db.ram_get("security");
        security
            .as_ref()
            .and_then(|v| v.get("blacklist"))
            .and_then(|bl| bl.get(&ip))
            .and_then(|r| r.get("reason"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    };

    let reputation_score = get_reputation_score(&ip);
    let behavior_score = get_behavior_score(&ip);

    let detections = build_detections_list(&ip, reputation_score, behavior_score, is_blocked);

    Json(ThreatResponse {
        ip,
        reputation_score,
        behavior_score,
        is_blocked,
        block_reason,
        detections,
    })
    .into_response()
}

async fn handle_block(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<BlockRequest>,
) -> Response {
    let api_key = match get_api_key_from_headers(&headers) {
        Some(key) => key,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"status": "error", "message": "Missing API key"})),
            )
                .into_response();
        }
    };

    if !check_permission(&api_key, "block", &state) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "message": "Insufficient permissions"})),
        )
            .into_response();
    }

    if payload.ip.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "IP address is required"})),
        )
            .into_response();
    }

    let reason = payload.reason.unwrap_or_else(|| "manual_block".to_string());
    let duration_minutes = payload.duration_hours.map(|h| (h * 60) as u32);

    let host = "default";
    let db = get_db(host);

    let expires_at = if let Some(minutes) = duration_minutes {
        let now = Utc::now();
        let expires = now + chrono::Duration::minutes(minutes as i64);
        Some(expires.to_rfc3339())
    } else {
        None
    };

    db.ban_ip(&payload.ip, &reason, duration_minutes).await;

    Json(BlockResponse {
        blocked: true,
        expires_at,
    })
    .into_response()
}

async fn handle_unblock(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<UnblockRequest>,
) -> Response {
    let api_key = match get_api_key_from_headers(&headers) {
        Some(key) => key,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"status": "error", "message": "Missing API key"})),
            )
                .into_response();
        }
    };

    if !check_permission(&api_key, "block", &state) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "message": "Insufficient permissions"})),
        )
            .into_response();
    }

    if payload.ip.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "IP address is required"})),
        )
            .into_response();
    }

    let host = "default";
    let db = get_db(host);
    let unblocked = db.unban_ip(&payload.ip);

    Json(UnblockResponse { unblocked })
    .into_response()
}

async fn handle_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let api_key = match get_api_key_from_headers(&headers) {
        Some(key) => key,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"status": "error", "message": "Missing API key"})),
            )
                .into_response();
        }
    };

    if !check_permission(&api_key, "stats", &state) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "message": "Insufficient permissions"})),
        )
            .into_response();
    }

    let total_requests = get_total_requests();
    let blocked_requests = get_blocked_requests();

    let detection_rate = if total_requests > 0 {
        format!("{:.1}%", (blocked_requests as f64 / total_requests as f64) * 100.0)
    } else {
        "0.0%".to_string()
    };

    let top_threats = get_top_threats();

    Json(StatsResponse {
        total_requests,
        blocked: blocked_requests,
        detection_rate,
        top_threats,
    })
    .into_response()
}

fn get_reputation_score(ip: &str) -> f64 {
    let host = "default";
    let db = get_db(host);
    
    let security = db.ram_get("security");
    if let Some(sec) = security {
        if let Some(bl) = sec.get("blacklist") {
            if let Some(record) = bl.get(ip) {
                if let Some(reputation) = record.get("reputation_score") {
                    if let Some(score) = reputation.as_f64() {
                        return score.round_to(2);
                    }
                }
            }
        }
    }
    
    50.0
}

fn get_behavior_score(ip: &str) -> f64 {
    let host = "default";
    let db = get_db(host);
    
    let analytics = db.ram_get("analytics");
    if let Some(an) = analytics {
        if let Some(security) = an.get("security") {
            if let Some(top_ips) = security.get("top_attack_ips") {
                if let Some(count) = top_ips.get(ip) {
                    if let Some(c) = count.as_u64() {
                        return (c as f64 * 10.0).min(100.0).round_to(2);
                    }
                }
            }
        }
    }
    
    30.0
}

fn build_detections_list(_ip: &str, reputation_score: f64, behavior_score: f64, is_blocked: bool) -> Vec<String> {
    let mut detections = Vec::new();

    if is_blocked {
        detections.push("blacklisted".to_string());
    }

    if reputation_score > 70.0 {
        detections.push("high_reputation_risk".to_string());
    }

    if behavior_score > 70.0 {
        detections.push("suspicious_behavior".to_string());
    }

    if reputation_score > 50.0 && behavior_score > 50.0 {
        detections.push("combined_threat_indicator".to_string());
    }

    detections
}

fn get_total_requests() -> u64 {
    let host = "default";
    let db = get_db(host);
    
    let analytics = db.ram_get("analytics");
    if let Some(an) = analytics {
        if let Some(traffic) = an.get("traffic") {
            if let Some(visitors) = traffic.get("visitors") {
                if let Some(total) = visitors.get("total") {
                    if let Some(t) = total.as_u64() {
                        return t;
                    }
                }
            }
        }
    }
    
    0
}

fn get_blocked_requests() -> u64 {
    let host = "default";
    let db = get_db(host);
    
    let analytics = db.ram_get("analytics");
    if let Some(an) = analytics {
        if let Some(security) = an.get("security") {
            if let Some(blocked) = security.get("blocked_requests") {
                if let Some(b) = blocked.as_u64() {
                    return b;
                }
            }
        }
    }
    
    0
}

fn get_top_threats() -> Vec<ThreatEntry> {
    let host = "default";
    let db = get_db(host);
    
    let analytics = db.ram_get("analytics");
    let mut threats = Vec::new();

    if let Some(an) = analytics {
        if let Some(security) = an.get("security") {
            if let Some(top_ips) = security.get("top_attack_ips") {
                if let Some(obj) = top_ips.as_object() {
                    for (ip, count) in obj {
                        if let Some(c) = count.as_u64() {
                            threats.push(ThreatEntry {
                                ip: ip.clone(),
                                count: c,
                                threat_type: "multiple".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    threats.sort_by(|a, b| b.count.cmp(&a.count));
    threats.truncate(10);
    
    threats
}

trait RoundTo {
    fn round_to(self, decimals: u32) -> f64;
}

impl RoundTo for f64 {
    fn round_to(self, decimals: u32) -> f64 {
        let factor = 10f64.powi(decimals as i32);
        (self * factor).round() / factor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::Settings;
    use crate::core::models::WafApiKey;
    use parking_lot::RwLock;
    use std::sync::Arc;

    fn create_test_state() -> AppState {
        let mut settings = Settings::default();
        settings.waf_api_keys = vec![
            WafApiKey {
                id: "test-1".to_string(),
                key: "test-api-key-read".to_string(),
                name: "Test Read Key".to_string(),
                permissions: vec!["read".to_string()],
                rate_limit: 1000,
                created_at: Utc::now(),
                last_used_at: None,
                is_active: true,
            },
            WafApiKey {
                id: "test-2".to_string(),
                key: "test-api-key-write".to_string(),
                name: "Test Write Key".to_string(),
                permissions: vec!["read".to_string(), "write".to_string()],
                rate_limit: 1000,
                created_at: Utc::now(),
                last_used_at: None,
                is_active: true,
            },
            WafApiKey {
                id: "test-3".to_string(),
                key: "test-api-key-block".to_string(),
                name: "Test Block Key".to_string(),
                permissions: vec!["read".to_string(), "write".to_string(), "block".to_string()],
                rate_limit: 1000,
                created_at: Utc::now(),
                last_used_at: None,
                is_active: true,
            },
            WafApiKey {
                id: "test-4".to_string(),
                key: "test-api-key-stats".to_string(),
                name: "Test Stats Key".to_string(),
                permissions: vec!["read".to_string(), "stats".to_string()],
                rate_limit: 1000,
                created_at: Utc::now(),
                last_used_at: None,
                is_active: true,
            },
            WafApiKey {
                id: "test-5".to_string(),
                key: "test-api-key-inactive".to_string(),
                name: "Test Inactive Key".to_string(),
                permissions: vec!["read".to_string()],
                rate_limit: 1000,
                created_at: Utc::now(),
                last_used_at: None,
                is_active: false,
            },
            WafApiKey {
                id: "test-6".to_string(),
                key: "test-api-key-wildcard".to_string(),
                name: "Test Wildcard Key".to_string(),
                permissions: vec!["*".to_string()],
                rate_limit: 1000,
                created_at: Utc::now(),
                last_used_at: None,
                is_active: true,
            },
        ];
        AppState {
            settings: Arc::new(RwLock::new(settings)),
            error_pages: std::collections::HashMap::new(),
            async_detection_queue: None,
            event_broadcaster: crate::api::routes::waf_events::EventBroadcaster::new(),
        }
    }

    #[test]
    fn test_check_permission_with_valid_read_key() {
        let state = create_test_state();
        assert!(check_permission("test-api-key-read", "read", &state));
        assert!(!check_permission("test-api-key-read", "write", &state));
        assert!(!check_permission("test-api-key-read", "block", &state));
    }

    #[test]
    fn test_check_permission_with_write_key() {
        let state = create_test_state();
        assert!(check_permission("test-api-key-write", "read", &state));
        assert!(check_permission("test-api-key-write", "write", &state));
        assert!(!check_permission("test-api-key-write", "block", &state));
    }

    #[test]
    fn test_check_permission_with_block_key() {
        let state = create_test_state();
        assert!(check_permission("test-api-key-block", "read", &state));
        assert!(check_permission("test-api-key-block", "write", &state));
        assert!(check_permission("test-api-key-block", "block", &state));
    }

    #[test]
    fn test_check_permission_with_stats_key() {
        let state = create_test_state();
        assert!(check_permission("test-api-key-stats", "read", &state));
        assert!(check_permission("test-api-key-stats", "stats", &state));
        assert!(!check_permission("test-api-key-stats", "block", &state));
    }

    #[test]
    fn test_check_permission_with_wildcard() {
        let state = create_test_state();
        assert!(check_permission("test-api-key-wildcard", "read", &state));
        assert!(check_permission("test-api-key-wildcard", "write", &state));
        assert!(check_permission("test-api-key-wildcard", "block", &state));
        assert!(check_permission("test-api-key-wildcard", "stats", &state));
    }

    #[test]
    fn test_check_permission_invalid_key() {
        let state = create_test_state();
        assert!(!check_permission("invalid-key", "read", &state));
        assert!(!check_permission("", "read", &state));
    }

    #[test]
    fn test_round_to() {
        assert_eq!(1.2345_f64.round_to(2), 1.23);
        assert_eq!(1.236_f64.round_to(2), 1.24);
        assert_eq!(100.0_f64.round_to(2), 100.0);
        assert_eq!(0.123456_f64.round_to(3), 0.123);
    }

    #[test]
    fn test_build_detections_empty() {
        let detections = build_detections_list("1.2.3.4", 30.0, 20.0, false);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_build_detections_blocked() {
        let detections = build_detections_list("1.2.3.4", 30.0, 20.0, true);
        assert_eq!(detections, vec!["blacklisted"]);
    }

    #[test]
    fn test_build_detections_high_reputation() {
        let detections = build_detections_list("1.2.3.4", 80.0, 20.0, false);
        assert_eq!(detections, vec!["high_reputation_risk"]);
    }

    #[test]
    fn test_build_detections_suspicious_behavior() {
        let detections = build_detections_list("1.2.3.4", 30.0, 80.0, false);
        assert_eq!(detections, vec!["suspicious_behavior"]);
    }

    #[test]
    fn test_build_detections_combined() {
        let detections = build_detections_list("1.2.3.4", 80.0, 80.0, false);
        assert_eq!(detections, vec![
            "high_reputation_risk",
            "suspicious_behavior",
            "combined_threat_indicator"
        ]);
    }

    #[test]
    fn test_build_detections_all_flags() {
        let detections = build_detections_list("1.2.3.4", 80.0, 80.0, true);
        assert_eq!(detections, vec![
            "blacklisted",
            "high_reputation_risk",
            "suspicious_behavior",
            "combined_threat_indicator"
        ]);
    }

    #[test]
    fn test_combined_score_calculation() {
        let rep = 80.0;
        let behavior = 60.0;
        let combined = (rep * 0.6 + behavior * 0.4).round_to(2);
        assert_eq!(combined, 72.0);
    }

    #[test]
    fn test_threat_multiplier_sql_injection() {
        let behavior: f64 = 50.0;
        let adjusted: f64 = (behavior * 1.5).min(100.0);
        assert_eq!(adjusted, 75.0);
    }

    #[test]
    fn test_threat_multiplier_ddos() {
        let behavior: f64 = 50.0;
        let adjusted: f64 = (behavior * 1.8).min(100.0);
        assert_eq!(adjusted, 90.0);
    }

    #[test]
    fn test_threat_multiplier_capped_at_100() {
        let behavior: f64 = 80.0;
        let adjusted = (behavior * 1.8).min(100.0);
        assert_eq!(adjusted, 100.0);
    }

    #[test]
    fn test_recommendation_action_thresholds() {
        let score_low = 40.0;
        let score_medium = 60.0;
        let score_high = 85.0;

        let action_low = if score_low > 80.0 {
            "block"
        } else if score_low > 50.0 {
            "challenge"
        } else {
            "allow"
        };
        assert_eq!(action_low, "allow");

        let action_medium = if score_medium > 80.0 {
            "block"
        } else if score_medium > 50.0 {
            "challenge"
        } else {
            "allow"
        };
        assert_eq!(action_medium, "challenge");

        let action_high = if score_high > 80.0 {
            "block"
        } else if score_high > 50.0 {
            "challenge"
        } else {
            "allow"
        };
        assert_eq!(action_high, "block");
    }
}

