use crate::api::app::AppState;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct LoginRequest {
    password: String,
}

#[derive(Debug, Deserialize)]
struct ConfigUpdateRequest {
    waf_port: Option<u16>,
    dashboard_password: Option<String>,
    dashboard_path: Option<String>,
    proxy_map: Option<std::collections::HashMap<String, String>>,
    api_key: Option<String>,
    llm_model: Option<String>,
    llm_base_url: Option<String>,
}

pub fn router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/dashboard/login", get(login_page))
        .route("/dashboard", get(dashboard_page))
        .route("/dashboard/api/login", post(api_login))
        .route("/dashboard/api/logout", post(api_logout))
        .route("/api/biubo/config", get(get_config).post(update_config))
        .route("/api/biubo/dashboard/cache-stats", get(cache_stats))
        .route("/api/biubo/dashboard/proxy-map", get(proxy_map))
}

async fn login_page(State(state): State<Arc<AppState>>) -> Response {
    let path = state.settings.read().page_root.join("dashboard_login.html");
    match std::fs::read_to_string(&path) {
        Ok(content) => Html(content).into_response(),
        Err(_) => Html("<h1>Login page missing</h1>".to_string()).into_response(),
    }
}

async fn dashboard_page(State(state): State<Arc<AppState>>) -> Response {
    let path = state.settings.read().page_root.join("dashboard.html");
    match std::fs::read_to_string(&path) {
        Ok(content) => Html(content).into_response(),
        Err(_) => Html("<h1>Dashboard page missing</h1>".to_string()).into_response(),
    }
}

async fn api_login(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<LoginRequest>,
) -> Response {
    let password = state.settings.read().dashboard_password.clone();
    if payload.password == password {
        Json(json!({"status": "success"})).into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "msg": "Incorrect password"})),
        )
            .into_response()
    }
}

async fn api_logout() -> Response {
    Json(json!({"status": "success"})).into_response()
}

async fn get_config(State(state): State<Arc<AppState>>) -> Response {
    let s = state.settings.read();
    Json(json!({
        "status": "success",
        "data": {
            "WAF_PORT": s.waf_port,
            "DASHBOARD_PATH": s.dashboard_path,
            "PROXY_MAP": s.proxy_map,
            "API_KEY": s.api_key,
            "LLM_MODEL": s.llm_model,
            "LLM_BASE_URL": s.llm_base_url
        }
    }))
    .into_response()
}

async fn update_config(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<ConfigUpdateRequest>,
) -> Response {
    let mut settings = state.settings.write();
    if let Some(v) = payload.waf_port {
        settings.waf_port = v;
    }
    if let Some(v) = payload.dashboard_password {
        settings.dashboard_password = v;
    }
    if let Some(v) = payload.dashboard_path {
        settings.dashboard_path = v;
    }
    if let Some(v) = payload.proxy_map {
        settings.proxy_map = v;
    }
    if let Some(v) = payload.api_key {
        settings.api_key = v;
    }
    if let Some(v) = payload.llm_model {
        settings.llm_model = v;
    }
    if let Some(v) = payload.llm_base_url {
        settings.llm_base_url = v;
    }
    settings.save_config();
    if let Err(e) = crate::core::engine::waf_engine::invalidate_all_rules_cache() {
        tracing::error!("Failed to invalidate WAF rules cache after config update: {}", e);
    }
    Json(json!({"status": "success"})).into_response()
}

async fn proxy_map(State(state): State<Arc<AppState>>) -> Response {
    let s = state.settings.read();
    Json(json!({
        "status": "success",
        "data": s.proxy_map
    }))
    .into_response()
}

async fn cache_stats() -> Response {
    let stats = crate::core::engine::waf_engine::get_cache_stats();
    Json(json!({
        "status": "success",
        "data": stats
    }))
    .into_response()
}
