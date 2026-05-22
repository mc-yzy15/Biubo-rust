use crate::api::app::AppState;
use crate::api::middleware::dashboard_auth::mask_sensitive_value;
use crate::api::response::ApiResponse;
use crate::utils::crypto::verify_password;
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

pub fn public_router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/dashboard/login", get(login_page))
        .route("/dashboard", get(dashboard_page))
        .route("/dashboard/api/login", post(api_login))
        .route("/dashboard/api/logout", post(api_logout))
}

pub fn protected_router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
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
    if verify_password(&payload.password, &password) {
        Json(ApiResponse::<()>::ok()).into_response()
    } else {
        ApiResponse::<()>::error("Incorrect password").with_status(StatusCode::UNAUTHORIZED)
    }
}

async fn api_logout() -> Response {
    Json(ApiResponse::<()>::ok()).into_response()
}

async fn get_config(State(state): State<Arc<AppState>>) -> Response {
    let s = state.settings.read();
    let masked_api_key = mask_sensitive_value(&s.api_key, 4);
    let masked_dashboard_password = if s.dashboard_password.is_empty() {
        String::new()
    } else {
        "***".to_string()
    };
    let masked_llm_quick_api_key = mask_sensitive_value(&s.llm_quick_api_key, 4);
    let masked_llm_deep_api_key = mask_sensitive_value(&s.llm_deep_api_key, 4);

    Json(ApiResponse::success(serde_json::json!({
        "WAF_PORT": s.waf_port,
        "DASHBOARD_PATH": s.dashboard_path,
        "PROXY_MAP": s.proxy_map,
        "API_KEY": masked_api_key,
        "DASHBOARD_PASSWORD": masked_dashboard_password,
        "LLM_MODEL": s.llm_model,
        "LLM_BASE_URL": s.llm_base_url,
        "LLM_QUICK_API_KEY": masked_llm_quick_api_key,
        "LLM_DEEP_API_KEY": masked_llm_deep_api_key
    })))
    .into_response()
}

async fn update_config(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<ConfigUpdateRequest>,
) -> Response {
    let mut guard = state.settings.write();
    let mut settings = (**guard).clone();
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
    *guard = Arc::new(settings);
    if let Err(e) = crate::core::engine::waf_engine::invalidate_all_rules_cache() {
        tracing::error!("Failed to invalidate WAF rules cache after config update: {}", e);
    }
    Json(ApiResponse::<()>::ok()).into_response()
}

async fn proxy_map(State(state): State<Arc<AppState>>) -> Response {
    let s = state.settings.read();
    Json(ApiResponse::success(serde_json::json!({
        "proxy_map": s.proxy_map
    })))
    .into_response()
}

async fn cache_stats() -> Response {
    let stats = crate::core::engine::waf_engine::get_cache_stats();
    Json(ApiResponse::success(stats)).into_response()
}
