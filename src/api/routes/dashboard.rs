use crate::api::app::AppState;
use crate::api::middleware::dashboard_auth::{
    create_dashboard_session_token, mask_sensitive_value,
};
use crate::api::response::ApiResponse;
use crate::utils::crypto::{hash_secret_if_needed, verify_password};
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
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
    llm_quick_api_key: Option<String>,
    llm_deep_api_key: Option<String>,
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
        .route("/api/biubo/dashboard/runtime", get(runtime_status))
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
    let (password_hash, challenge_secret, session_timeout_minutes, secure_cookie) = {
        let settings = state.settings.read();
        (
            settings.dashboard_password.clone(),
            settings.challenge_secret.clone(),
            settings.session_timeout,
            settings.ssl_enabled,
        )
    };

    if verify_password(&payload.password, &password_hash) {
        let token = create_dashboard_session_token(
            &password_hash,
            &challenge_secret,
            session_timeout_minutes,
        );
        let secure_attr = if secure_cookie { "; Secure" } else { "" };
        let cookie = format!(
            "biubo_session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
            token,
            session_timeout_minutes.max(1) * 60,
            secure_attr
        );

        let mut response = Json(ApiResponse::<()>::ok()).into_response();
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie).expect("session cookie is valid"),
        );
        response
    } else {
        ApiResponse::<()>::error("Incorrect password").with_status(StatusCode::UNAUTHORIZED)
    }
}

async fn api_logout(State(state): State<Arc<AppState>>) -> Response {
    let secure_attr = if state.settings.read().ssl_enabled {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "biubo_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        secure_attr
    );

    let mut response = Json(ApiResponse::<()>::ok()).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("logout cookie is valid"),
    );
    response
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
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            match hash_secret_if_needed(trimmed) {
                Ok(hashed) => settings.dashboard_password = hashed,
                Err(e) => {
                    tracing::error!("Failed to hash dashboard password before save: {}", e);
                    return ApiResponse::<()>::error("Failed to update dashboard password")
                        .with_status(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }
    }
    if let Some(v) = payload.dashboard_path {
        settings.dashboard_path = v;
    }
    if let Some(v) = payload.proxy_map {
        settings.proxy_map = v;
    }
    if let Some(v) = payload.api_key {
        if !looks_masked_secret(&v) {
            settings.api_key = v;
        }
    }
    if let Some(v) = payload.llm_model {
        settings.llm_model = v;
    }
    if let Some(v) = payload.llm_base_url {
        settings.llm_base_url = v;
    }
    if let Some(v) = payload.llm_quick_api_key {
        if !looks_masked_secret(&v) {
            settings.llm_quick_api_key = v;
        }
    }
    if let Some(v) = payload.llm_deep_api_key {
        if !looks_masked_secret(&v) {
            settings.llm_deep_api_key = v;
        }
    }
    settings.save_config();
    *guard = Arc::new(settings);
    if let Err(e) = crate::core::engine::waf_engine::invalidate_all_rules_cache() {
        tracing::error!(
            "Failed to invalidate WAF rules cache after config update: {}",
            e
        );
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

async fn runtime_status(State(state): State<Arc<AppState>>) -> Response {
    let detection = state
        .async_detection_queue
        .as_ref()
        .map(|queue| queue.snapshot());
    let metrics = crate::core::metrics::METRICS.snapshot();
    Json(ApiResponse::success(serde_json::json!({
        "detection_queue": detection,
        "log_queue": {
            "capacity": metrics.log_queue_capacity,
            "depth": metrics.log_queue_depth,
            "submitted": metrics.log_queue_submitted,
            "written": metrics.log_written,
            "dropped": metrics.log_queue_dropped,
            "security_dropped": metrics.log_queue_security_dropped,
            "write_errors": metrics.log_write_errors,
        }
    })))
    .into_response()
}

async fn cache_stats() -> Response {
    let stats = crate::core::engine::waf_engine::get_cache_stats();
    Json(ApiResponse::success(stats)).into_response()
}

fn looks_masked_secret(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed == "***" || trimmed.ends_with("***")
}
