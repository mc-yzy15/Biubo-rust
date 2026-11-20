use crate::api::app::AppState;
use crate::api::response::ApiResponse;
use crate::utils::crypto::{hash_secret_if_needed, verify_secret};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct SetupRequest {
    password: Option<String>,
    proxy_map: Option<std::collections::HashMap<String, String>>,
    waf_port: Option<u16>,
    api_key: Option<String>,
    llm_base_url: Option<String>,
    llm_model: Option<String>,
}

pub fn router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(init_page))
        .route("/api/setup", post(api_setup))
}

async fn init_page(State(state): State<Arc<AppState>>) -> Response {
    if state.settings.read().is_initialized() {
        let redirect_path = format!("{}/dashboard", state.settings.read().dashboard_path);
        return Redirect::temporary(&redirect_path).into_response();
    }

    let path = state.settings.read().page_root.join("init.html");
    match std::fs::read_to_string(&path) {
        Ok(content) => Html(content).into_response(),
        Err(_) => Html("<h1>Initialization page template missing</h1>".to_string()).into_response(),
    }
}

async fn api_setup(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<SetupRequest>,
) -> Response {
    let provided_token = match headers
        .get("X-Init-Token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(token) => token,
        None => {
            return ApiResponse::<()>::error("Missing X-Init-Token header")
                .with_status(StatusCode::UNAUTHORIZED);
        }
    };

    let password = match &payload.password {
        Some(p) if !p.is_empty() => p.clone(),
        _ => {
            return ApiResponse::<()>::error("Password and proxy map are required")
                .with_status(StatusCode::BAD_REQUEST);
        }
    };

    let proxy_map = match &payload.proxy_map {
        Some(m) if !m.is_empty() => m.clone(),
        _ => {
            return ApiResponse::<()>::error("Invalid proxy map format")
                .with_status(StatusCode::BAD_REQUEST);
        }
    };

    let password_hash = match hash_secret_if_needed(&password) {
        Ok(hashed) => hashed,
        Err(e) => {
            tracing::error!("Failed to hash dashboard password during setup: {}", e);
            return ApiResponse::<()>::error("Failed to save dashboard password")
                .with_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Validate and consume the one-time token under the same write lock so
    // concurrent setup requests cannot both initialize the instance.
    let mut guard = state.settings.write();
    if guard.is_initialized() {
        return ApiResponse::<()>::error("System already initialized")
            .with_status(StatusCode::BAD_REQUEST);
    }
    if guard.init_token.is_empty() {
        return ApiResponse::<()>::error("Initialization token has already been used")
            .with_status(StatusCode::FORBIDDEN);
    }
    if !verify_secret(&provided_token, &guard.init_token) {
        return ApiResponse::<()>::error("Invalid initialization token")
            .with_status(StatusCode::FORBIDDEN);
    }

    let mut settings = (**guard).clone();
    settings.dashboard_password = password_hash;
    settings.proxy_map = proxy_map;
    if let Some(v) = payload.waf_port {
        settings.waf_port = v;
    }
    if let Some(v) = payload.api_key {
        settings.api_key = v;
    }
    if let Some(v) = payload.llm_base_url {
        settings.llm_base_url = v;
    }
    if let Some(v) = payload.llm_model {
        settings.llm_model = v;
    }
    settings.initialized = true;
    settings.init_token = String::new();
    let dashboard_path = settings.dashboard_path.clone();
    settings.save_config();
    *guard = Arc::new(settings);

    Json(ApiResponse::success(serde_json::json!({
        "dashboard_path": dashboard_path
    })))
    .into_response()
}
