use crate::api::app::AppState;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::json;
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
    axum::Json(payload): axum::Json<SetupRequest>,
) -> Response {
    if state.settings.read().is_initialized() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "msg": "System already initialized"})),
        )
            .into_response();
    }

    let password = match &payload.password {
        Some(p) if !p.is_empty() => p.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "msg": "Password and proxy map are required"})),
            )
                .into_response();
        }
    };

    let proxy_map = match &payload.proxy_map {
        Some(m) if !m.is_empty() => m.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "msg": "Invalid proxy map format"})),
            )
                .into_response();
        }
    };

    {
        let mut settings = state.settings.write();
        settings.dashboard_password = password;
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
        settings.save_config();
    }

    Json(json!({"status": "success"})).into_response()
}
