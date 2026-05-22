use axum::extract::Request;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use serde_json::json;
use std::sync::Arc;

use crate::api::app::AppState;
use crate::utils::crypto::constant_time_compare;

pub async fn dashboard_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    if check_session_cookie(&headers, &state) {
        return next.run(request).await;
    }

    if check_api_key_header(&headers, &state) {
        return next.run(request).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "status": "error",
            "message": "Authentication required. Provide a valid session cookie or X-API-Key header."
        })),
    )
        .into_response()
}

fn check_session_cookie(headers: &HeaderMap, state: &Arc<AppState>) -> bool {
    let cookie_header = match headers.get("cookie").and_then(|v| v.to_str().ok()) {
        Some(c) => c,
        None => return false,
    };

    let session_token = cookie_header
        .split(';')
        .find_map(|cookie| {
            let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
            if parts.len() == 2 && parts[0].trim() == "biubo_session" {
                Some(parts[1].trim().to_string())
            } else {
                None
            }
        });

    match session_token {
        Some(token) if !token.is_empty() => {
            let settings = state.settings.read();
            constant_time_compare(token.as_bytes(), settings.dashboard_password.as_bytes())
        }
        _ => false,
    }
}

fn check_api_key_header(headers: &HeaderMap, state: &Arc<AppState>) -> bool {
    let api_key = match headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(key) => key,
        None => return false,
    };

    let settings = state.settings.read();
    if !settings.api_key.is_empty()
        && constant_time_compare(api_key.as_bytes(), settings.api_key.as_bytes())
    {
        return true;
    }

    settings
        .waf_api_keys
        .iter()
        .any(|k| k.is_active && constant_time_compare(k.key.as_bytes(), api_key.as_bytes()))
}

pub fn mask_sensitive_value(value: &str, visible_prefix: usize) -> String {
    if value.is_empty() {
        return String::new();
    }
    if value.len() <= visible_prefix {
        return "***".to_string();
    }
    format!("{}***", &value[..visible_prefix])
}
