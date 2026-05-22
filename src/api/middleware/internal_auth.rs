use axum::extract::Request;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use serde_json::json;
use std::sync::Arc;

use crate::api::app::AppState;
use crate::utils::crypto::constant_time_compare;

pub async fn internal_api_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let provided_key = match headers
        .get("X-Internal-API-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(key) => key,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": "error",
                    "message": "Missing X-Internal-API-Key header."
                })),
            )
                .into_response();
        }
    };

    let is_valid = {
        let settings = state.settings.read();
        constant_time_compare(provided_key.as_bytes(), settings.internal_api_key.as_bytes())
    };

    if is_valid {
        next.run(request).await
    } else {
        (
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "message": "Invalid internal API key."
            })),
        )
            .into_response()
    }
}
