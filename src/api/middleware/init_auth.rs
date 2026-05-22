use axum::extract::Request;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use serde_json::json;
use std::sync::Arc;

use crate::api::app::AppState;
use crate::utils::crypto::constant_time_compare;

#[allow(dead_code)]
pub async fn init_token_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let provided_token = match headers
        .get("X-Init-Token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": "error",
                    "message": "Missing X-Init-Token header."
                })),
            )
                .into_response();
        }
    };

    let (is_empty, is_valid) = {
        let settings = state.settings.read();
        (
            settings.init_token.is_empty(),
            constant_time_compare(provided_token.as_bytes(), settings.init_token.as_bytes()),
        )
    };

    if is_empty {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "message": "Initialization token has already been used or is invalid."
            })),
        )
            .into_response();
    }

    if is_valid {
        next.run(request).await
    } else {
        (
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "message": "Invalid initialization token."
            })),
        )
            .into_response()
    }
}
