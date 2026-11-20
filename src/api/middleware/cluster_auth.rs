use axum::extract::Request;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use serde_json::json;
use std::sync::Arc;

use crate::api::app::AppState;
use crate::utils::crypto::verify_secret;

pub async fn cluster_api_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let provided_secret = match headers
        .get("X-Cluster-Secret")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(secret) => secret,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": "error",
                    "message": "Missing X-Cluster-Secret header."
                })),
            )
                .into_response();
        }
    };

    let is_valid = {
        let settings = state.settings.read();
        verify_secret(&provided_secret, &settings.cluster_shared_secret)
    };

    if is_valid {
        next.run(request).await
    } else {
        (
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "message": "Invalid cluster shared secret."
            })),
        )
            .into_response()
    }
}
