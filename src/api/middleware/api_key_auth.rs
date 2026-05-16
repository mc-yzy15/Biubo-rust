use axum::extract::Request;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use serde_json::json;
use std::sync::Arc;

use crate::api::app::AppState;
use crate::utils::crypto::constant_time_compare;

pub async fn api_key_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let api_key = match extract_api_key(&headers) {
        Some(key) => key,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": "error",
                    "message": "Missing API key. Provide X-API-Key header."
                })),
            )
                .into_response();
        }
    };

    let (is_active, _permissions) = {
        let settings = state.settings.read();
        let waf_api_key = settings
            .waf_api_keys
            .iter()
            .find(|k| constant_time_compare(k.key.as_bytes(), api_key.as_bytes()));

        match waf_api_key {
            Some(key) => (key.is_active, key.permissions.clone()),
            None => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "status": "error",
                        "message": "Invalid API key."
                    })),
                )
                    .into_response();
            }
        }
    };

    if !is_active {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "message": "API key is inactive."
            })),
        )
            .into_response();
    }

    next.run(request).await
}

fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

pub fn check_permission(api_key: &str, permission: &str, state: &AppState) -> bool {
    let settings = state.settings.read();
    let waf_api_key = settings
        .waf_api_keys
        .iter()
        .find(|k| constant_time_compare(k.key.as_bytes(), api_key.as_bytes()));

    match waf_api_key {
        Some(key) => key.has_permission(permission),
        None => false,
    }
}

pub fn get_api_key_from_headers(headers: &HeaderMap) -> Option<String> {
    extract_api_key(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_api_key_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", "test-key-123".parse().unwrap());

        let result = extract_api_key(&headers);
        assert_eq!(result, Some("test-key-123".to_string()));
    }

    #[test]
    fn test_extract_api_key_missing() {
        let headers = HeaderMap::new();
        let result = extract_api_key(&headers);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_api_key_empty() {
        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", "".parse().unwrap());

        let result = extract_api_key(&headers);
        assert_eq!(result, Some("".to_string()));
    }
}
