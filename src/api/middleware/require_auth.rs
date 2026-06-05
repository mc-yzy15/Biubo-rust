use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::Response;
use std::sync::Arc;

use crate::api::app::AppState;
use crate::api::response::ApiResponse;
use crate::api::middleware::api_key_auth::get_api_key_from_headers;
use crate::utils::crypto::constant_time_compare;

pub struct RequireAuth {
    pub api_key: String,
}

impl RequireAuth {
    pub fn require_permission(&self, permission: &str, state: &AppState) -> Result<(), Response> {
        let settings = state.settings.read();
        let waf_api_key = settings
            .waf_api_keys
            .iter()
            .find(|k| constant_time_compare(k.key.as_bytes(), self.api_key.as_bytes()));

        match waf_api_key {
            Some(key) if key.has_permission(permission) => Ok(()),
            Some(_) => Err(ApiResponse::<()>::error("Insufficient permissions").with_status(StatusCode::FORBIDDEN)),
            None => Err(ApiResponse::<()>::error("Invalid API key").with_status(StatusCode::FORBIDDEN)),
        }
    }
}

impl FromRequestParts<Arc<AppState>> for RequireAuth {
    type Rejection = Response;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<AppState>,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let result = match get_api_key_from_headers(&parts.headers) {
            Some(key) => {
                let settings = _state.settings.read();
                let waf_api_key = settings
                    .waf_api_keys
                    .iter()
                    .find(|k| constant_time_compare(k.key.as_bytes(), key.as_bytes()));

                match waf_api_key {
                    Some(k) if k.is_active => Ok(RequireAuth { api_key: key }),
                    Some(_) => Err(ApiResponse::<()>::error("API key is inactive").with_status(StatusCode::FORBIDDEN)),
                    None => Err(ApiResponse::<()>::error("Invalid API key").with_status(StatusCode::FORBIDDEN)),
                }
            }
            None => Err(ApiResponse::<()>::error("Missing API key").with_status(StatusCode::UNAUTHORIZED)),
        };

        std::future::ready(result)
    }
}
