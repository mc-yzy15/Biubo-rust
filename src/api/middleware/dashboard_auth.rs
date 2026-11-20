use axum::extract::Request;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde_json::json;
use std::sync::Arc;

use crate::api::app::AppState;
use crate::utils::crypto::constant_time_compare;

type HmacSha256 = Hmac<sha2::Sha256>;

pub async fn dashboard_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    if check_session_cookie(&headers, &state) {
        return next.run(request).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "status": "error",
            "message": "Authentication required. Provide a valid dashboard session cookie."
        })),
    )
        .into_response()
}

fn check_session_cookie(headers: &HeaderMap, state: &Arc<AppState>) -> bool {
    let cookie_header = match headers.get("cookie").and_then(|v| v.to_str().ok()) {
        Some(c) => c,
        None => return false,
    };

    let session_token = cookie_header.split(';').find_map(|cookie| {
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
            verify_dashboard_session_token(
                &token,
                &settings.dashboard_password,
                &settings.challenge_secret,
            )
        }
        _ => false,
    }
}

pub fn create_dashboard_session_token(
    password_hash: &str,
    challenge_secret: &str,
    session_timeout_minutes: i64,
) -> String {
    let expires_at = Utc::now().timestamp() + (session_timeout_minutes.max(1) * 60);
    let signature =
        compute_dashboard_session_signature(password_hash, challenge_secret, expires_at);
    format!("{}.{}", expires_at, signature)
}

fn verify_dashboard_session_token(
    token: &str,
    password_hash: &str,
    challenge_secret: &str,
) -> bool {
    let (expires_at, signature) = match token.split_once('.') {
        Some(parts) => parts,
        None => return false,
    };

    let expires_at = match expires_at.parse::<i64>() {
        Ok(value) => value,
        Err(_) => return false,
    };

    if expires_at < Utc::now().timestamp() {
        return false;
    }

    let expected = compute_dashboard_session_signature(password_hash, challenge_secret, expires_at);
    constant_time_compare(signature.as_bytes(), expected.as_bytes())
}

fn compute_dashboard_session_signature(
    password_hash: &str,
    challenge_secret: &str,
    expires_at: i64,
) -> String {
    let mut mac = HmacSha256::new_from_slice(challenge_secret.as_bytes())
        .expect("HMAC accepts arbitrary-length keys");
    mac.update(b"dashboard-session:");
    mac.update(password_hash.as_bytes());
    mac.update(b":");
    mac.update(expires_at.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_session_token_round_trip() {
        let password_hash = "$2b$12$QdK5iJ2zO2u0f7J2zO2u0eQf8Qj3CZBzV7m8zQJt7b3R2Z8B0m4ba";
        let challenge_secret = "challenge-secret";

        let token = create_dashboard_session_token(password_hash, challenge_secret, 20);
        assert!(verify_dashboard_session_token(
            &token,
            password_hash,
            challenge_secret
        ));
        assert!(!verify_dashboard_session_token(
            &token,
            password_hash,
            "different-secret"
        ));
    }

    #[test]
    fn test_dashboard_session_token_expires() {
        let expires_at = Utc::now().timestamp() - 60;
        let signature = compute_dashboard_session_signature("hash", "secret", expires_at);
        let expired = format!("{}.{}", expires_at, signature);
        assert!(!verify_dashboard_session_token(&expired, "hash", "secret"));
    }
}
