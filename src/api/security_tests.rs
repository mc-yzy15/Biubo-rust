use super::app::AppState;
use super::middleware::dashboard_auth::dashboard_auth_middleware;
use super::routes;
use crate::config::settings::{Settings, SharedSettings};
use crate::core::models::WafApiKey;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn;
use axum::Router;
use chrono::Utc;
use parking_lot::RwLock;
use tower::ServiceExt;

use std::sync::Arc;

fn create_shared_settings() -> SharedSettings {
    let mut settings = Settings::default();
    settings.dashboard_password = crate::utils::crypto::hash_secret_if_needed("admin-pass")
        .expect("dashboard password should hash");
    settings.challenge_secret = "session-secret".to_string();
    settings.waf_api_keys = vec![WafApiKey {
        id: "waf-read".to_string(),
        key: "waf-read-key".to_string(),
        name: "Read key".to_string(),
        permissions: vec!["read".to_string()],
        rate_limit: 100,
        created_at: Utc::now(),
        last_used_at: None,
        is_active: true,
    }];
    Arc::new(RwLock::new(Arc::new(settings)))
}

fn create_state(settings: SharedSettings) -> Arc<AppState> {
    Arc::new(AppState {
        settings,
        error_pages: std::collections::HashMap::new(),
        async_detection_queue: None,
        event_broadcaster: crate::api::routes::waf_events::EventBroadcaster::new(),
        reputation_aggregator:
            crate::core::reputation::aggregator::ReputationAggregator::with_defaults(),
        reputation_manager: crate::core::reputation::manager::ReputationManager::new(&[]),
    })
}

fn create_dashboard_test_router() -> Router {
    let state = create_state(create_shared_settings());
    let dashboard_auth_state = state.clone();

    Router::new()
        .merge(routes::dashboard::public_router(state.clone()))
        .merge(
            Router::new()
                .merge(routes::dashboard::protected_router(state.clone()))
                .merge(routes::plugins::router(state.clone()))
                .layer(from_fn(
                    move |req: axum::http::Request<Body>, next: axum::middleware::Next| {
                        let state = dashboard_auth_state.clone();
                        async move {
                            dashboard_auth_middleware(
                                axum::extract::State(state),
                                req.headers().clone(),
                                req,
                                next,
                            )
                            .await
                        }
                    },
                )),
        )
        .with_state(state)
}

#[tokio::test]
async fn login_sets_cookie_and_allows_dashboard_access() {
    let app = create_dashboard_test_router();

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/api/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"admin-pass"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(login_response.status(), StatusCode::OK);
    let session_cookie = login_response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .expect("login should issue a session cookie")
        .to_string();
    assert!(session_cookie.contains("HttpOnly"));
    assert!(!session_cookie.contains("admin-pass"));

    let dashboard_response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/biubo/config")
                .header("cookie", session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(dashboard_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn waf_api_key_can_no_longer_access_dashboard() {
    let app = create_dashboard_test_router();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/biubo/config")
                .header("x-api-key", "waf-read-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn concurrent_setup_requests_only_initialize_once() {
    let settings = create_shared_settings();
    {
        let mut guard = settings.write();
        let mut updated = (**guard).clone();
        updated.initialized = false;
        updated.init_token = "one-time-init-token".to_string();
        let temp_dir =
            std::env::temp_dir().join(format!("biubo-init-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        updated.project_root = temp_dir;
        *guard = Arc::new(updated);
    }

    let state = create_state(settings.clone());
    let app = routes::init::router(state.clone()).with_state(state);
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/api/setup")
            .header("content-type", "application/json")
            .header("x-init-token", "one-time-init-token")
            .body(Body::from(
                r#"{"password":"admin-pass","proxy_map":{"example.com":"http://127.0.0.1:8081"}}"#,
            ))
            .unwrap()
    };

    let (first, second) = tokio::join!(app.clone().oneshot(request()), app.oneshot(request()));
    let statuses = [first.unwrap().status(), second.unwrap().status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1,
        "only one request may consume the one-time initialization token"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::BAD_REQUEST)
            .count(),
        1
    );
    assert!(settings.read().is_initialized());
    assert!(settings.read().init_token.is_empty());

    let project_root = settings.read().project_root.clone();
    let _ = std::fs::remove_dir_all(project_root);
}

#[tokio::test]
async fn reverse_proxy_forwards_common_methods_and_rejects_tunnel_methods() {
    let settings = create_shared_settings();
    let host = format!("{}.test", uuid::Uuid::new_v4().simple());
    {
        let mut guard = settings.write();
        let mut updated = (**guard).clone();
        updated.initialized = true;
        updated
            .proxy_map
            .insert(host.clone(), "http://127.0.0.1".to_string());
        *guard = Arc::new(updated);
    }

    crate::data::storage::manager::get_db(&host)
        .ram_set("site", serde_json::json!({"status": "on"}));

    let state = create_state(settings);
    let app = routes::proxy::router(state.clone()).with_state(state);
    for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/resource")
                    .header("host", &host)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // The private upstream is rejected by SSRF validation after dispatch;
        // that distinguishes a forwarded request from a router 404/405.
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{method}");
    }

    for method in ["TRACE", "CONNECT"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/resource")
                    .header("host", &host)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method}"
        );
    }

    let db_path = std::env::current_dir().unwrap().join("data").join(&host);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn plugin_routes_require_dashboard_session() {
    let app = create_dashboard_test_router();

    let unauthenticated = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/biubo/plugins")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/api/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"admin-pass"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let session_cookie = login_response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .expect("login should issue a session cookie")
        .to_string();

    let authenticated = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/biubo/plugins")
                .header("cookie", session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(authenticated.status(), StatusCode::OK);
}
