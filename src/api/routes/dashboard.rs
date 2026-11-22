use crate::api::app::AppState;
use crate::api::middleware::dashboard_auth::{
    create_dashboard_session_token, mask_sensitive_value,
};
use crate::api::response::ApiResponse;
use crate::utils::crypto::{hash_secret_if_needed, verify_password};
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

#[derive(Debug, Deserialize)]
struct LoginRequest {
    password: String,
}

#[derive(Debug, Deserialize)]
struct ConfigUpdateRequest {
    #[serde(alias = "WAF_PORT")]
    waf_port: Option<u16>,
    #[serde(alias = "ADVANCED_RULES_SHADOW_MODE")]
    advanced_rules_shadow_mode: Option<bool>,
    #[serde(alias = "DASHBOARD_PASSWORD")]
    dashboard_password: Option<String>,
    #[serde(alias = "DASHBOARD_PATH")]
    dashboard_path: Option<String>,
    #[serde(alias = "PROXY_MAP")]
    proxy_map: Option<std::collections::HashMap<String, String>>,
    #[serde(alias = "API_KEY")]
    api_key: Option<String>,
    #[serde(alias = "LLM_MODEL")]
    llm_model: Option<String>,
    #[serde(alias = "LLM_BASE_URL")]
    llm_base_url: Option<String>,
    #[serde(alias = "LLM_QUICK_API_KEY")]
    llm_quick_api_key: Option<String>,
    #[serde(alias = "LLM_DEEP_API_KEY")]
    llm_deep_api_key: Option<String>,
}

pub fn public_router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/dashboard/login", get(login_page))
        .route("/dashboard", get(dashboard_page))
        .route("/dashboard/api/login", post(api_login))
        .route("/dashboard/api/logout", post(api_logout))
}

pub fn protected_router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/biubo/config", get(get_config).post(update_config))
        .route("/api/biubo/config/validate", post(validate_config))
        .route("/api/biubo/config/rollback", post(rollback_config))
        .route("/api/biubo/dashboard/cache-stats", get(cache_stats))
        .route("/api/biubo/dashboard/runtime", get(runtime_status))
        .route("/api/biubo/dashboard/proxy-map", get(proxy_map))
}

async fn login_page(State(state): State<Arc<AppState>>) -> Response {
    let path = state.settings.read().page_root.join("dashboard_login.html");
    match std::fs::read_to_string(&path) {
        Ok(content) => Html(content).into_response(),
        Err(_) => Html("<h1>Login page missing</h1>".to_string()).into_response(),
    }
}

async fn dashboard_page(State(state): State<Arc<AppState>>) -> Response {
    let path = state.settings.read().page_root.join("dashboard.html");
    match std::fs::read_to_string(&path) {
        Ok(content) => Html(content).into_response(),
        Err(_) => Html("<h1>Dashboard page missing</h1>".to_string()).into_response(),
    }
}

async fn api_login(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<LoginRequest>,
) -> Response {
    let (password_hash, challenge_secret, session_timeout_minutes, secure_cookie) = {
        let settings = state.settings.read();
        (
            settings.dashboard_password.clone(),
            settings.challenge_secret.clone(),
            settings.session_timeout,
            settings.ssl_enabled,
        )
    };

    if verify_password(&payload.password, &password_hash) {
        let token = create_dashboard_session_token(
            &password_hash,
            &challenge_secret,
            session_timeout_minutes,
        );
        let secure_attr = if secure_cookie { "; Secure" } else { "" };
        let cookie = format!(
            "biubo_session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
            token,
            session_timeout_minutes.max(1) * 60,
            secure_attr
        );

        let mut response = Json(ApiResponse::<()>::ok()).into_response();
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie).expect("session cookie is valid"),
        );
        response
    } else {
        ApiResponse::<()>::error("Incorrect password").with_status(StatusCode::UNAUTHORIZED)
    }
}

async fn api_logout(State(state): State<Arc<AppState>>) -> Response {
    let secure_attr = if state.settings.read().ssl_enabled {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "biubo_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        secure_attr
    );

    let mut response = Json(ApiResponse::<()>::ok()).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("logout cookie is valid"),
    );
    response
}

async fn get_config(State(state): State<Arc<AppState>>) -> Response {
    let s = state.settings.read();
    let masked_api_key = mask_sensitive_value(&s.api_key, 4);
    let masked_dashboard_password = if s.dashboard_password.is_empty() {
        String::new()
    } else {
        "***".to_string()
    };
    let masked_llm_quick_api_key = mask_sensitive_value(&s.llm_quick_api_key, 4);
    let masked_llm_deep_api_key = mask_sensitive_value(&s.llm_deep_api_key, 4);

    Json(ApiResponse::success(serde_json::json!({
        "WAF_PORT": s.waf_port,
        "DASHBOARD_PATH": s.dashboard_path,
        "PROXY_MAP": s.proxy_map,
        "API_KEY": masked_api_key,
        "DASHBOARD_PASSWORD": masked_dashboard_password,
        "LLM_MODEL": s.llm_model,
        "LLM_BASE_URL": s.llm_base_url,
        "LLM_QUICK_API_KEY": masked_llm_quick_api_key,
        "LLM_DEEP_API_KEY": masked_llm_deep_api_key,
        "ADVANCED_RULES_SHADOW_MODE": s.rule_engine.shadow_mode
    })))
    .into_response()
}

async fn validate_config(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<ConfigUpdateRequest>,
) -> Response {
    let current = Arc::clone(&state.settings.read());
    match apply_config_update(&current, payload).and_then(|candidate| {
        candidate
            .validate()
            .map_err(|error| vec![validation_error(&error)])?;
        Ok(candidate)
    }) {
        Ok(_) => Json(ApiResponse::success(serde_json::json!({
            "valid": true,
            "errors": []
        })))
        .into_response(),
        Err(errors) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ApiResponse {
                status: "error".to_string(),
                data: Some(serde_json::json!({
                    "valid": false,
                    "errors": errors
                })),
                message: Some("Configuration validation failed".to_string()),
            }),
        )
            .into_response(),
    }
}

async fn update_config(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<ConfigUpdateRequest>,
) -> Response {
    let mut guard = state.settings.write();
    let previous = Arc::clone(&guard);
    let candidate = match apply_config_update(&previous, payload) {
        Ok(candidate) => candidate,
        Err(errors) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ApiResponse {
                    status: "error".to_string(),
                    data: Some(serde_json::json!({
                        "valid": false,
                        "errors": errors
                    })),
                    message: Some("Configuration validation failed".to_string()),
                }),
            )
                .into_response();
        }
    };
    if let Err(error) = candidate.validate() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ApiResponse {
                status: "error".to_string(),
                data: Some(serde_json::json!({
                    "valid": false,
                    "errors": [validation_error(&error)]
                })),
                message: Some("Configuration validation failed".to_string()),
            }),
        )
            .into_response();
    }
    if let Err(error) = candidate.try_save_config() {
        tracing::error!("Failed to persist validated dashboard config: {}", error);
        return ApiResponse::<()>::error("Failed to save configuration")
            .with_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let config_root = candidate.project_root.clone();
    rollback_snapshots()
        .lock()
        .insert(config_root, (*previous).clone());
    *guard = Arc::new(candidate);
    invalidate_rules_cache("config update");
    Json(ApiResponse::<()>::ok()).into_response()
}

async fn rollback_config(State(state): State<Arc<AppState>>) -> Response {
    let mut guard = state.settings.write();
    let current = Arc::clone(&guard);
    let config_root = current.project_root.clone();
    let previous = match rollback_snapshots().lock().get(&config_root).cloned() {
        Some(settings) => settings,
        None => {
            return ApiResponse::<()>::error("No configuration rollback snapshot is available")
                .with_status(StatusCode::NOT_FOUND);
        }
    };

    if previous.validate().is_err() {
        return ApiResponse::<()>::error("The rollback snapshot is no longer valid")
            .with_status(StatusCode::UNPROCESSABLE_ENTITY);
    }
    if let Err(error) = previous.try_save_config() {
        tracing::error!("Failed to persist configuration rollback: {}", error);
        return ApiResponse::<()>::error("Failed to save rollback configuration")
            .with_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    rollback_snapshots().lock().remove(&config_root);
    *guard = Arc::new(previous);
    invalidate_rules_cache("config rollback");
    Json(ApiResponse::<()>::ok()).into_response()
}

static ROLLBACK_SNAPSHOTS: LazyLock<
    parking_lot::Mutex<HashMap<PathBuf, crate::config::settings::Settings>>,
> = LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

fn rollback_snapshots(
) -> &'static parking_lot::Mutex<HashMap<PathBuf, crate::config::settings::Settings>> {
    &ROLLBACK_SNAPSHOTS
}

fn apply_config_update(
    current: &crate::config::settings::Settings,
    payload: ConfigUpdateRequest,
) -> Result<crate::config::settings::Settings, Vec<serde_json::Value>> {
    let mut settings = current.clone();
    if let Some(v) = payload.waf_port {
        settings.waf_port = v;
    }
    if let Some(v) = payload.advanced_rules_shadow_mode {
        settings.rule_engine.shadow_mode = v;
    }
    if let Some(v) = payload.dashboard_password {
        let trimmed = v.trim();
        if !trimmed.is_empty() && !looks_masked_secret(trimmed) {
            settings.dashboard_password = hash_secret_if_needed(trimmed).map_err(|_| {
                vec![serde_json::json!({
                    "field": "DASHBOARD_PASSWORD",
                    "message": "Could not process dashboard password"
                })]
            })?;
        }
    }
    if let Some(v) = payload.dashboard_path {
        settings.dashboard_path = v;
    }
    if let Some(v) = payload.proxy_map {
        settings.proxy_map = v;
    }
    if let Some(v) = payload.api_key {
        if !looks_masked_secret(&v) {
            settings.api_key = v;
        }
    }
    if let Some(v) = payload.llm_model {
        settings.llm_model = v;
    }
    if let Some(v) = payload.llm_base_url {
        settings.llm_base_url = v;
    }
    if let Some(v) = payload.llm_quick_api_key {
        if !looks_masked_secret(&v) {
            settings.llm_quick_api_key = v;
        }
    }
    if let Some(v) = payload.llm_deep_api_key {
        if !looks_masked_secret(&v) {
            settings.llm_deep_api_key = v;
        }
    }
    Ok(settings)
}

fn validation_error(error: &str) -> serde_json::Value {
    let (field, message) = if error.starts_with("WAF_PORT") {
        ("WAF_PORT", "Port must be between 1 and 65535")
    } else if error.starts_with("SSL_PORT") {
        ("SSL_PORT", "SSL port must be positive when SSL is enabled")
    } else if error.starts_with("SESSION_TIMEOUT") {
        ("SESSION_TIMEOUT", "Session timeout must be positive")
    } else if error.starts_with("CACHE_TTL") {
        ("CACHE_TTL", "Cache TTL must be positive")
    } else if error.starts_with("RATE_LIMIT_PER_SEC") {
        ("RATE_LIMIT_PER_SEC", "Rate limit must be positive")
    } else if error.starts_with("UPLOAD_MAX_SIZE") {
        ("UPLOAD_MAX_SIZE", "Upload max size must be positive")
    } else if error.starts_with("CHALLENGE_SECRET") {
        ("CHALLENGE_SECRET", "Challenge secret cannot be empty")
    } else if error.starts_with("CHALLENGE_EXPIRE") {
        ("CHALLENGE_EXPIRE", "Challenge expiration must be positive")
    } else if error.starts_with("PROXY_MAP") {
        (
            "PROXY_MAP",
            "Proxy map contains an invalid host or target URL",
        )
    } else if error.starts_with("SSL_DOMAINS") {
        (
            "SSL_DOMAINS",
            "At least one SSL domain is required when SSL is enabled",
        )
    } else if error.starts_with("SSL_ACME_EMAIL") {
        (
            "SSL_ACME_EMAIL",
            "ACME email is required when SSL is enabled",
        )
    } else if error.starts_with("LLM_TIMEOUT_SECS") {
        ("LLM_TIMEOUT_SECS", "LLM timeout must be positive")
    } else {
        ("CONFIG", "Configuration is invalid")
    };
    serde_json::json!({ "field": field, "message": message })
}

fn invalidate_rules_cache(action: &str) {
    if let Err(e) = crate::core::engine::waf_engine::invalidate_all_rules_cache() {
        tracing::error!(
            "Failed to invalidate WAF rules cache after {}: {}",
            action,
            e
        );
    }
}

async fn proxy_map(State(state): State<Arc<AppState>>) -> Response {
    let s = state.settings.read();
    Json(ApiResponse::success(serde_json::json!({
        "proxy_map": s.proxy_map
    })))
    .into_response()
}

async fn runtime_status(State(state): State<Arc<AppState>>) -> Response {
    let detection = state
        .async_detection_queue
        .as_ref()
        .map(|queue| queue.snapshot());
    let metrics = crate::core::metrics::METRICS.snapshot();
    #[cfg(feature = "advanced-rules")]
    let shadow_stats = crate::core::engine::waf_engine::get_advanced_rules_shadow_stats();
    #[cfg(not(feature = "advanced-rules"))]
    let shadow_stats = serde_json::json!({});
    Json(ApiResponse::success(serde_json::json!({
        "advanced_rules_shadow_mode": state.settings.read().rule_engine.shadow_mode,
        "advanced_rules_shadow_stats": shadow_stats,
        "detection_queue": detection,
        "log_queue": {
            "capacity": metrics.log_queue_capacity,
            "depth": metrics.log_queue_depth,
            "submitted": metrics.log_queue_submitted,
            "written": metrics.log_written,
            "dropped": metrics.log_queue_dropped,
            "security_dropped": metrics.log_queue_security_dropped,
            "write_errors": metrics.log_write_errors,
        }
    })))
    .into_response()
}

async fn cache_stats() -> Response {
    let stats = crate::core::engine::waf_engine::get_cache_stats();
    Json(ApiResponse::success(stats)).into_response()
}

fn looks_masked_secret(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed == "***" || trimmed.ends_with("***")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::dashboard_auth::dashboard_auth_middleware;
    use crate::api::routes::waf_events::EventBroadcaster;
    use crate::config::settings::Settings;
    use crate::core::reputation::aggregator::ReputationAggregator;
    use crate::core::reputation::manager::ReputationManager;
    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware::from_fn;
    use tower::ServiceExt;

    fn make_app(project_root: PathBuf) -> (Router, Arc<AppState>, String) {
        let mut settings = Settings::default();
        settings.project_root = project_root;
        settings.waf_port = 8181;
        settings.dashboard_password = "test-password-hash".to_string();
        settings.challenge_secret = "test-challenge-secret".to_string();
        let settings = Arc::new(parking_lot::RwLock::new(Arc::new(settings)));
        let state = Arc::new(AppState {
            settings: settings.clone(),
            error_pages: HashMap::new(),
            async_detection_queue: None,
            event_broadcaster: EventBroadcaster::new(),
            reputation_aggregator: ReputationAggregator::with_defaults(),
            reputation_manager: ReputationManager::new(&[]),
        });
        let auth_state = state.clone();
        let app = Router::new()
            .merge(protected_router(state.clone()))
            .layer(from_fn(
                move |req: Request<Body>, next: axum::middleware::Next| {
                    let state = auth_state.clone();
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
            ))
            .with_state(state.clone());
        let cookie = format!(
            "biubo_session={}",
            create_dashboard_session_token("test-password-hash", "test-challenge-secret", 20)
        );
        (app, state, cookie)
    }

    fn temp_project_root() -> PathBuf {
        std::env::temp_dir().join(format!("biubo-dashboard-test-{}", uuid::Uuid::new_v4()))
    }

    async fn post_json(app: Router, path: &str, cookie: &str, body: &str) -> Response {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn config_validate_update_rollback_and_legacy_api_are_safe() {
        let root = temp_project_root();
        std::fs::create_dir_all(&root).unwrap();
        let (app, state, cookie) = make_app(root.clone());
        let config_path = root.join("config.json");

        let valid_preview = post_json(
            app.clone(),
            "/api/biubo/config/validate",
            &cookie,
            r#"{"waf_port":8182,"api_key":"preview-only-secret"}"#,
        )
        .await;
        assert_eq!(valid_preview.status(), StatusCode::OK);
        let preview_body = axum::body::to_bytes(valid_preview.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!String::from_utf8(preview_body.to_vec())
            .unwrap()
            .contains("preview-only-secret"));
        assert!(!config_path.exists());
        assert_eq!(state.settings.read().waf_port, 8181);

        let invalid_preview = post_json(
            app.clone(),
            "/api/biubo/config/validate",
            &cookie,
            r#"{"proxy_map":{"example.test":"not-a-url"},"api_key":"do-not-echo-secret"}"#,
        )
        .await;
        assert_eq!(invalid_preview.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let invalid_body = axum::body::to_bytes(invalid_preview.into_body(), usize::MAX)
            .await
            .unwrap();
        let invalid_text = String::from_utf8(invalid_body.to_vec()).unwrap();
        assert!(invalid_text.contains("PROXY_MAP"));
        assert!(!invalid_text.contains("do-not-echo-secret"));
        assert!(!config_path.exists());
        assert_eq!(state.settings.read().waf_port, 8181);

        let invalid_update = post_json(
            app.clone(),
            "/api/biubo/config",
            &cookie,
            r#"{"waf_port":0}"#,
        )
        .await;
        assert_eq!(invalid_update.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(state.settings.read().waf_port, 8181);
        assert!(!config_path.exists());

        let update = post_json(
            app.clone(),
            "/api/biubo/config",
            &cookie,
            r#"{"WAF_PORT":8182,"ADVANCED_RULES_SHADOW_MODE":true,"DASHBOARD_PASSWORD":"***","API_KEY":"update-secret","LLM_QUICK_API_KEY":"quick-update-secret"}"#,
        )
        .await;
        assert_eq!(update.status(), StatusCode::OK);
        assert_eq!(state.settings.read().waf_port, 8182);
        assert_eq!(
            state.settings.read().dashboard_password,
            "test-password-hash"
        );
        assert!(state.settings.read().rule_engine.shadow_mode);
        let persisted = std::fs::read_to_string(&config_path).unwrap();
        let persisted_json: serde_json::Value = serde_json::from_str(&persisted).unwrap();
        let persisted_rules: crate::config::settings::RuleEngineConfig =
            serde_json::from_value(persisted_json["RULE_ENGINE"].clone()).unwrap();
        assert!(persisted_rules.shadow_mode);
        assert!(!persisted.contains("update-secret"));
        assert!(!persisted.contains("quick-update-secret"));

        let rollback = post_json(app.clone(), "/api/biubo/config/rollback", &cookie, "{}").await;
        assert_eq!(rollback.status(), StatusCode::OK);
        assert_eq!(state.settings.read().waf_port, 8181);
        assert!(!state.settings.read().rule_engine.shadow_mode);
        assert!(state.settings.read().api_key.is_empty());
        assert!(state.settings.read().llm_quick_api_key.is_empty());
        let rollback_body = axum::body::to_bytes(rollback.into_body(), usize::MAX)
            .await
            .unwrap();
        let rollback_text = String::from_utf8(rollback_body.to_vec()).unwrap();
        assert!(!rollback_text.contains("update-secret"));
        assert!(!rollback_text.contains("quick-update-secret"));

        let legacy_get = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/biubo/config")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(legacy_get.status(), StatusCode::OK);
        let legacy_body = axum::body::to_bytes(legacy_get.into_body(), usize::MAX)
            .await
            .unwrap();
        let legacy_text = String::from_utf8(legacy_body.to_vec()).unwrap();
        assert!(!legacy_text.contains("update-secret"));

        let _ = std::fs::remove_dir_all(root);
    }
}
