use crate::api::app::AppState;
use crate::core::engine::waf_engine::detect_request;
use crate::core::security::challenge::{
    ChallengeStatus, get_challenge_token, verify_challenge_token,
};
use crate::core::security::rate_limit::{BlockReason, check_rate_limit};
use crate::core::session::manager::{build_log_entry, create_session};
use crate::data::storage::manager::get_db;
use crate::services::proxy::forwarder::forward_request;
use crate::utils::compression::decode_content;
use crate::utils::http_utils::{get_client_ip, get_ip_reputation, is_static_resource};
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use url::form_urlencoded;

static STRIKE_COUNTER: once_cell::sync::Lazy<DashMap<String, u32>> =
    once_cell::sync::Lazy::new(DashMap::new);

pub fn router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/{*path}", get(reverse_proxy))
        .route("/", get(reverse_proxy))
        .with_state(state)
}

#[axum::debug_handler]
async fn reverse_proxy(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> Response {
    let (
        host,
        target_base,
        client_ip,
        user_agent,
        request_id,
        proxy_status,
        is_whitelisted,
        path,
        query_string,
        method,
        headers,
        cookies,
        raw_cookie_header,
        upload_max_size,
        upload_allowed_extensions,
        challenge_secret,
        content_encoding,
    ) = {
        let settings = state.settings.read();

        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let target_base = match settings.proxy_map.get(&host) {
            Some(t) => t.clone(),
            None => {
                return Html(state.error_pages.get("404").cloned().unwrap_or_default())
                    .into_response();
            }
        };

        let client_ip = get_client_ip(req.headers(), &settings.get_ip_from_headers);
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let request_id = uuid::Uuid::new_v4().to_string();

        let proxy_status = {
            let db = get_db(&host);
            db.ram_get("site")
                .and_then(|v| v.get("status").cloned())
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "on".to_string())
        };

        let is_whitelisted = {
            let db = get_db(&host);
            db.is_whitelisted(&client_ip)
        };

        if !settings.is_initialized() {
            let p = req.uri().path().to_string();
            if !p.starts_with("/init")
                && !is_static_resource(&req.uri().to_string(), &settings.static_extensions)
            {
                return Redirect::temporary("/init/").into_response();
            }
        }

        let path = req.uri().path().to_string();
        let query_string = req.uri().query().map(String::from);
        let method = req.method().clone();
        let headers = extract_headers(req.headers());
        let cookies = extract_cookies(req.headers());
        let raw_cookie_header = req
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let content_encoding = req
            .headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let upload_max_size = settings.upload_max_size;
        let upload_allowed_extensions = settings.upload_allowed_extensions.clone();
        let challenge_secret = settings.challenge_secret.clone();

        drop(settings);

        (
            host,
            target_base,
            client_ip,
            user_agent,
            request_id,
            proxy_status,
            is_whitelisted,
            path,
            query_string,
            method,
            headers,
            cookies,
            raw_cookie_header,
            upload_max_size,
            upload_allowed_extensions,
            challenge_secret,
            content_encoding,
        )
    };

    let decoded_body = {
        let body_result = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await;
        match body_result {
            Ok(bytes) => {
                let body_bytes = bytes.to_vec();
                if body_bytes.is_empty() {
                    Vec::new()
                } else {
                    decode_content(&body_bytes, &content_encoding)
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Request body read failed (possible attack or oversized payload): {} from {}",
                    e,
                    client_ip
                );
                Vec::new()
            }
        }
    };

    if proxy_status == "off" {
        return Html(state.error_pages.get("404").cloned().unwrap_or_default()).into_response();
    }

    if proxy_status != "pass" && !is_whitelisted {
        let rate_result = {
            let s = state.settings.read().clone();
            check_rate_limit(&client_ip, &host, &s).await
        };

        if rate_result.blocked {
            let challenge_cookie = raw_cookie_header
                .as_deref()
                .and_then(|c| extract_cookie_value(c, "bw_challenge"));

            let status = verify_challenge_token(
                challenge_cookie.as_deref(),
                &client_ip,
                &user_agent,
                &challenge_secret,
            );
            match status {
                ChallengeStatus::Invalid => {
                    let db = get_db(&host);
                    let _ = db.ban_ip(&client_ip, "forged_challenge_token", None).await;
                    return build_forbidden_response(&state, "403");
                }
                ChallengeStatus::Expired | ChallengeStatus::Missing => {
                    let db = get_db(&host);
                    if db.is_banned(&client_ip) {
                        if db.is_temporary_banned(&client_ip) {
                            let captcha_cookie = raw_cookie_header
                                .as_deref()
                                .and_then(|c| extract_cookie_value(c, "bw_captcha"));

                            if captcha_cookie.is_none() {
                                return build_captcha_response(&state, &challenge_secret);
                            }
                        }
                        return build_forbidden_response(&state, "403");
                    }

                    let mut strikes = STRIKE_COUNTER.entry(client_ip.clone()).or_insert(0);
                    let current = *strikes.value();
                    if current >= 3 {
                        let db = get_db(&host);
                        let reason = match rate_result.reason {
                            Some(BlockReason::Banned) => "banned",
                            Some(BlockReason::TemporaryBanned) => "temporary_banned",
                            Some(BlockReason::RateLimit) => "rate_limit",
                            None => "unknown",
                        };
                        let _ = db.ban_ip_temporary(&client_ip, reason).await;
                        return build_captcha_response(&state, &challenge_secret);
                    }
                    *strikes.value_mut() += 1;
                    return build_challenge_response(
                        &state,
                        &client_ip,
                        &user_agent,
                        &challenge_secret,
                    );
                }
                ChallengeStatus::Valid => {}
            }
        }

        let reputation = get_ip_reputation(&client_ip).await;
        if !reputation {
            let db = get_db(&host);
            let _ = db.ban_ip(&client_ip, "bad_ip_reputation", None).await;
            return build_forbidden_response(&state, "403");
        }

        let (file_safe, file_msg) = check_file_security(
            &decoded_body,
            &headers,
            upload_max_size,
            &upload_allowed_extensions,
        );
        if !file_safe {
            let db = get_db(&host);
            let _ = db.ban_ip(&client_ip, &file_msg, None).await;
            return build_forbidden_response(&state, "403");
        }

        let mut args_map = HashMap::new();
        if let Some(ref qs) = query_string {
            for (key, value) in form_urlencoded::parse(qs.as_bytes()) {
                args_map.insert(key.into_owned(), value.into_owned());
            }
        }

        let detection = {
            let s = state.settings.read().clone();
            detect_request(
                &path,
                method.as_str(),
                &headers,
                &cookies,
                &decoded_body,
                &args_map,
                &s,
                &host,
            )
            .await
        };

        if detection.detection_type != "normal" {
            let log_entry = build_log_entry(
                &request_id,
                &build_snapshot(
                    &client_ip,
                    method.as_str(),
                    &path,
                    &headers,
                    &cookies,
                    &decoded_body,
                    &query_string,
                ),
                &detection,
                403,
            );
            create_session(&request_id, &host, log_entry);

            if proxy_status == "on" {
                return build_forbidden_response(&state, "403");
            }
        }
    }

    let forward_result = {
        let s = state.settings.read().clone();
        forward_request(
            &target_base,
            &path,
            method.as_str(),
            &headers,
            &decoded_body,
            &cookies,
            query_string.as_deref(),
            &s,
        )
        .await
    };

    let forward_result = match forward_result {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Forward error: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Html(state.error_pages.get("500").cloned().unwrap_or_default()),
            )
                .into_response();
        }
    };

    if proxy_status != "pass" {
        let log_entry = build_log_entry(
            &request_id,
            &build_snapshot(
                &client_ip,
                method.as_str(),
                &path,
                &headers,
                &cookies,
                &decoded_body,
                &query_string,
            ),
            &crate::core::engine::waf_engine::DetectionResult::normal(),
            forward_result.status,
        );
        create_session(&request_id, &host, log_entry);
    }

    let content_type = forward_result
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let mut final_content = forward_result.content;
    if content_type.contains("text/html") {
        final_content = inject_beacon(&final_content, &request_id);
    }

    let mut response = Response::builder().status(forward_result.status);
    for (key, value) in &forward_result.headers {
        if key.eq_ignore_ascii_case("content-length")
            || key.eq_ignore_ascii_case("content-encoding")
        {
            continue;
        }
        response = response.header(key.as_str(), value.as_str());
    }

    match response.body(Body::from(final_content)) {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to build response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .expect("Failed to build error response")
        }
    }
}

fn extract_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            map.insert(key.as_str().to_string(), v.to_string());
        }
    }
    map
}

fn extract_cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(cookie_header) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for pair in cookie_header.split(';') {
            let pair = pair.trim();
            if let Some((key, value)) = pair.split_once('=') {
                map.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    map
}

fn extract_cookie_value(cookie_str: &str, name: &str) -> Option<String> {
    for pair in cookie_str.split(';') {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once('=') {
            if key.trim() == name {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

fn build_snapshot(
    ip: &str,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    cookies: &HashMap<String, String>,
    body: &[u8],
    query_string: &Option<String>,
) -> HashMap<String, serde_json::Value> {
    let mut map = HashMap::new();
    map.insert("remote_addr".to_string(), serde_json::json!(ip));
    map.insert("method".to_string(), serde_json::json!(method));
    map.insert("url".to_string(), serde_json::json!(url));
    map.insert("headers".to_string(), serde_json::json!(headers));
    map.insert("cookies".to_string(), serde_json::json!(cookies));
    map.insert(
        "data".to_string(),
        serde_json::json!(String::from_utf8_lossy(body).to_string()),
    );
    if let Some(qs) = query_string {
        map.insert("args".to_string(), serde_json::json!(qs));
    }
    map
}

fn check_file_security(
    body: &[u8],
    headers: &HashMap<String, String>,
    upload_max_size: usize,
    upload_allowed_extensions: &std::collections::HashSet<String>,
) -> (bool, String) {
    let content_type = headers
        .get("content-type")
        .map(|v| v.to_string())
        .unwrap_or_default();

    if !content_type.contains("multipart/form-data") {
        if body.len() > upload_max_size {
            return (false, "upload_size_exceeded".to_string());
        }
        return (true, String::new());
    }

    if body.len() > upload_max_size {
        return (false, "upload_size_exceeded".to_string());
    }

    let body_str = String::from_utf8_lossy(body);
    for filename in extract_filenames_from_multipart(&body_str) {
        let ext = std::path::Path::new(&filename)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();
        if !ext.is_empty() && !upload_allowed_extensions.contains(&ext) {
            return (false, format!("forbidden_extension:{}", ext));
        }
    }

    (true, String::new())
}

fn extract_filenames_from_multipart(body: &str) -> Vec<String> {
    let mut filenames = Vec::new();
    let re = regex::Regex::new(r#"filename="([^"]+)""#).unwrap();
    for cap in re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            filenames.push(m.as_str().to_string());
        }
    }
    filenames
}

fn inject_beacon(content: &[u8], request_id: &str) -> Vec<u8> {
    let html = String::from_utf8_lossy(content);
    if !html.contains("<body") {
        return content.to_vec();
    }

    let beacon_script = format!(
        r#"<script src="/biubo-cgi/scripts/biubo/beacon.js" data-request-id="{}"></script>"#,
        request_id
    );

    if let Some(pos) = html.rfind("</body>") {
        let mut result = html.into_owned();
        result.insert_str(pos, &beacon_script);
        return result.into_bytes();
    }

    content.to_vec()
}

fn build_challenge_response(
    state: &Arc<AppState>,
    ip: &str,
    ua: &str,
    challenge_secret: &str,
) -> Response {
    let token = get_challenge_token(ip, ua, challenge_secret);
    let html = state
        .error_pages
        .get("challenge")
        .cloned()
        .unwrap_or_else(|| "<h1>Challenge Required</h1>".to_string());

    (
        StatusCode::FORBIDDEN,
        [(
            "Set-Cookie",
            format!("bw_challenge={}; Path=/; HttpOnly", token),
        )],
        Html(html),
    )
        .into_response()
}

fn build_captcha_response(state: &Arc<AppState>, _challenge_secret: &str) -> Response {
    let html = state
        .error_pages
        .get("captcha")
        .cloned()
        .unwrap_or_else(|| "<h1>Captcha Required</h1>".to_string());

    (StatusCode::FORBIDDEN, Html(html)).into_response()
}

fn build_forbidden_response(state: &Arc<AppState>, code: &str) -> Response {
    let html = state
        .error_pages
        .get(code)
        .cloned()
        .unwrap_or_else(|| format!("<h1>{} Error</h1>", code));

    let status = match code {
        "403" => StatusCode::FORBIDDEN,
        "429" => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::FORBIDDEN,
    };

    (status, Html(html)).into_response()
}
