use std::collections::HashMap;

use crate::config::settings::Settings;
use crate::utils::http_utils::STRIP_RESP_HEADERS;
use crate::utils::url_validator::{is_safe_target, validate_target_url, UrlValidationResult};

static HTTP_CLIENT: once_cell::sync::Lazy<Result<reqwest::Client, String>> =
    once_cell::sync::Lazy::new(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .pool_max_idle_per_host(20)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))
    });

const WSGI_FORBIDDEN_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

pub struct ForwardResult {
    pub content: Vec<u8>,
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

pub async fn forward_request(
    target_base: &str,
    path: &str,
    method: &str,
    headers: &HashMap<String, String>,
    data: &[u8],
    cookies: &HashMap<String, String>,
    query_string: Option<&str>,
    settings: &Settings,
) -> Result<ForwardResult, Box<dyn std::error::Error + Send + Sync>> {
    let trimmed_path = path.trim_start_matches('/');
    let path_segment = if trimmed_path.is_empty() { "" } else { trimmed_path };
    let separator = if path_segment.is_empty() { "" } else { "/" };
    let target_url = format!(
        "{}{}{}{}",
        target_base.trim_end_matches('/'),
        separator,
        path_segment,
        query_string.map(|q| format!("?{}", q)).unwrap_or_default()
    );

    if !is_safe_target(&target_url) {
        let reason = match validate_target_url(&target_url) {
            UrlValidationResult::PrivateIp => "private IP address".to_string(),
            UrlValidationResult::Localhost => "localhost".to_string(),
            UrlValidationResult::LinkLocal => "link-local address".to_string(),
            UrlValidationResult::Reserved => "reserved address".to_string(),
            UrlValidationResult::InvalidUrl => "invalid URL".to_string(),
            UrlValidationResult::Valid => unreachable!(),
        };
        tracing::warn!("SSRF attempt blocked: {} -> {}", target_url, reason);
        return Err(format!("SSRF attempt detected: target URL resolves to {}", reason).into());
    }

    let mut req_headers = headers.clone();

    for key in WSGI_FORBIDDEN_HEADERS {
        req_headers.remove(*key);
    }

    if !settings.host_forward {
        if let Ok(parsed) = url::Url::parse(target_base) {
            if let Some(host) = parsed.host_str() {
                req_headers.insert("Host".to_string(), host.to_string());
            }
        }
    }
    req_headers.insert(
        "Accept-Encoding".to_string(),
        "gzip, deflate, br".to_string(),
    );

    let client = HTTP_CLIENT.as_ref().map_err(|e| {
        let err: Box<dyn std::error::Error + Send + Sync> =
            format!("HTTP client initialization failed: {}", e).into();
        err
    })?;

    let mut req_builder = client.request(method.parse::<reqwest::Method>()?, &target_url);

    for (key, value) in &req_headers {
        req_builder = req_builder.header(key.as_str(), value.as_str());
    }

    if !cookies.is_empty() {
        let cookie_header = cookies
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<_>>()
            .join("; ");
        req_builder = req_builder.header("Cookie", &cookie_header);
    }

    req_builder = req_builder.body(data.to_vec());

    let resp = req_builder.send().await?;

    let status = resp.status().as_u16();

    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter(|(name, _)| {
            !STRIP_RESP_HEADERS
                .iter()
                .any(|s| name.as_str().eq_ignore_ascii_case(s))
        })
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    let content = resp.bytes().await?.to_vec();

    Ok(ForwardResult {
        content,
        status,
        headers: resp_headers,
    })
}
