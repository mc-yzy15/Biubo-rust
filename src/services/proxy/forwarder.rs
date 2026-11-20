use std::collections::HashMap;

use crate::config::settings::Settings;
use crate::utils::http_utils::STRIP_RESP_HEADERS;
use crate::utils::url_validator::{resolve_safe_target, UrlValidationResult};

static HTTP_CLIENT: once_cell::sync::Lazy<Result<reqwest::Client, String>> =
    once_cell::sync::Lazy::new(build_http_client);

static PINNED_HTTP_CLIENTS: once_cell::sync::Lazy<moka::sync::Cache<String, reqwest::Client>> =
    once_cell::sync::Lazy::new(|| {
        moka::sync::Cache::builder()
            .max_capacity(256)
            .time_to_idle(std::time::Duration::from_secs(60))
            .build()
    });

fn build_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(5))
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))
}

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
    let path_segment = if trimmed_path.is_empty() {
        ""
    } else {
        trimmed_path
    };
    let separator = if path_segment.is_empty() { "" } else { "/" };
    let target_url = format!(
        "{}{}{}{}",
        target_base.trim_end_matches('/'),
        separator,
        path_segment,
        query_string.map(|q| format!("?{}", q)).unwrap_or_default()
    );

    let safe_addresses = match resolve_safe_target(&target_url).await {
        Ok(addresses) => addresses,
        Err(validation) => {
            let reason = match validation {
                UrlValidationResult::PrivateIp => "private IP address".to_string(),
                UrlValidationResult::Localhost => "localhost".to_string(),
                UrlValidationResult::LinkLocal => "link-local address".to_string(),
                UrlValidationResult::Reserved => "reserved address".to_string(),
                UrlValidationResult::DnsResolvesToPrivate => {
                    "DNS resolves to private IP".to_string()
                }
                UrlValidationResult::InvalidUrl => "invalid URL".to_string(),
            };
            tracing::warn!("SSRF attempt blocked: {} -> {}", target_url, reason);
            return Err(format!("SSRF attempt detected: target URL resolves to {}", reason).into());
        }
    };

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

    let parsed_target = url::Url::parse(&target_url)?;
    let host = parsed_target
        .host_str()
        .ok_or_else(|| "Target URL has no host".to_string())?;
    let client = if host.parse::<std::net::IpAddr>().is_ok() {
        HTTP_CLIENT
            .as_ref()
            .cloned()
            .map_err(|e| format!("HTTP client initialization failed: {}", e))?
    } else {
        if safe_addresses.is_empty() {
            return Err("DNS target resolved to no addresses".into());
        }
        // Key the client by the exact validated DNS result set. If DNS changes,
        // the new request cannot reuse a client pinned to stale addresses.
        let cache_key = format!(
            "{}:{}:{:?}",
            host.to_ascii_lowercase(),
            parsed_target.port_or_known_default().unwrap_or_default(),
            safe_addresses
        );
        if let Some(client) = PINNED_HTTP_CLIENTS.get(&cache_key) {
            client
        } else {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(5))
                .pool_max_idle_per_host(20)
                .pool_idle_timeout(std::time::Duration::from_secs(90))
                .resolve_to_addrs(host, &safe_addresses)
                .build()?;
            PINNED_HTTP_CLIENTS.insert(cache_key, client.clone());
            client
        }
    };

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
