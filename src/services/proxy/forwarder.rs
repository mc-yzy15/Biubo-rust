use std::collections::HashMap;

use crate::config::settings::Settings;
use crate::utils::http_utils::STRIP_RESP_HEADERS;

static HTTP_CLIENT: once_cell::sync::Lazy<reqwest::Client> = once_cell::sync::Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(5))
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .build()
        .expect("Failed to build HTTP client")
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
    let target_url = format!(
        "{}/{}{}",
        target_base.trim_end_matches('/'),
        path.trim_start_matches('/'),
        query_string.map(|q| format!("?{}", q)).unwrap_or_default()
    );

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

    let mut req_builder = HTTP_CLIENT.request(method.parse::<reqwest::Method>()?, &target_url);

    for (key, value) in &req_headers {
        req_builder = req_builder.header(key.as_str(), value.as_str());
    }

    for (key, value) in cookies {
        req_builder = req_builder.header("Cookie", format!("{}={}", key, value));
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
