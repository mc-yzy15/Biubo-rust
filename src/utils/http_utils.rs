use std::collections::HashSet;

use crate::config::settings::IpHeaderConfig;
use crate::utils::url_validator::is_ip_in_range;

static HTTP_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(reqwest::Client::new);

pub static STRIP_RESP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
    "server",
    "x-powered-by",
];

pub fn get_client_ip_with_trust(
    headers: &axum::http::HeaderMap,
    config: &IpHeaderConfig,
    remote_addr: &str,
) -> String {
    if !config.state {
        return String::new();
    }

    let is_trusted = if config.trusted_proxies.is_empty() {
        true
    } else {
        config
            .trusted_proxies
            .iter()
            .any(|cidr| is_ip_in_range(remote_addr, cidr))
    };

    if !is_trusted {
        return remote_addr.to_string();
    }

    for header_name in &config.order {
        if let Some(value) = headers.get(header_name) {
            if let Ok(v) = value.to_str() {
                if header_name == "X-Forwarded-For" {
                    if let Some(first) = v.split(',').next() {
                        return first.trim().to_string();
                    }
                }
                return v.to_string();
            }
        }
    }

    remote_addr.to_string()
}

pub fn is_static_resource(url: &str, extensions: &HashSet<String>) -> bool {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };

    let path = parsed.path().to_lowercase();

    let suffix = match std::path::Path::new(&path).extension() {
        Some(ext) => format!(".{}", ext.to_string_lossy()),
        None => return false,
    };

    if !extensions.contains(&suffix) {
        return false;
    }

    if !path.ends_with(&suffix) {
        return false;
    }

    if !parsed.query().map(|q| q.is_empty()).unwrap_or(true) {
        let decoded =
            percent_encoding::percent_decode_str(parsed.query().unwrap_or("")).decode_utf8_lossy();
        if ['<', '>', '\'', '"', '(', ')']
            .iter()
            .any(|c| decoded.contains(*c))
        {
            return false;
        }
    }

    true
}

pub async fn get_ip_info(ip: &str) -> serde_json::Value {
    let url = format!("https://biubo.zplb.org.cn/api/ip?ip={}", ip);
    match HTTP_CLIENT
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("get_ip_info failed for {}: {}", ip, e);
                serde_json::json!({})
            }
        },
        Err(e) => {
            tracing::warn!("get_ip_info failed for {}: {}", ip, e);
            serde_json::json!({})
        }
    }
}

pub async fn get_geo_info(city: &str, country: &str) -> serde_json::Value {
    let queries: Vec<String> = {
        let mut q = Vec::new();
        if !city.is_empty() && !country.is_empty() {
            q.push(format!("{}, {}", city, country));
        }
        if !city.is_empty() {
            q.push(city.to_string());
        }
        if !country.is_empty() {
            q.push(country.to_string());
        }
        q
    };

    for query in queries {
        let url = format!(
            "https://biubo.zplb.org.cn/api/geo?q={}",
            percent_encoding::utf8_percent_encode(&query, percent_encoding::NON_ALPHANUMERIC)
        );
        match HTTP_CLIENT
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(v) = resp.json::<serde_json::Value>().await {
                    if let Some(results) = v.as_array() {
                        for loc in results {
                            if loc.get("location_type").and_then(|v| v.as_str()) == Some("city") {
                                return serde_json::json!({
                                    "lat": loc.get("latitude").and_then(|v| v.as_f64()).unwrap_or(0.0),
                                    "lon": loc.get("longitude").and_then(|v| v.as_f64()).unwrap_or(0.0)
                                });
                            }
                        }
                        for loc in results {
                            if loc.get("location_type").and_then(|v| v.as_str()) == Some("country")
                            {
                                return serde_json::json!({
                                    "lat": loc.get("latitude").and_then(|v| v.as_f64()).unwrap_or(0.0),
                                    "lon": loc.get("longitude").and_then(|v| v.as_f64()).unwrap_or(0.0)
                                });
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("get_geo_info failed for {}, {}: {}", city, country, e);
            }
        }
    }

    serde_json::json!({})
}

#[cfg(test)]
pub async fn get_ip_reputation(ip: &str) -> bool {
    let url = format!("https://biubo.zplb.org.cn/api/ip/reputation?ip={}", ip);
    match HTTP_CLIENT
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(v) => v
                .get("safe")
                .and_then(|s| s.as_bool())
                .unwrap_or(false),
            Err(e) => {
                tracing::warn!("get_ip_reputation failed for {}: {}", ip, e);
                false
            }
        },
        Err(e) => {
            tracing::warn!("get_ip_reputation failed for {}: {}", ip, e);
            false
        }
    }
}


