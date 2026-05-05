use std::collections::HashSet;

use crate::config::settings::IpHeaderConfig;

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

pub fn get_client_ip(headers: &axum::http::HeaderMap, config: &IpHeaderConfig) -> String {
    if config.state {
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
    }
    String::new()
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
    let client = reqwest::Client::new();
    match client
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
        let client = reqwest::Client::new();
        match client
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
                                    "lat": loc.get("latitude").and_then(|v| v.as_f64()).expect("City latitude is missing or not a number"),
                                    "lon": loc.get("longitude").and_then(|v| v.as_f64()).expect("City longitude is missing or not a number")
                                });
                            }
                        }
                        for loc in results {
                            if loc.get("location_type").and_then(|v| v.as_str()) == Some("country")
                            {
                                return serde_json::json!({
                                    "lat": loc.get("latitude").and_then(|v| v.as_f64()).expect("Country latitude is missing or not a number"),
                                    "lon": loc.get("longitude").and_then(|v| v.as_f64()).expect("Country longitude is missing or not a number")
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

pub async fn get_ip_reputation(ip: &str) -> bool {
    let url = format!("https://biubo.zplb.org.cn/api/ip/reputation?ip={}", ip);
    let client = reqwest::Client::new();
    match client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(v) => v
                .get("safe")
                .and_then(|s| s.as_bool())
                .expect("IP reputation safe field is missing or not a boolean"),
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

#[allow(dead_code)]
pub async fn verify_captcha(ticket: &str) -> bool {
    let client = reqwest::Client::new();
    match client
        .post("https://captcha.zplb.org.cn/api/verify")
        .json(&serde_json::json!({"ticket": ticket}))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(v) => v
                .get("success")
                .and_then(|s| s.as_bool())
                .expect("Captcha success field is missing or not a boolean"),
            Err(e) => {
                tracing::error!("Captcha verification failed: {}", e);
                false
            }
        },
        Err(e) => {
            tracing::error!("Captcha verification failed: {}", e);
            false
        }
    }
}

#[allow(dead_code)]
pub fn get_source_from_referer(referer: &str) -> String {
    if referer.is_empty() {
        return "direct".to_string();
    }

    let referer_lower = referer.to_lowercase();

    let search_engines = [
        "google.",
        "bing.",
        "baidu.",
        "duckduckgo.",
        "yahoo.",
        "yandex.",
        "sogou.",
        "so.com",
        "360.cn",
        "naver.",
        "daum.",
        "ask.",
        "ecosia.",
        "brave.com/search",
    ];

    let social_networks = [
        "twitter.",
        "t.co",
        "x.com",
        "facebook.",
        "fb.com",
        "instagram.",
        "linkedin.",
        "weibo.",
        "wechat.",
        "wx.qq.com",
        "tiktok.",
        "douyin.",
        "youtube.",
        "youtu.be",
        "pinterest.",
        "reddit.",
        "telegram.",
        "whatsapp.",
        "line.",
        "discord.",
        "snapchat.",
    ];

    if search_engines.iter().any(|s| referer_lower.contains(s)) {
        return "search".to_string();
    }
    if social_networks.iter().any(|s| referer_lower.contains(s)) {
        return "social".to_string();
    }
    "referral".to_string()
}
