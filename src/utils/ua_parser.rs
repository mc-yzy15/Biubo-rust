use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UaInfo {
    pub browser: String,
    pub os: String,
    pub device: String,
}

pub fn parse_user_agent(ua: &str) -> UaInfo {
    let mut result = UaInfo {
        browser: "Unknown".to_string(),
        os: "Unknown".to_string(),
        device: "PC".to_string(),
    };

    if ua.is_empty() {
        return result;
    }

    let ua_lower = ua.to_lowercase();

    if ua_lower.contains("edg/") {
        result.browser = "Edge".to_string();
    } else if ua_lower.contains("chrome/") {
        result.browser = "Chrome".to_string();
    } else if ua_lower.contains("firefox/") {
        result.browser = "Firefox".to_string();
    } else if ua_lower.contains("safari/") {
        result.browser = "Safari".to_string();
    } else if ua_lower.contains("msie") || ua_lower.contains("trident") {
        result.browser = "IE".to_string();
    }

    if ua_lower.contains("windows") {
        result.os = "Windows".to_string();
    } else if ua_lower.contains("mac os") {
        result.os = "MacOS".to_string();
    } else if ua_lower.contains("linux") {
        result.os = "Linux".to_string();
    } else if ua_lower.contains("android") {
        result.os = "Android".to_string();
        result.device = "Mobile".to_string();
    } else if ua_lower.contains("iphone") || ua_lower.contains("ipad") {
        result.os = "iOS".to_string();
        result.device = "Mobile".to_string();
    }

    result
}
