use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;

static ENCODED_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"%[0-9a-fA-F]{2}").expect("valid regex"),
        Regex::new(r"\\x[0-9a-fA-F]{2}").expect("valid regex"),
        Regex::new(r"\\u[0-9a-fA-F]{4}").expect("valid regex"),
        Regex::new(r"&#x?[0-9a-fA-F]+;").expect("valid regex"),
        Regex::new(r"base64[,\s]+[A-Za-z0-9+/=]{16,}").expect("valid regex"),
        Regex::new(r"\\[r\n\t]{2,}").expect("valid regex"),
    ]
});

static ATTACK_PAYLOAD_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)(union\s+(all\s+)?select|or\s+1\s*=\s*1|'\s*or\s*')").expect("valid regex"),
        Regex::new(r"(?i)(<script|javascript\s*:|on\w+\s*=)").expect("valid regex"),
        Regex::new(r"(?i)(\.\./|\.\.\\|etc/passwd|etc/shadow)").expect("valid regex"),
        Regex::new(r"(?i)(system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\()").expect("valid regex"),
        Regex::new(r"(?i)(\$\{jndi:|<%|<\?php|<?xml)").expect("valid regex"),
        Regex::new(r"(?i)(sqlmap|nikto|nmap|burp|dirbuster|gobuster|nuclei|wfuzz|hydra)").expect("valid regex"),
    ]
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSignals {
    pub has_encoded_payload: bool,
    pub encoded_content_ratio: f64,
    pub has_attack_progression: bool,
    pub behavior_score: f64,
    pub reputation_score: f64,
    pub attack_progression_score: f64,
}

impl ThreatSignals {
    pub fn none() -> Self {
        Self {
            has_encoded_payload: false,
            encoded_content_ratio: 0.0,
            has_attack_progression: false,
            behavior_score: 0.0,
            reputation_score: 0.0,
            attack_progression_score: 0.0,
        }
    }

    pub fn has_any_signal(&self) -> bool {
        self.has_encoded_payload
            || self.has_attack_progression
            || self.behavior_score > 0.0
            || self.reputation_score > 0.0
            || self.attack_progression_score > 0.0
    }

    pub fn combined_threat_score(&self) -> f64 {
        let encoded_weight = if self.has_encoded_payload { 0.25 } else { 0.0 };
        let progression_weight = if self.has_attack_progression { 0.25 } else { 0.0 };
        let behavior_component = self.behavior_score * 0.2;
        let reputation_component = self.reputation_score * 0.15;
        let progression_component = self.attack_progression_score * 0.15;

        (encoded_weight + progression_weight + behavior_component + reputation_component + progression_component).min(1.0)
    }
}

pub fn has_encoded_payload(request_body: &str) -> bool {
    if request_body.is_empty() {
        return false;
    }

    let encoded_matches: usize = ENCODED_PATTERNS
        .iter()
        .map(|re| re.find_iter(request_body).count())
        .sum();

    encoded_matches > 0 && (encoded_matches as f64 / request_body.len().max(1) as f64) > 0.01
}

pub fn compute_encoded_content_ratio(request_body: &str) -> f64 {
    if request_body.is_empty() {
        return 0.0;
    }

    let total_encoded: usize = ENCODED_PATTERNS
        .iter()
        .map(|re| re.find_iter(request_body).count())
        .sum();

    (total_encoded as f64 / request_body.len().max(1) as f64).min(1.0)
}

pub struct RequestRecord {
    pub timestamp: u64,
    pub url: String,
    pub method: String,
    pub status_code: u16,
    pub is_suspicious: bool,
}

pub fn has_attack_progression(ip_history: &[RequestRecord]) -> bool {
    if ip_history.len() < 3 {
        return false;
    }

    let recent: Vec<&RequestRecord> = ip_history.iter().rev().take(10).collect();
    
    let suspicious_count = recent.iter().filter(|r| r.is_suspicious).count();
    if suspicious_count >= 3 {
        return true;
    }

    let path_enumeration_detected = detect_path_enumeration(&recent);
    if path_enumeration_detected {
        return true;
    }

    let status_pattern_detected = detect_suspicious_status_pattern(&recent);
    if status_pattern_detected {
        return true;
    }

    false
}

fn detect_path_enumeration(records: &[&RequestRecord]) -> bool {
    if records.len() < 5 {
        return false;
    }

    let paths: Vec<&str> = records.iter().map(|r| r.url.as_str()).collect();
    
    let mut sequential_count = 0;
    for i in 1..paths.len().min(10) {
        let current = paths[i];
        let previous = paths[i - 1];
        
        let similarity = compute_path_similarity(previous, current);
        if similarity > 0.7 {
            sequential_count += 1;
        }
    }

    sequential_count >= 3
}

fn compute_path_similarity(path1: &str, path2: &str) -> f64 {
    let parts1: Vec<&str> = path1.split('/').collect();
    let parts2: Vec<&str> = path2.split('/').collect();
    
    let max_len = parts1.len().max(parts2.len());
    if max_len == 0 {
        return 1.0;
    }

    let mut matching = 0;
    for (p1, p2) in parts1.iter().zip(parts2.iter()) {
        if p1 == p2 {
            matching += 1;
        }
    }

    matching as f64 / max_len as f64
}

fn detect_suspicious_status_pattern(records: &[&RequestRecord]) -> bool {
    let error_count = records.iter().filter(|r| r.status_code >= 400).count();
    let not_found_count = records.iter().filter(|r| r.status_code == 404).count();
    
    let total = records.len();
    if total == 0 {
        return false;
    }

    let error_ratio = error_count as f64 / total as f64;
    error_ratio > 0.5 || not_found_count >= 5
}

pub fn compute_threat_signals(
    request_body: &str,
    reputation_score: f64,
    ip_history: &[RequestRecord],
    headers: &HashMap<String, String>,
) -> ThreatSignals {
    let has_encoded = has_encoded_payload(request_body);
    let encoded_ratio = compute_encoded_content_ratio(request_body);
    let has_progression = has_attack_progression(ip_history);

    let behavior_score = compute_behavior_score(headers, request_body);
    let progression_score = compute_attack_progression_score(ip_history);

    ThreatSignals {
        has_encoded_payload: has_encoded,
        encoded_content_ratio: encoded_ratio,
        has_attack_progression: has_progression,
        behavior_score,
        reputation_score,
        attack_progression_score: progression_score,
    }
}

fn compute_behavior_score(headers: &HashMap<String, String>, body: &str) -> f64 {
    let mut score = 0.0;

    let has_ua = headers.contains_key("user-agent");
    let has_accept = headers.contains_key("accept");
    let has_accept_lang = headers.contains_key("accept-language");
    let has_referer = headers.contains_key("referer");

    if !has_ua {
        score += 0.3;
    }
    if !has_accept && !has_accept_lang {
        score += 0.2;
    }
    if !has_referer && !body.is_empty() {
        score += 0.1;
    }

    if let Some(ua) = headers.get("user-agent") {
        if is_suspicious_ua(ua) {
            score += 0.4;
        }
    }

    score.min(1.0)
}

fn is_suspicious_ua(ua: &str) -> bool {
    let suspicious_patterns = [
        "sqlmap", "nikto", "nmap", "burp", "dirbuster", 
        "gobuster", "nuclei", "wfuzz", "hydra", "curl/",
        "python-requests", "python-urllib", "go-http-client",
    ];

    suspicious_patterns.iter().any(|p| ua.to_lowercase().contains(p))
}

fn compute_attack_progression_score(ip_history: &[RequestRecord]) -> f64 {
    if ip_history.is_empty() {
        return 0.0;
    }

    let recent: Vec<&RequestRecord> = ip_history.iter().rev().take(10).collect();
    let suspicious_count = recent.iter().filter(|r| r.is_suspicious).count();
    let suspicious_ratio = suspicious_count as f64 / recent.len().max(1) as f64;

    let error_count = recent.iter().filter(|r| r.status_code >= 400).count();
    let error_ratio = error_count as f64 / recent.len().max(1) as f64;

    (suspicious_ratio * 0.6 + error_ratio * 0.4).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_encoded_payload_with_url_encoding() {
        assert!(has_encoded_payload("test%20encoded%2Fpath"));
    }

    #[test]
    fn test_has_encoded_payload_with_hex_encoding() {
        assert!(has_encoded_payload("test\\x41\\x42"));
    }

    #[test]
    fn test_has_encoded_payload_with_unicode() {
        assert!(has_encoded_payload("test\\u0041\\u0042"));
    }

    #[test]
    fn test_has_encoded_payload_with_html_entity() {
        assert!(has_encoded_payload("test&#60;script&#62;"));
    }

    #[test]
    fn test_has_encoded_payload_with_base64() {
        assert!(has_encoded_payload("base64,SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBsb25nIHN0cmluZw=="));
    }

    #[test]
    fn test_no_encoded_payload() {
        assert!(!has_encoded_payload("Hello World"));
        assert!(!has_encoded_payload(""));
    }

    #[test]
    fn test_has_attack_progression_with_suspicious_requests() {
        let history = vec![
            RequestRecord { timestamp: 1, url: "/admin".to_string(), method: "GET".to_string(), status_code: 403, is_suspicious: true },
            RequestRecord { timestamp: 2, url: "/admin/config".to_string(), method: "GET".to_string(), status_code: 403, is_suspicious: true },
            RequestRecord { timestamp: 3, url: "/admin/users".to_string(), method: "GET".to_string(), status_code: 403, is_suspicious: true },
        ];
        assert!(has_attack_progression(&history));
    }

    #[test]
    fn test_no_attack_progression_with_normal_requests() {
        let history = vec![
            RequestRecord { timestamp: 1, url: "/index.html".to_string(), method: "GET".to_string(), status_code: 200, is_suspicious: false },
            RequestRecord { timestamp: 2, url: "/about".to_string(), method: "GET".to_string(), status_code: 200, is_suspicious: false },
            RequestRecord { timestamp: 3, url: "/contact".to_string(), method: "GET".to_string(), status_code: 200, is_suspicious: false },
        ];
        assert!(!has_attack_progression(&history));
    }

    #[test]
    fn test_threat_signals_combined_score() {
        let signals = ThreatSignals {
            has_encoded_payload: true,
            encoded_content_ratio: 0.15,
            has_attack_progression: true,
            behavior_score: 0.7,
            reputation_score: 0.8,
            attack_progression_score: 0.6,
        };

        let score = signals.combined_threat_score();
        assert!(score > 0.0);
        assert!(score <= 1.0);
    }

    #[test]
    fn test_threat_signals_none() {
        let signals = ThreatSignals::none();
        assert!(!signals.has_any_signal());
        assert_eq!(signals.combined_threat_score(), 0.0);
    }

    #[test]
    fn test_compute_behavior_score_missing_headers() {
        let headers = HashMap::new();
        let score = compute_behavior_score(&headers, "");
        assert!(score > 0.0);
    }

    #[test]
    fn test_compute_behavior_score_with_suspicious_ua() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "sqlmap/1.5".to_string());
        headers.insert("accept".to_string(), "*/*".to_string());
        headers.insert("accept-language".to_string(), "en".to_string());
        headers.insert("referer".to_string(), "http://example.com".to_string());
        
        let score = compute_behavior_score(&headers, "");
        assert!(score > 0.3);
    }
}
