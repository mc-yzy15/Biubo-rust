
use serde::{Deserialize, Serialize};
#[cfg(feature = "advanced-rules")]
use dashmap::DashMap;
#[cfg(feature = "advanced-rules")]
use regex::Regex;
#[cfg(feature = "advanced-rules")]
use std::collections::HashMap;
#[cfg(feature = "advanced-rules")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "advanced-rules")]
use std::sync::Arc;
#[cfg(feature = "advanced-rules")]
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Rule Data Model
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    Xss,
    SqlInjection,
    Rce,
    Lfi,
    Rfi,
    PathTraversal,
    Ssti,
    Xxe,
    CommandInjection,
    Scanner,
    Bot,
    HttpSmuggling,
    SessionFixation,
    Csrf,
    ApiAbuse,
    PhpAttack,
    JavaAttack,
    NodejsAttack,
    WordpressAttack,
    Deserialization,
    CveExploit,
    BotSignature,
    ProtocolValidation,
    MethodEnforcement,
    RequestAnomaly,
    Custom,
}

impl RuleCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleCategory::Xss => "xss",
            RuleCategory::SqlInjection => "sql_injection",
            RuleCategory::Rce => "rce",
            RuleCategory::Lfi => "lfi",
            RuleCategory::Rfi => "rfi",
            RuleCategory::PathTraversal => "path_traversal",
            RuleCategory::Ssti => "ssti",
            RuleCategory::Xxe => "xxe",
            RuleCategory::CommandInjection => "command_injection",
            RuleCategory::Scanner => "scanner",
            RuleCategory::Bot => "bot",
            RuleCategory::HttpSmuggling => "http_smuggling",
            RuleCategory::SessionFixation => "session_fixation",
            RuleCategory::Csrf => "csrf",
            RuleCategory::ApiAbuse => "api_abuse",
            RuleCategory::PhpAttack => "php_attack",
            RuleCategory::JavaAttack => "java_attack",
            RuleCategory::NodejsAttack => "nodejs_attack",
            RuleCategory::WordpressAttack => "wordpress_attack",
            RuleCategory::Deserialization => "deserialization",
            RuleCategory::CveExploit => "cve_exploit",
            RuleCategory::BotSignature => "bot_signature",
            RuleCategory::ProtocolValidation => "protocol_validation",
            RuleCategory::MethodEnforcement => "method_enforcement",
            RuleCategory::RequestAnomaly => "request_anomaly",
            RuleCategory::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: u64,
    pub category: RuleCategory,
    pub paranoia_level: u8,
    pub severity: String,
    pub description: String,
    pub pattern: String,
    #[serde(default)]
    pub mitre_id: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[cfg(feature = "advanced-rules")]
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule: Rule,
}

// ============================================================================
// CompiledCategory (internal)
// ============================================================================

#[cfg(feature = "advanced-rules")]
pub struct CompiledCategory {
    pub regex: Regex,
    pub rule_ids: Vec<u64>,
}

// ============================================================================
// RuleStatistics (internal)
// ============================================================================

#[cfg(feature = "advanced-rules")]
pub struct RuleStatistics {
    rule_hits: DashMap<u64, AtomicU64>,
    category_hits: DashMap<String, AtomicU64>,
    rule_last_hit: DashMap<u64, AtomicU64>,
}

#[cfg(feature = "advanced-rules")]
impl RuleStatistics {
    pub fn record_hit(&self, rule_id: u64, category: &str) {
        let rule_counter = self
            .rule_hits
            .entry(rule_id)
            .or_insert_with(|| AtomicU64::new(0));
        rule_counter.fetch_add(1, Ordering::Relaxed);

        let cat_counter = self
            .category_hits
            .entry(category.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        cat_counter.fetch_add(1, Ordering::Relaxed);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ts_counter = self
            .rule_last_hit
            .entry(rule_id)
            .or_insert_with(|| AtomicU64::new(0));
        ts_counter.store(now, Ordering::Relaxed);
    }
}

// ============================================================================
// RuleEngine
// ============================================================================

#[cfg(feature = "advanced-rules")]
pub struct WafRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: String,
    pub cookies: HashMap<String, String>,
}

#[cfg(feature = "advanced-rules")]
impl WafRequest {
    pub fn to_detection_string(&self) -> String {
        let mut parts = Vec::new();
        parts.push(self.url.to_lowercase());
        parts.push(self.method.to_lowercase());

        for (k, v) in &self.headers {
            parts.push(format!("{}={}", k.to_lowercase(), v.to_lowercase()));
        }

        for (k, v) in &self.query_params {
            parts.push(format!("{}={}", k.to_lowercase(), v.to_lowercase()));
        }

        parts.push(self.body.to_lowercase());

        for (k, v) in &self.cookies {
            parts.push(format!("{}={}", k.to_lowercase(), v.to_lowercase()));
        }

        parts.join(" ")
    }
}

#[cfg(feature = "advanced-rules")]
pub struct RuleEngine {
    rules: DashMap<u64, Rule>,
    compiled: DashMap<RuleCategory, CompiledCategory>,
    statistics: Arc<RuleStatistics>,
}

#[cfg(feature = "advanced-rules")]
impl RuleEngine {
    pub fn match_request(&self, request: &WafRequest) -> Vec<RuleMatch> {
        let detection_text = request.to_detection_string();
        let mut matches = Vec::new();

        for entry in self.compiled.iter() {
            let compiled = entry.value();

            if compiled.regex.is_match(&detection_text) {
                for rule_id in &compiled.rule_ids {
                    if let Some(rule_ref) = self.rules.get(rule_id) {
                        let rule = rule_ref.value().clone();
                        self.statistics.record_hit(rule.id, rule.category.as_str());
                        matches.push(RuleMatch {
                            rule,
                        });
                    }
                }
            }
        }

        matches
    }
}
