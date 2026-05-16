#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Duration;

const TIER1_TIMEOUT_SECS: u64 = 3;
const TIER2_TIMEOUT_SECS: u64 = 10;

static JSON_BLOCK_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"```(?:json)?\s*(\{.*?\})\s*```").unwrap()
});

static JSON_OBJECT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\{.*?\}").unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub quick_model: String,
    pub quick_base_url: String,
    pub quick_api_key: String,
    pub deep_model: String,
    pub deep_base_url: String,
    pub deep_api_key: String,
}

impl LlmConfig {
    pub fn new(
        quick_model: String,
        quick_base_url: String,
        quick_api_key: String,
        deep_model: String,
        deep_base_url: String,
        deep_api_key: String,
    ) -> Self {
        LlmConfig {
            quick_model,
            quick_base_url,
            quick_api_key,
            deep_model,
            deep_base_url,
            deep_api_key,
        }
    }

    pub fn from_settings(settings: &crate::config::settings::Settings) -> Self {
        LlmConfig {
            quick_model: settings.llm_quick_model.clone(),
            quick_base_url: settings.llm_quick_base_url.clone(),
            quick_api_key: settings.llm_quick_api_key.clone(),
            deep_model: settings.llm_deep_model.clone(),
            deep_base_url: settings.llm_deep_base_url.clone(),
            deep_api_key: settings.llm_deep_api_key.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier1Verdict {
    pub verdict: String,
    pub confidence: f64,
}

impl Tier1Verdict {
    pub fn new(verdict: String, confidence: f64) -> Self {
        Tier1Verdict { verdict, confidence }
    }

    pub fn is_safe(&self) -> bool {
        self.verdict == "safe"
    }

    pub fn is_suspicious(&self) -> bool {
        self.verdict == "suspicious"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroDayContext {
    pub tier1_verdict: Tier1Verdict,
    pub tier1_confidence: f64,
    pub request_url: String,
    pub request_method: String,
    pub request_headers: HashMap<String, String>,
    pub request_body: String,
    pub behavior_score: f64,
    pub behavior_factors: Vec<String>,
    pub reputation_score: f64,
    pub provider_details: String,
    pub recent_history: String,
    pub rule_check_results: String,
}

impl ZeroDayContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tier1_verdict: Tier1Verdict,
        tier1_confidence: f64,
        request_url: String,
        request_method: String,
        request_headers: HashMap<String, String>,
        request_body: String,
        behavior_score: f64,
        behavior_factors: Vec<String>,
        reputation_score: f64,
        provider_details: String,
        recent_history: String,
        rule_check_results: String,
    ) -> Self {
        ZeroDayContext {
            tier1_verdict,
            tier1_confidence,
            request_url,
            request_method,
            request_headers,
            request_body,
            behavior_score,
            behavior_factors,
            reputation_score,
            provider_details,
            recent_history,
            rule_check_results,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier2Result {
    #[serde(rename = "type")]
    pub result_type: String,
    pub attack_types: Vec<String>,
    pub analysis: String,
}

impl Tier2Result {
    pub fn is_hacker(&self) -> bool {
        self.result_type == "hacker"
    }

    pub fn is_normal(&self) -> bool {
        self.result_type == "normal"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LlmResult {
    Safe,
    Suspicious(Tier2Result),
    Error(String),
}

pub struct Tier1QuickEval {
    pub config: LlmConfig,
}

impl Tier1QuickEval {
    pub fn new(config: LlmConfig) -> Self {
        Tier1QuickEval { config }
    }

    pub async fn evaluate(
        &self,
        url: &str,
        method: &str,
        payload_snippet: &str,
        behavior_score: f64,
        reputation_score: f64,
    ) -> Result<Tier1Verdict, String> {
        let prompt = self.build_tier1_prompt(url, method, payload_snippet, behavior_score, reputation_score);

        let response = self.call_llm(&prompt, &self.config.quick_model, &self.config.quick_base_url, &self.config.quick_api_key, TIER1_TIMEOUT_SECS).await?;

        self.parse_tier1_response(&response)
    }

    fn build_tier1_prompt(&self, url: &str, method: &str, payload_snippet: &str, behavior_score: f64, reputation_score: f64) -> String {
        format!(
            "You are a security triage assistant. Given this HTTP request and threat signals, quickly determine if it warrants deeper analysis.\n\n\
            Request: {method} {url}\n\
            Behavior Score: {behavior_score}/100\n\
            IP Reputation: {reputation_score}/100\n\
            Suspicious Content: {payload_snippet}\n\n\
            Respond ONLY with JSON: {{\"verdict\": \"safe\"|\"suspicious\", \"confidence\": 0.0-1.0}}",
            method = method,
            url = url,
            behavior_score = behavior_score,
            reputation_score = reputation_score,
            payload_snippet = payload_snippet,
        )
    }

    async fn call_llm(
        &self,
        prompt: &str,
        model: &str,
        base_url: &str,
        api_key: &str,
        timeout_secs: u64,
    ) -> Result<String, String> {
        if api_key.is_empty() {
            return Err("API key is empty".to_string());
        }

        let body = serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": false,
        });

        let client = reqwest::Client::new();

        let result = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            client
                .post(format!("{}/chat/completions", base_url.trim_end_matches('/')))
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send(),
        )
        .await;

        match result {
            Ok(Ok(response)) => {
                let response_text = response.text().await.map_err(|e| format!("Failed to read response: {}", e))?;
                self.extract_llm_response(&response_text)
            }
            Ok(Err(e)) => Err(format!("HTTP request failed: {}", e)),
            Err(_) => Err(format!("LLM call timed out after {} seconds", timeout_secs)),
        }
    }

    fn extract_llm_response(&self, response_text: &str) -> Result<String, String> {
        let json: serde_json::Value = serde_json::from_str(response_text).map_err(|e| format!("Failed to parse LLM response: {}", e))?;

        json.get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "No content in LLM response".to_string())
    }

    fn parse_tier1_response(&self, response: &str) -> Result<Tier1Verdict, String> {
        let cleaned = self.extract_json_from_response(response);

        let parsed: serde_json::Value = serde_json::from_str(&cleaned).map_err(|e| {
            format!("Failed to parse Tier 1 response JSON: {}. Response: {}", e, response)
        })?;

        let verdict = parsed.get("verdict")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'verdict' field in Tier 1 response".to_string())?
            .to_string();

        let confidence = parsed.get("confidence")
            .and_then(|v| v.as_f64())
            .ok_or_else(|| "Missing 'confidence' field in Tier 1 response".to_string())?;

        let confidence = confidence.clamp(0.0, 1.0);

        Ok(Tier1Verdict::new(verdict, confidence))
    }

    fn extract_json_from_response(&self, response: &str) -> String {
        if serde_json::from_str::<serde_json::Value>(response.trim()).is_ok() {
            return response.trim().to_string();
        }

        if let Some(captures) = JSON_BLOCK_RE.captures(response) {
            if let Some(m) = captures.get(1) {
                return m.as_str().to_string();
            }
        }

        if let Some(captures) = JSON_OBJECT_RE.captures(response) {
            if let Some(m) = captures.get(0) {
                return m.as_str().to_string();
            }
        }

        response.trim().to_string()
    }
}

pub struct Tier2DeepAnalysis {
    pub config: LlmConfig,
}

impl Tier2DeepAnalysis {
    pub fn new(config: LlmConfig) -> Self {
        Tier2DeepAnalysis { config }
    }

    pub async fn analyze(&self, context: &ZeroDayContext) -> Result<Tier2Result, String> {
        let prompt = self.build_tier2_prompt(context);

        let response = self.call_llm(&prompt, &self.config.deep_model, &self.config.deep_base_url, &self.config.deep_api_key, TIER2_TIMEOUT_SECS).await?;

        self.parse_tier2_response(&response)
    }

    fn build_tier2_prompt(&self, context: &ZeroDayContext) -> String {
        let headers_str = serde_json::to_string(&context.request_headers).unwrap_or_default();
        let behavior_factors_str = context.behavior_factors.join(", ");

        format!(
            "You are an expert HTTP security analysis engine. Your job: distinguish real attacks from normal user behavior, including zero-day and novel attack patterns.\n\n\
            ## Context\n\
            - Tier 1 quick evaluation verdict: {tier1_verdict} (confidence: {tier1_confidence})\n\
            - WAF rule check: No known patterns matched\n\
            - Behavior score: {behavior_score}/100 (factors: {behavior_factors})\n\
            - IP reputation: {reputation_score}/100 (providers: {provider_details})\n\
            - Request history: {recent_history}\n\n\
            ## Current Request\n\
            - URL: {url}\n\
            - Method: {method}\n\
            - Headers: {headers}\n\
            - Body: {body}\n\n\
            ## Analysis\n\
            Determine if this is a zero-day or novel attack.\n\n\
            Output JSON only:\n\
            - {{\"type\": \"normal\"}} - if genuinely benign\n\
            - {{\"type\": \"hacker\", \"attack_types\": [\"zero_day_suspected\", ...], \"analysis\": \"brief explanation\"}}",
            tier1_verdict = context.tier1_verdict.verdict,
            tier1_confidence = context.tier1_confidence,
            behavior_score = context.behavior_score,
            behavior_factors = behavior_factors_str,
            reputation_score = context.reputation_score,
            provider_details = context.provider_details,
            recent_history = context.recent_history,
            url = context.request_url,
            method = context.request_method,
            headers = headers_str,
            body = context.request_body,
        )
    }

    async fn call_llm(
        &self,
        prompt: &str,
        model: &str,
        base_url: &str,
        api_key: &str,
        timeout_secs: u64,
    ) -> Result<String, String> {
        if api_key.is_empty() {
            return Err("API key is empty".to_string());
        }

        let body = serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": false,
        });

        let client = reqwest::Client::new();

        let result = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            client
                .post(format!("{}/chat/completions", base_url.trim_end_matches('/')))
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send(),
        )
        .await;

        match result {
            Ok(Ok(response)) => {
                let response_text = response.text().await.map_err(|e| format!("Failed to read response: {}", e))?;
                self.extract_llm_response(&response_text)
            }
            Ok(Err(e)) => Err(format!("HTTP request failed: {}", e)),
            Err(_) => Err(format!("LLM call timed out after {} seconds", timeout_secs)),
        }
    }

    fn extract_llm_response(&self, response_text: &str) -> Result<String, String> {
        let json: serde_json::Value = serde_json::from_str(response_text).map_err(|e| format!("Failed to parse LLM response: {}", e))?;

        json.get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "No content in LLM response".to_string())
    }

    fn parse_tier2_response(&self, response: &str) -> Result<Tier2Result, String> {
        let cleaned = self.extract_json_from_response(response);

        let parsed: serde_json::Value = serde_json::from_str(&cleaned).map_err(|e| {
            format!("Failed to parse Tier 2 response JSON: {}. Response: {}", e, response)
        })?;

        let result_type = parsed.get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'type' field in Tier 2 response".to_string())?
            .to_string();

        let attack_types = parsed.get("attack_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let analysis = parsed.get("analysis")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(Tier2Result {
            result_type,
            attack_types,
            analysis,
        })
    }

    fn extract_json_from_response(&self, response: &str) -> String {
        if serde_json::from_str::<serde_json::Value>(response.trim()).is_ok() {
            return response.trim().to_string();
        }

        if let Some(captures) = JSON_BLOCK_RE.captures(response) {
            if let Some(m) = captures.get(1) {
                return m.as_str().to_string();
            }
        }

        if let Some(captures) = JSON_OBJECT_RE.captures(response) {
            if let Some(m) = captures.get(0) {
                return m.as_str().to_string();
            }
        }

        response.trim().to_string()
    }
}

pub struct TwoTierLlmPipeline {
    pub quick_eval: Tier1QuickEval,
    pub deep_analysis: Tier2DeepAnalysis,
}

impl TwoTierLlmPipeline {
    pub fn new(config: LlmConfig) -> Self {
        let config_clone_1 = config.clone();
        let config_clone_2 = config.clone();

        TwoTierLlmPipeline {
            quick_eval: Tier1QuickEval::new(config_clone_1),
            deep_analysis: Tier2DeepAnalysis::new(config_clone_2),
        }
    }

    pub async fn run(
        &self,
        url: &str,
        method: &str,
        payload_snippet: &str,
        behavior_score: f64,
        reputation_score: f64,
        full_context: Option<ZeroDayContext>,
    ) -> LlmResult {
        let tier1_result = self.quick_eval.evaluate(url, method, payload_snippet, behavior_score, reputation_score).await;

        match tier1_result {
            Ok(verdict) => {
                if verdict.is_safe() {
                    return LlmResult::Safe;
                }

                if let Some(context) = full_context {
                    let tier2_result = self.deep_analysis.analyze(&context).await;

                    match tier2_result {
                        Ok(result) => LlmResult::Suspicious(result),
                        Err(e) => LlmResult::Error(format!("Tier 2 analysis failed: {}", e)),
                    }
                } else {
                    LlmResult::Error("Full context required for Tier 2 analysis".to_string())
                }
            }
            Err(e) => LlmResult::Error(format!("Tier 1 evaluation failed: {}", e)),
        }
    }
}

pub struct LlmTriggerConditionChecker;

impl LlmTriggerConditionChecker {
    pub fn should_invoke_llm(
        rule_matched: bool,
        behavior_score: f64,
        reputation_score: f64,
        has_encoded_payload: bool,
        has_attack_progression: bool,
    ) -> bool {
        !rule_matched && (
            behavior_score >= 40.0 ||
            reputation_score >= 40.0 ||
            has_encoded_payload ||
            has_attack_progression
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trigger_condition_rule_matched_returns_false() {
        assert!(!LlmTriggerConditionChecker::should_invoke_llm(true, 50.0, 50.0, false, false));
        assert!(!LlmTriggerConditionChecker::should_invoke_llm(true, 100.0, 100.0, true, true));
    }

    #[test]
    fn test_trigger_condition_behavior_score_high() {
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 40.0, 0.0, false, false));
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 50.0, 0.0, false, false));
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 100.0, 0.0, false, false));
    }

    #[test]
    fn test_trigger_condition_reputation_score_high() {
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 0.0, 40.0, false, false));
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 0.0, 50.0, false, false));
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 0.0, 100.0, false, false));
    }

    #[test]
    fn test_trigger_condition_encoded_payload() {
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 0.0, 0.0, true, false));
    }

    #[test]
    fn test_trigger_condition_attack_progression() {
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 0.0, 0.0, false, true));
    }

    #[test]
    fn test_trigger_condition_all_false_returns_false() {
        assert!(!LlmTriggerConditionChecker::should_invoke_llm(false, 0.0, 0.0, false, false));
        assert!(!LlmTriggerConditionChecker::should_invoke_llm(false, 39.9, 39.9, false, false));
    }

    #[test]
    fn test_trigger_condition_combinations() {
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 50.0, 50.0, true, true));
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 40.0, 30.0, false, false));
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 30.0, 40.0, false, false));
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 10.0, 10.0, true, false));
        assert!(LlmTriggerConditionChecker::should_invoke_llm(false, 10.0, 10.0, false, true));
    }

    #[test]
    fn test_tier1_verdict_is_safe() {
        let verdict = Tier1Verdict::new("safe".to_string(), 0.9);
        assert!(verdict.is_safe());
        assert!(!verdict.is_suspicious());
    }

    #[test]
    fn test_tier1_verdict_is_suspicious() {
        let verdict = Tier1Verdict::new("suspicious".to_string(), 0.7);
        assert!(!verdict.is_safe());
        assert!(verdict.is_suspicious());
    }

    #[test]
    fn test_tier2_result_is_hacker() {
        let result = Tier2Result {
            result_type: "hacker".to_string(),
            attack_types: vec!["zero_day_suspected".to_string()],
            analysis: "test".to_string(),
        };
        assert!(result.is_hacker());
        assert!(!result.is_normal());
    }

    #[test]
    fn test_tier2_result_is_normal() {
        let result = Tier2Result {
            result_type: "normal".to_string(),
            attack_types: vec![],
            analysis: "test".to_string(),
        };
        assert!(!result.is_hacker());
        assert!(result.is_normal());
    }

    #[test]
    fn test_parse_tier1_response_valid_json() {
        let eval = Tier1QuickEval::new(LlmConfig::new(
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
        ));

        let response = r#"{"verdict": "suspicious", "confidence": 0.85}"#;
        let result = eval.parse_tier1_response(response).unwrap();

        assert_eq!(result.verdict, "suspicious");
        assert!((result.confidence - 0.85).abs() < 0.01);
    }

    #[test]
    fn test_parse_tier1_response_with_json_block() {
        let eval = Tier1QuickEval::new(LlmConfig::new(
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
        ));

        let response = r#"```json
{"verdict": "safe", "confidence": 0.92}
```"#;
        let result = eval.parse_tier1_response(response).unwrap();

        assert_eq!(result.verdict, "safe");
        assert!((result.confidence - 0.92).abs() < 0.01);
    }

    #[test]
    fn test_parse_tier1_response_confidence_clamped() {
        let eval = Tier1QuickEval::new(LlmConfig::new(
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
        ));

        let response = r#"{"verdict": "suspicious", "confidence": 1.5}"#;
        let result = eval.parse_tier1_response(response).unwrap();

        assert_eq!(result.confidence, 1.0);

        let response = r#"{"verdict": "suspicious", "confidence": -0.5}"#;
        let result = eval.parse_tier1_response(response).unwrap();

        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn test_parse_tier2_response_hacker() {
        let analysis = Tier2DeepAnalysis::new(LlmConfig::new(
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
        ));

        let response = r#"{"type": "hacker", "attack_types": ["zero_day_suspected", "novel_sqli"], "analysis": "This is a test"}"#;
        let result = analysis.parse_tier2_response(response).unwrap();

        assert_eq!(result.result_type, "hacker");
        assert_eq!(result.attack_types.len(), 2);
        assert_eq!(result.attack_types[0], "zero_day_suspected");
        assert_eq!(result.analysis, "This is a test");
    }

    #[test]
    fn test_parse_tier2_response_normal() {
        let analysis = Tier2DeepAnalysis::new(LlmConfig::new(
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
        ));

        let response = r#"{"type": "normal"}"#;
        let result = analysis.parse_tier2_response(response).unwrap();

        assert_eq!(result.result_type, "normal");
        assert!(result.attack_types.is_empty());
        assert_eq!(result.analysis, "");
    }

    #[test]
    fn test_parse_tier1_response_missing_fields() {
        let eval = Tier1QuickEval::new(LlmConfig::new(
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
            "test".to_string(),
            "http://test".to_string(),
            "".to_string(),
        ));

        let response = r#"{"verdict": "safe"}"#;
        assert!(eval.parse_tier1_response(response).is_err());

        let response = r#"{"confidence": 0.9}"#;
        assert!(eval.parse_tier1_response(response).is_err());
    }

    #[test]
    fn test_llm_config_from_settings() {
        let settings = crate::config::settings::Settings::default();
        let config = LlmConfig::from_settings(&settings);

        assert_eq!(config.quick_model, settings.llm_quick_model);
        assert_eq!(config.quick_base_url, settings.llm_quick_base_url);
        assert_eq!(config.quick_api_key, settings.llm_quick_api_key);
        assert_eq!(config.deep_model, settings.llm_deep_model);
        assert_eq!(config.deep_base_url, settings.llm_deep_base_url);
        assert_eq!(config.deep_api_key, settings.llm_deep_api_key);
    }

    #[test]
    fn test_zeroday_context_creation() {
        let verdict = Tier1Verdict::new("suspicious".to_string(), 0.8);
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let context = ZeroDayContext::new(
            verdict.clone(),
            0.8,
            "http://example.com/api".to_string(),
            "POST".to_string(),
            headers,
            "{\"test\": true}".to_string(),
            65.0,
            vec!["high_velocity".to_string()],
            70.0,
            "provider_x".to_string(),
            "recent_history".to_string(),
            "no_rules_matched".to_string(),
        );

        assert_eq!(context.tier1_verdict.verdict, "suspicious");
        assert!((context.tier1_confidence - 0.8).abs() < 0.01);
        assert_eq!(context.request_method, "POST");
        assert_eq!(context.behavior_score, 65.0);
        assert_eq!(context.behavior_factors.len(), 1);
    }
}
