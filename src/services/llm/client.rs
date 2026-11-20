use crate::config::settings::Settings;

static HTTP_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .connect_timeout(std::time::Duration::from_secs(5))
        .pool_max_idle_per_host(64)
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .build()
        .expect("Failed to build LLM service HTTP client")
});

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedLlmConfig {
    model: String,
    base_url: String,
    api_key: String,
}

pub async fn llm_call(
    question: &str,
    thinking: bool,
    model: Option<&str>,
    settings: &Settings,
) -> String {
    let resolved = match resolve_llm_config(model, settings) {
        Some(config) => config,
        None => {
            tracing::warn!("LLM call skipped: No LLM API key configured.");
            return String::new();
        }
    };

    let mut body = serde_json::json!({
        "model": resolved.model,
        "messages": [{"role": "user", "content": question}],
        "stream": true,
    });

    if thinking {
        body["enable_thinking"] = serde_json::json!(true);
    }

    let response = match HTTP_CLIENT
        .post(format!(
            "{}/chat/completions",
            resolved.base_url.trim_end_matches('/')
        ))
        .header("Authorization", format!("Bearer {}", resolved.api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("LLM call failed: {}", e);
            return String::new();
        }
    };

    let full_text = match response.text().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("LLM response read failed: {}", e);
            return String::new();
        }
    };

    let mut answer = String::new();
    for line in full_text.lines() {
        let line = line.trim();
        if !line.starts_with("data: ") {
            continue;
        }
        let data = &line[6..];
        if data == "[DONE]" {
            break;
        }

        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data) {
            if let Some(content) = parsed
                .get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("delta"))
                .and_then(|d| d.get("content"))
                .and_then(|v| v.as_str())
            {
                answer.push_str(content);
            }
        }
    }

    answer
}

fn resolve_llm_config(model: Option<&str>, settings: &Settings) -> Option<ResolvedLlmConfig> {
    let requested_model = model.unwrap_or(&settings.llm_model);

    if !settings.llm_deep_api_key.is_empty() && requested_model == settings.llm_deep_model {
        let resolved_model = if requested_model.is_empty() {
            settings.llm_deep_model.clone()
        } else {
            requested_model.to_string()
        };
        let base_url = if settings.llm_deep_base_url.is_empty() {
            settings.llm_base_url.clone()
        } else {
            settings.llm_deep_base_url.clone()
        };

        return Some(ResolvedLlmConfig {
            model: resolved_model,
            base_url,
            api_key: settings.llm_deep_api_key.clone(),
        });
    }

    if !settings.llm_quick_api_key.is_empty() {
        let resolved_model = if let Some(explicit_model) = model {
            explicit_model.to_string()
        } else if !settings.llm_quick_model.is_empty() {
            settings.llm_quick_model.clone()
        } else {
            settings.llm_model.clone()
        };
        let base_url = if settings.llm_quick_base_url.is_empty() {
            settings.llm_base_url.clone()
        } else {
            settings.llm_quick_base_url.clone()
        };

        return Some(ResolvedLlmConfig {
            model: resolved_model,
            base_url,
            api_key: settings.llm_quick_api_key.clone(),
        });
    }

    if !settings.api_key.is_empty() {
        return Some(ResolvedLlmConfig {
            model: requested_model.to_string(),
            base_url: settings.llm_base_url.clone(),
            api_key: settings.api_key.clone(),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_llm_config_prefers_quick_profile() {
        let mut settings = Settings::default();
        settings.api_key = "legacy-key".to_string();
        settings.llm_model = "generic-model".to_string();
        settings.llm_base_url = "https://generic".to_string();
        settings.llm_quick_model = "quick-model".to_string();
        settings.llm_quick_base_url = "https://quick".to_string();
        settings.llm_quick_api_key = "quick-key".to_string();

        let resolved = resolve_llm_config(None, &settings).unwrap();
        assert_eq!(
            resolved,
            ResolvedLlmConfig {
                model: "quick-model".to_string(),
                base_url: "https://quick".to_string(),
                api_key: "quick-key".to_string(),
            }
        );
    }

    #[test]
    fn test_resolve_llm_config_uses_deep_profile_for_deep_model() {
        let mut settings = Settings::default();
        settings.llm_model = "generic-model".to_string();
        settings.llm_base_url = "https://generic".to_string();
        settings.llm_quick_api_key = "quick-key".to_string();
        settings.llm_quick_model = "quick-model".to_string();
        settings.llm_deep_model = "deep-model".to_string();
        settings.llm_deep_base_url = "https://deep".to_string();
        settings.llm_deep_api_key = "deep-key".to_string();

        let resolved = resolve_llm_config(Some("deep-model"), &settings).unwrap();
        assert_eq!(
            resolved,
            ResolvedLlmConfig {
                model: "deep-model".to_string(),
                base_url: "https://deep".to_string(),
                api_key: "deep-key".to_string(),
            }
        );
    }

    #[test]
    fn test_resolve_llm_config_falls_back_to_legacy_key() {
        let mut settings = Settings::default();
        settings.llm_model = "generic-model".to_string();
        settings.llm_base_url = "https://generic".to_string();
        settings.api_key = "legacy-key".to_string();

        let resolved = resolve_llm_config(None, &settings).unwrap();
        assert_eq!(
            resolved,
            ResolvedLlmConfig {
                model: "generic-model".to_string(),
                base_url: "https://generic".to_string(),
                api_key: "legacy-key".to_string(),
            }
        );
    }
}
