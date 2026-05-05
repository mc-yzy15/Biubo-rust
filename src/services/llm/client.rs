use crate::config::settings::Settings;

pub async fn llm_call(
    question: &str,
    thinking: bool,
    model: Option<&str>,
    settings: &Settings,
) -> String {
    if settings.api_key.is_empty() {
        tracing::warn!("LLM call skipped: No API_KEY configured.");
        return String::new();
    }

    let model = model.unwrap_or(&settings.llm_model);

    let mut body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": question}],
        "stream": true,
    });

    if thinking {
        body["enable_thinking"] = serde_json::json!(true);
    }

    let client = reqwest::Client::new();

    let response = match client
        .post(format!(
            "{}/chat/completions",
            settings.llm_base_url.trim_end_matches('/')
        ))
        .header("Authorization", format!("Bearer {}", settings.api_key))
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
