use crate::data::storage::manager::ProxyDB;
use crate::utils::ua_parser::parse_user_agent;

pub fn update_analytics(db: &ProxyDB, entry: &serde_json::Value) {
    let log = match entry.get("log") {
        Some(v) => v,
        None => return,
    };

    let ip = log.get("cdn_ip").and_then(|v| v.as_str()).unwrap_or("");
    let _fingerprint = log.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("");
    let is_hacker = log.get("type").and_then(|v| v.as_str()) == Some("hacker");
    let url = log.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let url = extract_path(url);
    let country = log
        .get("country")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let country = if country.is_empty() { "unknown" } else { country };
    let ua = log
        .get("headers")
        .and_then(|h| h.get("User-Agent"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let duration_sec = log
        .get("duration_sec")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let mut analytics = db
        .ram_get("analytics")
        .unwrap_or(serde_json::json!({}));
    let log_db = db.get_log_db();
    let mut overview = log_db
        .as_ref()
        .and_then(|ldb| ldb.get("overview"))
        .unwrap_or(serde_json::json!({}));

    fn inc(obj: &mut serde_json::Value, key: &str) {
        let current = obj.get(key).and_then(|v| v.as_u64()).unwrap_or(0);
        obj[key] = serde_json::json!(current + 1);
    }

    #[allow(dead_code)]
    fn inc_str(obj: &mut serde_json::Value, key: &str) {
        let current = obj.get(key).and_then(|v| v.as_u64()).unwrap_or(0);
        obj[key] = serde_json::json!(current + 1);
    }

    if is_hacker {
        if let Some(security) = analytics.get_mut("security") {
            let blocked = security.get("blocked_requests").and_then(|v| v.as_u64()).unwrap_or(0);
            security["blocked_requests"] = serde_json::json!(blocked + 1);

            if let Some(attack_types) = log.get("attack_types").and_then(|v| v.as_array()) {
                for at in attack_types {
                    if let Some(name) = at.as_str() {
                        inc(&mut security["attack_types"], name);
                    }
                }
            }

            inc(&mut security["top_attack_ips"], &ip);
            inc(&mut security["top_target_urls"], &url);

            if let Some(geo) = security.get_mut("geo") {
                inc(&mut geo["attackers_by_country"], &country);
            }
        }

        if let Some(security) = overview.get_mut("security") {
            let blocked = security.get("blocked_requests").and_then(|v| v.as_u64()).unwrap_or(0);
            security["blocked_requests"] = serde_json::json!(blocked + 1);

            if let Some(attack_types) = log.get("attack_types").and_then(|v| v.as_array()) {
                for at in attack_types {
                    if let Some(name) = at.as_str() {
                        inc(&mut security["attack_types"], name);
                    }
                }
            }

            inc(&mut security["top_attack_ips"], &ip);
            inc(&mut security["top_target_urls"], &url);

            if let Some(geo) = security.get_mut("geo") {
                inc(&mut geo["attackers_by_country"], &country);
            }
        }
    }

    if duration_sec != 0 {
        if let Some(traffic) = analytics.get_mut("traffic") {
            let visitors = traffic
                .get("visitors")
                .and_then(|v| v.get("total"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            traffic["visitors"]["total"] = serde_json::json!(visitors + 1);
        }

        if let Some(traffic) = analytics.get_mut("traffic") {
            if let Some(engagement) = traffic.get_mut("engagement") {
                let total = engagement.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
                engagement["total"] = serde_json::json!(total + 1);

                if duration_sec <= 15 {
                    let bounce = engagement
                        .get("bounce_rate")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    engagement["bounce_rate"] =
                        serde_json::json!((bounce * (total as f64) + 1.0) / (total as f64 + 1.0));
                }

                let avg = engagement
                    .get("avg_session_duration")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                engagement["avg_session_duration"] = serde_json::json!(
                    (avg * (total as f64) + duration_sec as f64) / (total as f64 + 1.0)
                );
            }

            inc(&mut traffic["trending_urls"], &url);

            let ua_info = parse_user_agent(ua);
            if let Some(clients) = traffic.get_mut("clients") {
                inc(&mut clients["browsers"], &ua_info.browser);
                inc(&mut clients["os"], &ua_info.os);
                inc(&mut clients["devices"], &ua_info.device);
            }
        }
    }

    db.ram_set("analytics", analytics);
    if let Some(ldb) = log_db {
        ldb.set("overview", overview);
    }
}

fn extract_path(url: &str) -> String {
    url::Url::parse(url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| url.to_string())
}
