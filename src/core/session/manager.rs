use std::collections::HashMap;
use std::time::Duration;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::config::settings::SharedSettings;
use crate::data::analytics::aggregator::update_analytics;
use crate::data::storage::base::Database;
use crate::data::storage::manager::get_db;
use crate::utils::compression::{compress_json, decompress_json};
use crate::utils::http_utils::get_ip_info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub request_id: String,
    #[serde(rename = "type")]
    pub log_type: String,
    pub attack_types: Vec<String>,
    pub time: String,
    pub ip: String,
    pub cdn_ip: String,
    pub country: String,
    pub city: String,
    pub fingerprint: String,
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub data: serde_json::Value,
    pub browser_info: serde_json::Value,
    pub rrweb: serde_json::Value,
    pub duration_sec: u64,
    pub status: u16,
}

struct Session {
    timestamp: std::time::Instant,
    host: String,
    log: LogEntry,
    dirty: bool,
}

static SESSIONS: once_cell::sync::Lazy<DashMap<String, Session>> =
    once_cell::sync::Lazy::new(DashMap::new);

const MAX_SESSIONS: usize = 100000;

pub fn build_log_entry(
    request_id: &str,
    snapshot: &HashMap<String, serde_json::Value>,
    detection: &crate::core::engine::waf_engine::DetectionResult,
    status_code: u16,
) -> LogEntry {
    LogEntry {
        request_id: request_id.to_string(),
        log_type: detection.detection_type.clone(),
        attack_types: detection.attack_types.clone(),
        time: chrono::Utc::now().to_rfc3339(),
        ip: snapshot
            .get("remote_addr")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        cdn_ip: snapshot
            .get("remote_addr")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        country: String::new(),
        city: String::new(),
        fingerprint: String::new(),
        method: snapshot
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        url: snapshot
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        headers: HashMap::new(),
        cookies: HashMap::new(),
        data: serde_json::json!({}),
        browser_info: serde_json::json!({}),
        rrweb: serde_json::json!([]),
        duration_sec: 0,
        status: status_code,
    }
}

pub fn create_session(request_id: &str, host: &str, log_entry: LogEntry) {
    if SESSIONS.len() >= MAX_SESSIONS {
        tracing::warn!("Session limit reached ({}), rejecting new session for {}", MAX_SESSIONS, request_id);
        return;
    }

    let session = Session {
        timestamp: std::time::Instant::now(),
        host: host.to_string(),
        log: log_entry,
        dirty: false,
    };

    flush_session(request_id, &session);
    SESSIONS.insert(request_id.to_string(), session);
}

pub fn update_session_log(
    request_id: &str,
    _host: &str,
    updates: HashMap<String, serde_json::Value>,
) {
    if let Some(mut session) = SESSIONS.get_mut(request_id) {
        for (key, value) in updates {
            match key.as_str() {
                "ip" => session.log.ip = value.as_str().unwrap_or("").to_string(),
                "cdn_ip" => session.log.cdn_ip = value.as_str().unwrap_or("").to_string(),
                "country" => session.log.country = value.as_str().unwrap_or("").to_string(),
                "city" => session.log.city = value.as_str().unwrap_or("").to_string(),
                "fingerprint" => session.log.fingerprint = value.as_str().unwrap_or("").to_string(),
                "browser_info" => session.log.browser_info = value,
                _ => {}
            }
        }
        session.timestamp = std::time::Instant::now();
        session.dirty = true;
    }
}

/// 处理 rrweb 事件数组，计算持续时间并压缩事件数据。
///
/// 返回 `(duration_sec, compressed_rrweb)`：
/// - 当 `events` 为空时，`duration_sec` 为 `None`，`compressed_rrweb` 为空字符串。
/// - 否则 `duration_sec` 为首末事件时间戳之差（秒），`compressed_rrweb` 为压缩后的字符串。
fn process_rrweb_events(events: &[serde_json::Value]) -> (Option<u64>, serde_json::Value) {
    if events.is_empty() {
        return (None, serde_json::json!(""));
    }

    let first_ts = events
        .first()
        .and_then(|v| v.get("timestamp"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let last_ts = events
        .last()
        .and_then(|e| e.get("timestamp"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let duration_sec = (last_ts - first_ts).abs() as u64 / 1000;
    let compressed_rrweb = serde_json::json!(String::from_utf8_lossy(&compress_json(
        &serde_json::json!({"events": events})
    ))
    .to_string());

    (Some(duration_sec), compressed_rrweb)
}

pub fn update_rrweb_events(request_id: &str, host: &str, events: Vec<serde_json::Value>) {
    if events.is_empty() {
        return;
    }

    if let Some(mut session) = SESSIONS.get_mut(request_id) {
        session.timestamp = std::time::Instant::now();
    }

    let db = get_db(host);
    let log_db = match db.get_log_db() {
        Some(ldb) => ldb,
        None => return,
    };

    let mut logs = log_db
        .get("logs")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    let target_idx = logs
        .iter()
        .position(|e| e.get("request_id").and_then(|v| v.as_str()) == Some(request_id));

    let target_idx = match target_idx {
        Some(i) => i,
        None => return,
    };

    let target_entry = &mut logs[target_idx];
    let mut existing_events = Vec::new();

    if let Some(rrweb_val) = target_entry.get("rrweb") {
        if let Some(rrweb_bytes) = rrweb_val.as_str() {
            let decoded = decompress_json(rrweb_bytes.as_bytes());
            if let Some(events_arr) = decoded.get("events").and_then(|v| v.as_array()) {
                existing_events = events_arr.clone();
            }
        } else if rrweb_val.is_object() {
            if let Some(events_arr) = rrweb_val.get("events").and_then(|v| v.as_array()) {
                existing_events = events_arr.clone();
            }
        }
    }

    existing_events.extend(events);

    let (duration_sec, compressed_rrweb) = process_rrweb_events(&existing_events);
    if let Some(dur) = duration_sec {
        target_entry["duration_sec"] = serde_json::json!(dur);
        target_entry["rrweb"] = compressed_rrweb;
    }

    log_db.set("logs", serde_json::json!(logs));
}

fn flush_session(sid: &str, session: &Session) {
    let log = session.log.clone();
    let mut log_value = match serde_json::to_value(&log) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                "[SessionManager] Failed to serialize log entry for {}: {}",
                sid,
                e
            );
            serde_json::json!({})
        }
    };

    if log.country.is_empty() {
        let cdn_ip = log.cdn_ip.clone();
        // Use tokio::spawn instead of std::thread::spawn to avoid creating a new
        // OS thread + Tokio runtime per session with missing geo data.
        tokio::spawn(async move {
            let info = get_ip_info(&cdn_ip).await;
            tracing::debug!("IP info fetched for {}: {:?}", cdn_ip, info);
        });
    }

    let db = get_db(&session.host);

    if let Some(log_db) = db.get_log_db() {
        let logs = log_db
            .get("logs")
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();

        let disk_rrweb = logs
            .iter()
            .find(|e| e.get("request_id").and_then(|v| v.as_str()) == Some(sid))
            .and_then(|e| e.get("rrweb").cloned());

        let disk_duration = logs
            .iter()
            .find(|e| e.get("request_id").and_then(|v| v.as_str()) == Some(sid))
            .and_then(|e| e.get("duration_sec").cloned());

        if let Some(rrweb) = disk_rrweb {
            log_value["rrweb"] = rrweb;
        } else {
            let rrweb_val = log_value
                .get("rrweb")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]));
            if let Some(arr) = rrweb_val.as_array() {
                let (duration_sec, compressed_rrweb) = process_rrweb_events(arr);
                if let Some(dur) = duration_sec {
                    log_value["duration_sec"] = serde_json::json!(dur);
                }
                log_value["rrweb"] = compressed_rrweb;
            } else {
                log_value["rrweb"] = serde_json::json!("");
            }
        }

        if let Some(dur) = disk_duration {
            log_value["duration_sec"] = dur;
        }
    }

    db.write_log_direct(log_value);
    tracing::debug!("Session flushed: {}", sid);
}

pub fn start_session_gc_worker(session_timeout: u64, gc_interval: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(gc_interval));
        let now = std::time::Instant::now();

        let expired: Vec<String> = SESSIONS
            .iter()
            .filter(|e| now.duration_since(e.value().timestamp).as_secs() > session_timeout)
            .map(|e| e.key().clone())
            .collect();

        for sid in expired {
            if let Some((_, session)) = SESSIONS.remove(&sid) {
                let db = get_db(&session.host);

                if let Some(log_db) = db.get_log_db() {
                    let logs = log_db
                        .get("logs")
                        .and_then(|v| v.as_array().cloned())
                        .unwrap_or_default();

                    if let Some(entry) = logs
                        .iter()
                        .find(|e| e.get("request_id").and_then(|v| v.as_str()) == Some(&sid))
                    {
                        let duration = entry.get("duration_sec").cloned();
                        let mut session_log =
                            serde_json::to_value(&session.log).unwrap_or(serde_json::json!({}));
                        if let Some(dur) = duration {
                            session_log["duration_sec"] = dur;
                        }

                        let session_val = serde_json::json!({
                            "log": session_log,
                        });
                        update_analytics(&db, &session_val);
                    }
                }

                if session.dirty {
                    flush_session(&sid, &session);
                }
            }
        }
    });
}

pub fn start_log_gc_worker(settings: SharedSettings) {
    let settings = settings.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(15));
        loop {
            if settings.read().log_auto_delete {
                let s = settings.read();
                let retain_rule = s.log_retain.clone();
                let retention_days = s.log_retention_days;
                let db_root = s.db_root.clone();

                drop(s);

                let retain_asts = if !retain_rule.is_empty() {
                    crate::utils::query_parser::parse(&retain_rule).ok()
                } else {
                    None
                };

                let cutoff_date = (chrono::Utc::now() - chrono::Duration::days(retention_days))
                    .format("%Y-%m-%d")
                    .to_string();

                if db_root.exists() {
                    if let Ok(hosts) = std::fs::read_dir(&db_root) {
                        for host_entry in hosts.flatten() {
                            let host_dir = host_entry.path().join("logs");
                            if !host_dir.exists() {
                                continue;
                            }

                            if let Ok(log_files) = std::fs::read_dir(&host_dir) {
                                for file_entry in log_files.flatten() {
                                    let file_name = file_entry.file_name();
                                    let name = file_name.to_string_lossy();

                                    if !name.ends_with(".msgpack") {
                                        continue;
                                    }

                                    let file_date = name.split(".msgpack").next().unwrap_or("");
                                    if file_date >= cutoff_date.as_str() {
                                        continue;
                                    }

                                    let filepath = file_entry.path();
                                    match Database::new(&filepath, false, 5, Duration::from_secs(5))
                                    {
                                        Ok(db) => {
                                            let logs = db
                                                .get("logs")
                                                .and_then(|v| v.as_array().cloned())
                                                .unwrap_or_default();

                                            let mut retained = Vec::new();
                                            if let Some(ref ast) = retain_asts {
                                                for rec in &logs {
                                                    if crate::utils::query_parser::evaluate(
                                                        ast, rec,
                                                    ) {
                                                        retained.push(rec.clone());
                                                    }
                                                }
                                            }

                                            if retained.is_empty() {
                                                db.close();
                                                let _ = std::fs::remove_file(&filepath);
                                                tracing::info!(
                                                    "Deleted old log file completely: {}",
                                                    name
                                                );
                                            } else if retained.len() < logs.len() {
                                                db.set("logs", serde_json::json!(retained));
                                                db.close();
                                                tracing::info!(
                                                    "Pruned {} logs from {}, retained {}.",
                                                    logs.len() - retained.len(),
                                                    name,
                                                    retained.len()
                                                );
                                            } else {
                                                db.close();
                                            }
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "Log GC error on {}: {}",
                                                filepath.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(3600 * 24));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::compression::decompress_json;

    #[test]
    fn test_process_rrweb_events_empty() {
        let events: Vec<serde_json::Value> = vec![];
        let (duration, rrweb) = process_rrweb_events(&events);
        assert_eq!(duration, None);
        assert_eq!(rrweb, serde_json::json!(""));
    }

    #[test]
    fn test_process_rrweb_events_single_event() {
        let events = vec![serde_json::json!({
            "timestamp": 1000.0,
            "type": 4,
            "data": {}
        })];
        let (duration, rrweb) = process_rrweb_events(&events);
        assert_eq!(duration, Some(0));
        let decompressed = decompress_json(rrweb.as_str().unwrap().as_bytes());
        let arr = decompressed["events"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["timestamp"], 1000.0);
    }

    #[test]
    fn test_process_rrweb_events_multiple_events() {
        let events = vec![
            serde_json::json!({"timestamp": 1000.0, "type": 4}),
            serde_json::json!({"timestamp": 3000.0, "type": 4}),
            serde_json::json!({"timestamp": 6000.0, "type": 4}),
        ];
        let (duration, rrweb) = process_rrweb_events(&events);
        assert_eq!(duration, Some(5));

        let decompressed = decompress_json(rrweb.as_str().unwrap().as_bytes());
        let arr = decompressed["events"].as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["timestamp"], 1000.0);
        assert_eq!(arr[2]["timestamp"], 6000.0);
    }

    #[test]
    fn test_process_rrweb_events_missing_timestamps() {
        let events = vec![
            serde_json::json!({"type": 4}),
            serde_json::json!({"timestamp": 5000.0, "type": 4}),
        ];
        let (duration, rrweb) = process_rrweb_events(&events);
        assert_eq!(duration, Some(5));

        let decompressed = decompress_json(rrweb.as_str().unwrap().as_bytes());
        let arr = decompressed["events"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn test_process_rrweb_events_reverse_order() {
        let events = vec![
            serde_json::json!({"timestamp": 5000.0, "type": 4}),
            serde_json::json!({"timestamp": 1000.0, "type": 4}),
        ];
        let (duration, _) = process_rrweb_events(&events);
        assert_eq!(duration, Some(4));
    }
}
