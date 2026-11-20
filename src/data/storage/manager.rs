use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::LazyLock;

use parking_lot::Mutex;

use crate::config::settings::Settings;
use crate::data::storage::base::Database;
use crate::error::WafResult;
use serde_json::Value;

struct PendingLogEntry {
    host: String,
    entry: serde_json::Value,
}

struct LogQueue {
    normal: tokio::sync::mpsc::Sender<PendingLogEntry>,
    security: tokio::sync::mpsc::Sender<PendingLogEntry>,
}

static LOG_QUEUE: LazyLock<LogQueue> = LazyLock::new(|| {
    let (normal_tx, normal_rx) =
        tokio::sync::mpsc::channel(crate::core::metrics::LOG_QUEUE_NORMAL_CAPACITY);
    let (security_tx, security_rx) =
        tokio::sync::mpsc::channel(crate::core::metrics::LOG_QUEUE_SECURITY_CAPACITY);
    start_log_writer_worker(normal_rx, security_rx);
    LogQueue {
        normal: normal_tx,
        security: security_tx,
    }
});

fn is_high_priority_security_log(entry: &serde_json::Value) -> bool {
    ["type", "detection_type"].iter().any(|key| {
        entry
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .map(|value| {
                [
                    "hacker",
                    "challenge",
                    "block",
                    "blocked",
                    "attack",
                    "malicious",
                ]
                .iter()
                .any(|kind| value.eq_ignore_ascii_case(kind))
            })
            .unwrap_or(false)
    })
}

fn try_enqueue_log(
    sender: &tokio::sync::mpsc::Sender<PendingLogEntry>,
    pending: PendingLogEntry,
    metrics: &crate::core::metrics::Metrics,
) -> Result<(), tokio::sync::mpsc::error::TrySendError<PendingLogEntry>> {
    let permit = match sender.try_reserve() {
        Ok(permit) => permit,
        Err(tokio::sync::mpsc::error::TrySendError::Full(())) => {
            return Err(tokio::sync::mpsc::error::TrySendError::Full(pending));
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
            return Err(tokio::sync::mpsc::error::TrySendError::Closed(pending));
        }
    };
    // Reserve capacity before updating the gauge, then publish only after the
    // gauge has been incremented so the receiver cannot underflow it.
    metrics.log_queue_depth.fetch_add(1, Ordering::Relaxed);
    metrics.log_queue_submitted.fetch_add(1, Ordering::Relaxed);
    permit.send(pending);
    Ok(())
}

fn enqueue_log(
    queue: &LogQueue,
    pending: PendingLogEntry,
    high_priority: bool,
    metrics: &crate::core::metrics::Metrics,
) {
    if high_priority {
        match try_enqueue_log(&queue.security, pending, metrics) {
            Ok(()) => return,
            Err(tokio::sync::mpsc::error::TrySendError::Full(pending)) => {
                // Security logs may use spare normal capacity, but normal traffic
                // cannot consume the reserved security queue.
                match try_enqueue_log(&queue.normal, pending, metrics) {
                    Ok(()) => return,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        metrics
                            .log_queue_enqueue_errors
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(pending)) => {
                metrics
                    .log_queue_enqueue_errors
                    .fetch_add(1, Ordering::Relaxed);
                match try_enqueue_log(&queue.normal, pending, metrics) {
                    Ok(()) => return,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        metrics
                            .log_queue_enqueue_errors
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        metrics
            .log_queue_security_dropped
            .fetch_add(1, Ordering::Relaxed);
    } else {
        match try_enqueue_log(&queue.normal, pending, metrics) {
            Ok(()) => return,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                metrics
                    .log_queue_enqueue_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    metrics.log_queue_dropped.fetch_add(1, Ordering::Relaxed);
}

fn decrement_log_queue_depth(metrics: &crate::core::metrics::Metrics) {
    let _ = metrics
        .log_queue_depth
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_sub(1))
        });
}

fn start_log_writer_worker(
    mut normal_rx: tokio::sync::mpsc::Receiver<PendingLogEntry>,
    mut security_rx: tokio::sync::mpsc::Receiver<PendingLogEntry>,
) {
    let spawn_result = std::thread::Builder::new()
        .name("log-writer".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(error) => {
                    tracing::error!("Failed to build log writer runtime: {}", error);
                    let metrics = &crate::core::metrics::METRICS;
                    metrics.log_write_errors.fetch_add(1, Ordering::Relaxed);
                    security_rx.close();
                    normal_rx.close();
                    while security_rx.try_recv().is_ok() {
                        decrement_log_queue_depth(metrics);
                        metrics.log_write_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    while normal_rx.try_recv().is_ok() {
                        decrement_log_queue_depth(metrics);
                        metrics.log_write_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    return;
                }
            };
            rt.block_on(async move {
                let mut security_open = true;
                let mut normal_open = true;
                loop {
                    let pending = tokio::select! {
                        pending = security_rx.recv(), if security_open => {
                            if pending.is_none() { security_open = false; }
                            pending
                        },
                        pending = normal_rx.recv(), if normal_open => {
                            if pending.is_none() { normal_open = false; }
                            pending
                        },
                        else => break,
                    };
                    let Some(pending) = pending else {
                        continue;
                    };
                    decrement_log_queue_depth(&crate::core::metrics::METRICS);
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        get_db(&pending.host).write_log_direct_checked(pending.entry)
                    }));
                    match result {
                        Ok(true) => {
                            crate::core::metrics::METRICS
                                .log_written
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(false) => {
                            crate::core::metrics::METRICS
                                .log_write_errors
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::error!("Failed to persist queued log entry");
                        }
                        Err(_) => {
                            crate::core::metrics::METRICS
                                .log_write_errors
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::error!("Log writer panicked while persisting an entry");
                        }
                    }
                }
            });
        });
    if let Err(error) = spawn_result {
        tracing::error!("Failed to spawn log writer thread: {}", error);
        crate::core::metrics::METRICS
            .log_queue_enqueue_errors
            .fetch_add(1, Ordering::Relaxed);
    }
}

pub struct ProxyDB {
    pub host: String,
    pub host_dir: PathBuf,
    ram: Arc<Database>,
    log_db: Mutex<Option<Arc<Database>>>,
    log_path: Mutex<String>,
    template_root: PathBuf,
    lock: Mutex<()>,
}

impl ProxyDB {
    pub fn new(host: &str, settings: &Settings) -> WafResult<Self> {
        let host_dir = settings.db_root.join(host);
        std::fs::create_dir_all(host_dir.join("logs"))?;

        let ram_path = host_dir.join("RAM.msgpack");
        let ram = Database::new_with_pool(&ram_path, false, 5)?;

        let mut db = ProxyDB {
            host: host.to_string(),
            host_dir,
            ram: Arc::new(ram),
            log_db: Mutex::new(None),
            log_path: Mutex::new(String::new()),
            template_root: settings.template_root.clone(),
            lock: Mutex::new(()),
        };

        if db.ram.is_empty() {
            db.init_ram_if_empty(settings)?;
        }

        db.ensure_log_db()?;

        Ok(db)
    }

    /// Create a new ProxyDB at a custom path (used as fallback when normal path fails)
    pub fn new_with_path(host: &str, host_dir: &PathBuf, settings: &Settings) -> WafResult<Self> {
        std::fs::create_dir_all(host_dir.join("logs"))?;

        let ram_path = host_dir.join("RAM.msgpack");
        let ram = Database::new_with_pool(&ram_path, false, 5)?;

        let mut db = ProxyDB {
            host: host.to_string(),
            host_dir: host_dir.clone(),
            ram: Arc::new(ram),
            log_db: Mutex::new(None),
            log_path: Mutex::new(String::new()),
            template_root: settings.template_root.clone(),
            lock: Mutex::new(()),
        };

        if db.ram.is_empty() {
            db.init_ram_if_empty(settings)?;
        }

        db.ensure_log_db()?;

        Ok(db)
    }

    /// Create an ephemeral in-memory-only ProxyDB (ultimate fallback, no persistent I/O)
    pub fn new_ephemeral(host: &str) -> Self {
        let host_dir = std::env::temp_dir().join("biubo-waf-ephemeral").join(host);
        let _ = std::fs::create_dir_all(&host_dir);

        let ram_path = host_dir.join("RAM.msgpack");
        let ram = Database::new_with_pool(&ram_path, false, 5).unwrap_or_else(|_| {
            let fallback_path =
                std::env::temp_dir().join(format!("biubo-waf-ram-{}.msgpack", host));
            Database::new_with_pool(&fallback_path, false, 5)
                .expect("Impossible: temp fallback DB creation failed")
        });

        ProxyDB {
            host: host.to_string(),
            host_dir,
            ram: Arc::new(ram),
            log_db: Mutex::new(None),
            log_path: Mutex::new(String::new()),
            template_root: std::path::PathBuf::new(),
            lock: Mutex::new(()),
        }
    }

    fn init_ram_if_empty(&mut self, settings: &Settings) -> WafResult<()> {
        let template_path = settings.template_root.join("RAM.json");
        if template_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&template_path) {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(obj) = data.as_object() {
                        for (k, v) in obj {
                            self.ram.set(k, v.clone());
                        }
                    }
                }
            }
        }

        let now = chrono::Utc::now().format("%Y/%m/%d %H:%M").to_string();
        let site_info = serde_json::json!({
            "description": "This is a WAF proxy.",
            "domain": self.host,
            "created_at": now,
        });
        self.ram.set("site", site_info);

        Ok(())
    }

    pub fn ensure_log_db(&self) -> WafResult<()> {
        let date_str = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let new_path = self
            .host_dir
            .join("logs")
            .join(format!("{}.msgpack", date_str))
            .to_string_lossy()
            .to_string();

        let current_path = self.log_path.lock();
        if new_path == *current_path {
            return Ok(());
        }
        drop(current_path);

        {
            let mut log_db = self.log_db.lock();
            if let Some(ref db) = *log_db {
                let _ = db.flush();
            }

            let db = Database::new_with_pool(&new_path, false, 5)?;
            if db.is_empty() {
                let template_path = self.template_root.join("log.json");
                if template_path.exists() {
                    if let Ok(content) = std::fs::read_to_string(&template_path) {
                        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(obj) = data.as_object() {
                                for (k, v) in obj {
                                    db.set(k, v.clone());
                                }
                            }
                        }
                    }
                }
            }

            if !db.contains_key("logs") {
                db.set("logs", serde_json::json!([]));
            }

            let overview = db.get("overview").unwrap_or(serde_json::json!({}));
            if overview.get("seen_ips_today").is_none() {
                let mut overview = overview;
                overview["seen_ips_today"] = serde_json::json!({});
                db.set("overview", overview);
            }

            *log_db = Some(Arc::new(db));
        }

        *self.log_path.lock() = new_path;
        Ok(())
    }

    pub fn write_log(&self, entry: serde_json::Value) {
        let high_priority = is_high_priority_security_log(&entry);
        enqueue_log(
            &LOG_QUEUE,
            PendingLogEntry {
                host: self.host.clone(),
                entry,
            },
            high_priority,
            &crate::core::metrics::METRICS,
        );
    }

    pub fn write_log_direct(&self, entry: serde_json::Value) {
        let _ = self.write_log_direct_checked(entry);
    }

    fn write_log_direct_checked(&self, entry: serde_json::Value) -> bool {
        #[cfg(feature = "plugin-system")]
        let entry_for_exporter = entry.clone();

        // Use the new O(1) individual-key path when a request_id is present.
        if entry.get("request_id").and_then(|v| v.as_str()).is_some() {
            if !self.write_log_entry_checked(entry) {
                return false;
            }
            #[cfg(feature = "plugin-system")]
            tokio::spawn(async move {
                crate::plugins::trigger_exporters(entry_for_exporter).await;
            });
            return true;
        }

        // Legacy path for entries without request_id
        let should_export = {
            let _guard = self.lock.lock();
            if self.ensure_log_db().is_err() {
                return false;
            }
            let log_db = self.log_db.lock();
            if let Some(ref db) = *log_db {
                let mut logs = db
                    .get("logs")
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default();

                const MAX_LOG_ENTRIES: usize = 10_000;
                if logs.len() >= MAX_LOG_ENTRIES {
                    let remove_count = MAX_LOG_ENTRIES / 5;
                    logs.drain(0..remove_count);
                }

                logs.push(entry);
                db.set("logs", serde_json::json!(logs));
                true
            } else {
                false
            }
        };

        if should_export {
            #[cfg(feature = "plugin-system")]
            tokio::spawn(async move {
                crate::plugins::trigger_exporters(entry_for_exporter).await;
            });
        }
        should_export
    }

    pub fn ram_get(&self, key: &str) -> Option<serde_json::Value> {
        self.ram.get(key)
    }

    pub fn ram_set(&self, key: &str, value: serde_json::Value) {
        self.ram.set(key, value);
    }

    async fn ban_ip_impl(&self, ip: &str, reason: &str, expire_json: serde_json::Value) {
        let info = crate::utils::http_utils::get_ip_info(ip).await;
        let country = info
            .get("country")
            .or_else(|| info.get("countryName"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let city = info
            .get("city")
            .or_else(|| info.get("cityName"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let _guard = self.lock.lock();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let record = serde_json::json!({
            "reason": reason,
            "expire": expire_json,
            "added_at": now,
            "country": country,
            "city": city,
        });

        let mut security = self
            .ram_get("security")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        let blacklist = security
            .entry("blacklist")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(obj) = blacklist.as_object_mut() {
            obj.insert(ip.to_string(), record.clone());
        }
        self.ram_set("security", serde_json::Value::Object(security));

        let _ = self.ensure_log_db();
        let log_db = self.log_db.lock();
        if let Some(ref db) = *log_db {
            let mut overview = db
                .get("overview")
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default();
            let block_today = overview
                .entry("block_today")
                .or_insert_with(|| serde_json::json!([]));
            if let Some(arr) = block_today.as_array_mut() {
                let mut ip_map = serde_json::Map::new();
                ip_map.insert(ip.into(), record);
                arr.push(serde_json::Value::Object(ip_map));
            }
            db.set("overview", serde_json::Value::Object(overview));
            let _ = db.flush();
        }

        let _ = self.ram.flush();
        tracing::warn!(
            "[BAN] {} banned — reason={} expire={}",
            ip,
            reason,
            expire_json
        );
    }

    pub async fn ban_ip(&self, ip: &str, reason: &str, expire_minutes: Option<u32>) {
        let expire_json = match expire_minutes {
            None => serde_json::Value::Null,
            Some(n) => serde_json::json!(n),
        };
        self.ban_ip_impl(ip, reason, expire_json).await;
    }

    pub async fn ban_ip_temporary(&self, ip: &str, reason: &str) {
        self.ban_ip_impl(ip, reason, serde_json::json!(true)).await;
    }

    pub fn unban_ip(&self, ip: &str) -> bool {
        let _guard = self.lock.lock();
        let mut security = self
            .ram_get("security")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();

        if let Some(blacklist) = security
            .get_mut("blacklist")
            .and_then(|v| v.as_object_mut())
        {
            if blacklist.remove(ip).is_some() {
                self.ram_set("security", serde_json::Value::Object(security));
                let _ = self.ram.flush();
                tracing::warn!("[UNBAN] {} removed from blacklist", ip);
                return true;
            }
        }
        false
    }

    pub fn is_banned(&self, ip: &str) -> bool {
        let security = self.ram_get("security");
        let blacklist = security
            .as_ref()
            .and_then(|v| v.get("blacklist"))
            .and_then(|v| v.as_object());

        let record = match blacklist.and_then(|m| m.get(ip)) {
            Some(r) => r,
            None => return false,
        };

        let expire_val = match record.get("expire") {
            Some(val) => val,
            None => return true,
        };

        if expire_val.is_null() {
            return true;
        }

        if expire_val.as_bool() == Some(true) {
            return true;
        }

        let expire_min = match expire_val.as_u64() {
            Some(min) => min,
            None => return true,
        };

        let added_at_str = match record.get("added_at").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return true,
        };

        let added_at = match chrono::DateTime::parse_from_rfc3339(added_at_str) {
            Ok(dt) => dt.to_utc(),
            Err(_) => return true,
        };

        let expire_at = added_at + chrono::Duration::minutes(expire_min as i64);
        let now = chrono::Utc::now();

        if now >= expire_at {
            let mut security = self
                .ram_get("security")
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default();
            if let Some(bl) = security
                .get_mut("blacklist")
                .and_then(|v| v.as_object_mut())
            {
                bl.remove(ip);
                self.ram_set("security", serde_json::Value::Object(security));
                let _ = self.ram.flush();
            }
            tracing::warn!("[UNBAN] {} auto-removed from blacklist (expired)", ip);
            false
        } else {
            true
        }
    }

    pub fn is_temporary_banned(&self, ip: &str) -> bool {
        let security = self.ram_get("security");
        let record = security
            .as_ref()
            .and_then(|v| v.get("blacklist"))
            .and_then(|v| v.get(ip));
        record
            .and_then(|r| r.get("expire").and_then(|v| v.as_bool()))
            .unwrap_or(false)
    }

    pub fn is_whitelisted(&self, ip: &str) -> bool {
        let security = self.ram_get("security");
        security
            .as_ref()
            .and_then(|v| v.get("whitelist"))
            .and_then(|v| v.as_object())
            .map(|m| m.contains_key(ip))
            .unwrap_or(false)
    }

    pub fn add_whitelist(&self, ip: &str, remark: &str) {
        let _guard = self.lock.lock();
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let record = serde_json::json!({
            "remark": remark,
            "added_at": now,
        });

        let mut security = self
            .ram_get("security")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        let whitelist = security
            .entry("whitelist")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(obj) = whitelist.as_object_mut() {
            obj.insert(ip.to_string(), record);
        }
        self.ram_set("security", serde_json::Value::Object(security));
        let _ = self.ram.flush();
    }

    pub fn remove_whitelist(&self, ip: &str) -> bool {
        let _guard = self.lock.lock();
        let mut security = self
            .ram_get("security")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();

        if let Some(whitelist) = security
            .get_mut("whitelist")
            .and_then(|v| v.as_object_mut())
        {
            if whitelist.remove(ip).is_some() {
                self.ram_set("security", serde_json::Value::Object(security));
                return true;
            }
        }
        false
    }

    pub fn get_log_db(&self) -> Option<Arc<Database>> {
        self.log_db.lock().clone()
    }

    pub fn get_ban_record(&self, ip: &str) -> Option<serde_json::Value> {
        self.ram_get("security")
            .and_then(|v| v.get("blacklist").cloned())
            .and_then(|bl| bl.get(ip).cloned())
    }

    pub fn get_logs(&self) -> Vec<serde_json::Value> {
        let _ = self.ensure_log_db();
        let log_db = self.log_db.lock();
        match *log_db {
            Some(ref db) => {
                // Try new individual-key format first (log_index + log:{id})
                let index = db.get("log_index");
                if let Some(Value::Array(ids)) = &index {
                    let mut logs: Vec<serde_json::Value> = Vec::with_capacity(ids.len());
                    for id_val in ids {
                        if let Some(id_str) = id_val.as_str() {
                            if let Some(entry) = db.get(&format!("log:{}", id_str)) {
                                logs.push(entry);
                            }
                        }
                    }
                    return logs;
                }
                // Fall back to legacy "logs" array format
                db.get("logs")
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default()
            }
            None => vec![],
        }
    }

    pub fn find_log_by_request_id(&self, id: &str) -> Option<serde_json::Value> {
        let _ = self.ensure_log_db();
        let log_db = self.log_db.lock();
        match *log_db {
            Some(ref db) => {
                // Try new individual-key format first
                let entry = db.get(&format!("log:{}", id));
                if entry.is_some() {
                    return entry;
                }
                // Fall back to legacy "logs" array
                let logs = db
                    .get("logs")
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default();
                logs.iter()
                    .find(|e| e.get("request_id").and_then(|v| v.as_str()) == Some(id))
                    .cloned()
            }
            None => None,
        }
    }

    /// Write a log entry using the new individual-key format.
    /// Stores the entry as `log:{request_id}` and maintains a capped `log_index` for iteration.
    /// This is O(1) instead of O(n) like the legacy `write_log_direct`.
    #[allow(dead_code)]
    pub fn write_log_entry(&self, entry: serde_json::Value) {
        let _ = self.write_log_entry_checked(entry);
    }

    fn write_log_entry_checked(&self, entry: serde_json::Value) -> bool {
        let request_id = entry
            .get("request_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let _guard = self.lock.lock();
        if self.ensure_log_db().is_err() {
            return false;
        }
        let log_db = self.log_db.lock();
        if let Some(ref db) = *log_db {
            if let Some(ref rid) = request_id {
                // Store the full entry as an individual key
                db.set(&format!("log:{}", rid), entry);

                // Maintain a capped index for enumeration
                const MAX_INDEX_SIZE: usize = 10_000;
                let mut index = db
                    .get("log_index")
                    .unwrap_or_else(|| Value::Array(Vec::new()));

                if let Value::Array(ref mut ids) = index {
                    // Check if this request_id already exists in index
                    let exists = ids.iter().any(|v| v.as_str() == Some(rid));
                    if !exists {
                        if ids.len() >= MAX_INDEX_SIZE {
                            ids.remove(0);
                        }
                        ids.push(Value::String(rid.clone()));
                    }
                }
                db.set("log_index", index);
            } else {
                // Fallback: no request_id, use legacy array
                let mut logs = db
                    .get("logs")
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default();
                logs.push(entry);
                db.set("logs", Value::Array(logs));
            }
            true
        } else {
            false
        }
    }
}

/// PROXY_DBS 缓存容量上限（可缓存的不同 host 数量）。
///
/// 目前为模块级常量；后续可迁移到 config.json / 环境变量实现可配置化
/// （受限于并行修改窗口，本次不改动 src/config/settings.rs）。
const PROXY_DB_CACHE_MAX_CAPACITY: u64 = 1000;

/// PROXY_DBS 缓存 TTI（秒）：host 空闲超过该时长后被淘汰。
const PROXY_DB_CACHE_TTI_SECS: u64 = 3600;

/// Settings 一次性快照：进程启动后只加载一次，供所有缓存 miss 复用。
///
/// 原实现在每次 miss 时都调用 `Settings::load()` 重读配置文件；
/// 攻击者用随机 Host 头可触发海量文件 I/O。快照复用消除该开销。
/// 如需运行时配置热更新，后续再引入刷新机制。
static SETTINGS_SNAPSHOT: LazyLock<Settings> = LazyLock::new(Settings::load);

/// 有界 ProxyDB 缓存：moka LRU（max_capacity）+ TTI 淘汰。
///
/// 淘汰时通过 eviction listener 对被淘汰实例执行 flush，
/// 保证 LRU/TTI 淘汰不丢失未落盘的写入。
static PROXY_DBS: LazyLock<moka::sync::Cache<String, Arc<ProxyDB>>> = LazyLock::new(|| {
    moka::sync::Cache::builder()
        .max_capacity(PROXY_DB_CACHE_MAX_CAPACITY)
        .time_to_idle(std::time::Duration::from_secs(PROXY_DB_CACHE_TTI_SECS))
        .eviction_listener(|host: Arc<String>, db: Arc<ProxyDB>, cause| {
            // listener 处于同步上下文，Database::flush 为同步 API，可直接调用。
            // 失败仅忽略（与 flush_all 保持一致），绝不 panic。
            db.ram.flush().ok();
            if let Some(log_db) = db.get_log_db() {
                log_db.flush().ok();
            }
            tracing::debug!(
                "ProxyDB for host '{}' evicted from cache (cause: {:?}), flushed to disk",
                host,
                cause
            );
        })
        .build()
});

/// 创建 ProxyDB 实例（三级 fallback：正常路径 → temp_dir fallback → 纯内存 ephemeral）。
fn create_proxy_db(host: &str) -> Arc<ProxyDB> {
    let settings: &Settings = &SETTINGS_SNAPSHOT;
    match ProxyDB::new(host, settings) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            tracing::error!("Failed to create ProxyDB for host '{}': {}", host, e);
            tracing::warn!("Creating fallback ProxyDB for '{}' to avoid crash", host);
            // Try fallback in temp directory
            let fallback_dir = std::env::temp_dir().join("biubo-waf-fallback").join(host);
            match ProxyDB::new_with_path(host, &fallback_dir, settings) {
                Ok(db) => {
                    tracing::warn!(
                        "Using fallback ProxyDB for '{}' at {:?}",
                        host,
                        fallback_dir
                    );
                    Arc::new(db)
                }
                Err(fallback_err) => {
                    tracing::error!(
                        "Fallback ProxyDB also failed: {} - using in-memory stub",
                        fallback_err
                    );
                    Arc::new(ProxyDB::new_ephemeral(host))
                }
            }
        }
    }
}

pub fn get_db(host: &str) -> Arc<ProxyDB> {
    // get_with：并发 miss 时只有一个线程执行初始化，其余等待复用结果。
    // 三级 fallback 保证 create_proxy_db 不会返回错误（最坏降级为 ephemeral）。
    PROXY_DBS.get_with(host.to_string(), || create_proxy_db(host))
}

/// Flush all ProxyDB instances (used during graceful shutdown).
/// Ensures all pending writes are persisted before the process exits.
pub async fn flush_all() {
    tracing::info!("Flushing all ProxyDB instances...");
    let count = PROXY_DBS.entry_count();
    for (_host, db) in PROXY_DBS.iter() {
        db.ram.flush().ok();
        if let Some(log_db) = db.get_log_db() {
            log_db.flush().ok();
        }
    }
    tracing::info!("Flushed {} ProxyDB instances", count);
}

/// 缓存当前条目数（仅测试用，用于验证有界化行为）。
#[cfg(test)]
pub(crate) fn proxy_db_cache_len() -> u64 {
    PROXY_DBS.entry_count()
}

#[cfg(test)]
mod log_queue_tests {
    use super::*;

    fn pending(id: usize, entry: serde_json::Value) -> PendingLogEntry {
        PendingLogEntry {
            host: format!("test-{id}.invalid"),
            entry,
        }
    }

    fn queue(
        normal_capacity: usize,
        security_capacity: usize,
    ) -> (
        LogQueue,
        tokio::sync::mpsc::Receiver<PendingLogEntry>,
        tokio::sync::mpsc::Receiver<PendingLogEntry>,
    ) {
        let (normal, normal_rx) = tokio::sync::mpsc::channel(normal_capacity);
        let (security, security_rx) = tokio::sync::mpsc::channel(security_capacity);
        (LogQueue { normal, security }, normal_rx, security_rx)
    }

    #[test]
    fn log_queue_has_fixed_bounded_capacity_and_security_priority() {
        use crate::core::metrics::{
            Metrics, LOG_QUEUE_CAPACITY, LOG_QUEUE_NORMAL_CAPACITY, LOG_QUEUE_SECURITY_CAPACITY,
        };

        assert_eq!(
            LOG_QUEUE_CAPACITY,
            LOG_QUEUE_NORMAL_CAPACITY + LOG_QUEUE_SECURITY_CAPACITY
        );
        assert!(LOG_QUEUE_NORMAL_CAPACITY > 0);
        assert!(LOG_QUEUE_SECURITY_CAPACITY > 0);

        let (queue, _normal_rx, _security_rx) = queue(2, 1);
        let metrics = Metrics::new();

        // Normal traffic cannot consume the separately reserved security slot.
        enqueue_log(
            &queue,
            pending(0, serde_json::json!({"type":"normal"})),
            false,
            &metrics,
        );
        enqueue_log(
            &queue,
            pending(1, serde_json::json!({"type":"normal"})),
            false,
            &metrics,
        );
        enqueue_log(
            &queue,
            pending(2, serde_json::json!({"type":"normal"})),
            false,
            &metrics,
        );
        assert_eq!(metrics.log_queue_submitted.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.log_queue_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.log_queue_depth.load(Ordering::Relaxed), 2);

        // Security logs use their reserve first, then fall back to normal capacity.
        enqueue_log(
            &queue,
            pending(3, serde_json::json!({"detection_type":"hacker"})),
            true,
            &metrics,
        );
        enqueue_log(
            &queue,
            pending(4, serde_json::json!({"type":"challenge"})),
            true,
            &metrics,
        );
        assert_eq!(metrics.log_queue_submitted.load(Ordering::Relaxed), 3);
        assert_eq!(
            metrics.log_queue_security_dropped.load(Ordering::Relaxed),
            1
        );
        assert_eq!(metrics.log_queue_dropped.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.log_queue_depth.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn high_priority_logs_fall_back_to_available_normal_capacity() {
        use crate::core::metrics::Metrics;

        let (queue, _normal_rx, _security_rx) = queue(2, 1);
        let metrics = Metrics::new();
        enqueue_log(
            &queue,
            pending(0, serde_json::json!({"type":"hacker"})),
            true,
            &metrics,
        );
        enqueue_log(
            &queue,
            pending(1, serde_json::json!({"type":"normal"})),
            false,
            &metrics,
        );
        enqueue_log(
            &queue,
            pending(2, serde_json::json!({"type":"block"})),
            true,
            &metrics,
        );

        assert_eq!(metrics.log_queue_submitted.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.log_queue_depth.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.log_queue_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(
            metrics.log_queue_security_dropped.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn closed_channels_are_counted_without_blocking_or_panicking() {
        use crate::core::metrics::Metrics;

        let (normal, normal_rx) = tokio::sync::mpsc::channel(1);
        let (security, security_rx) = tokio::sync::mpsc::channel(1);
        drop(normal_rx);
        drop(security_rx);
        let queue = LogQueue { normal, security };
        let metrics = Metrics::new();

        enqueue_log(
            &queue,
            pending(0, serde_json::json!({"type":"normal"})),
            false,
            &metrics,
        );
        enqueue_log(
            &queue,
            pending(1, serde_json::json!({"type":"hacker"})),
            true,
            &metrics,
        );

        assert_eq!(metrics.log_queue_enqueue_errors.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.log_queue_dropped.load(Ordering::Relaxed), 2);
        assert_eq!(
            metrics.log_queue_security_dropped.load(Ordering::Relaxed),
            1
        );
        assert_eq!(metrics.log_queue_depth.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn concurrent_producers_keep_queue_and_metrics_bounded() {
        use crate::core::metrics::Metrics;
        use std::sync::Arc;

        const CAPACITY: usize = 32;
        const PRODUCERS: usize = 8;
        const PER_PRODUCER: usize = 100;
        let (queue, _normal_rx, _security_rx) = queue(CAPACITY, 4);
        let queue = Arc::new(queue);
        let metrics = Arc::new(Metrics::new());

        std::thread::scope(|scope| {
            for producer in 0..PRODUCERS {
                let queue = Arc::clone(&queue);
                let metrics = Arc::clone(&metrics);
                scope.spawn(move || {
                    for index in 0..PER_PRODUCER {
                        enqueue_log(
                            &queue,
                            pending(
                                producer * PER_PRODUCER + index,
                                serde_json::json!({"type":"normal"}),
                            ),
                            false,
                            &metrics,
                        );
                    }
                });
            }
        });

        let accepted = metrics.log_queue_submitted.load(Ordering::Relaxed);
        let dropped = metrics.log_queue_dropped.load(Ordering::Relaxed);
        assert_eq!(accepted, CAPACITY as u64);
        assert_eq!(dropped, (PRODUCERS * PER_PRODUCER - CAPACITY) as u64);
        assert_eq!(
            metrics.log_queue_depth.load(Ordering::Relaxed),
            CAPACITY as u64
        );
    }

    #[test]
    fn security_event_classifier_is_case_insensitive_and_low_cardinality() {
        assert!(is_high_priority_security_log(
            &serde_json::json!({"type":"HACKER"})
        ));
        assert!(is_high_priority_security_log(
            &serde_json::json!({"detection_type":"challenge"})
        ));
        assert!(!is_high_priority_security_log(
            &serde_json::json!({"type":"normal", "host":"hacker"})
        ));
    }
}

#[cfg(test)]
mod proxy_db_cache_tests {
    use super::*;

    /// 行为验证：插入远超容量上限的不同 host 后，缓存条目数 ≤ max_capacity。
    ///
    /// 直接插入 ephemeral 实例避免依赖 Settings/磁盘目录；
    /// run_pending_tasks() 强制 moka 处理待淘汰队列后再计数。
    #[test]
    fn test_unbounded_cache_growth() {
        let total = PROXY_DB_CACHE_MAX_CAPACITY as usize + 500;
        for i in 0..total {
            let host = format!("cache-bound-test-{}.invalid", i);
            PROXY_DBS.insert(host, Arc::new(ProxyDB::new_ephemeral("cache-bound-test")));
        }
        // moka 的 entry_count 为最终一致，需先执行待处理淘汰任务
        PROXY_DBS.run_pending_tasks();
        PROXY_DBS.run_pending_tasks();

        let len = proxy_db_cache_len();
        assert!(
            len <= PROXY_DB_CACHE_MAX_CAPACITY,
            "PROXY_DBS 缓存未被容量上限约束: {} > {}",
            len,
            PROXY_DB_CACHE_MAX_CAPACITY
        );

        // 清理测试污染，避免影响同进程内其他测试
        PROXY_DBS.invalidate_all();
        PROXY_DBS.run_pending_tasks();
    }
}
