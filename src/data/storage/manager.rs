use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use std::sync::LazyLock;

use crate::config::settings::Settings;
use crate::data::storage::base::Database;
use crate::error::WafResult;
use serde_json::Value;

struct PendingLogEntry {
    host: String,
    entry: serde_json::Value,
}

static LOG_SENDER: LazyLock<tokio::sync::mpsc::UnboundedSender<PendingLogEntry>> =
    LazyLock::new(|| {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        start_log_writer_worker(rx);
        tx
    });

fn start_log_writer_worker(mut rx: tokio::sync::mpsc::UnboundedReceiver<PendingLogEntry>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("log writer runtime");
        rt.block_on(async move {
            while let Some(pending) = rx.recv().await {
                let db = get_db(&pending.host);
                db.write_log_direct(pending.entry);
            }
        });
    });
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
        let _ = LOG_SENDER.send(PendingLogEntry {
            host: self.host.clone(),
            entry,
        });
    }

    pub fn write_log_direct(&self, entry: serde_json::Value) {
        #[cfg(feature = "plugin-system")]
        let entry_for_exporter = entry.clone();

        // Use the new O(1) individual-key path when a request_id is present.
        if entry.get("request_id").and_then(|v| v.as_str()).is_some() {
            self.write_log_entry(entry);
            #[cfg(feature = "plugin-system")]
            tokio::spawn(async move {
                crate::plugins::trigger_exporters(entry_for_exporter).await;
            });
            return;
        }

        // Legacy path for entries without request_id
        let should_export = {
            let _guard = self.lock.lock();
            let _ = self.ensure_log_db();
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
    pub fn write_log_entry(&self, entry: serde_json::Value) {
        let request_id = entry
            .get("request_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let _guard = self.lock.lock();
        let _ = self.ensure_log_db();
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
