#![allow(dead_code)]
#![allow(unused_imports)]

use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::config::settings::Settings;
use crate::data::storage::base::Database;

#[cfg(feature = "plugin-system")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRecord {
    pub reason: String,
    pub expire: Option<u32>,
    pub added_at: String,
    pub country: String,
    pub city: String,
}

#[cfg(feature = "plugin-system")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistRecord {
    pub remark: String,
    pub added_at: String,
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
    pub fn new(host: &str, settings: &Settings) -> std::io::Result<Self> {
        let host_dir = settings.db_root.join(host);
        std::fs::create_dir_all(host_dir.join("logs"))?;

        let ram_path = host_dir.join("RAM.msgpack");
        let ram = Database::new(&ram_path, false, 5, std::time::Duration::from_secs(5))?;

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

    fn init_ram_if_empty(&mut self, settings: &Settings) -> std::io::Result<()> {
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

    pub fn ensure_log_db(&self) -> std::io::Result<()> {
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

            let db = Database::new(&new_path, false, 5, std::time::Duration::from_secs(5))?;
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
        #[cfg(feature = "plugin-system")]
        let entry_for_exporter = entry.clone();
        let should_export = {
            let _guard = self.lock.lock();
            let _ = self.ensure_log_db();
            let log_db = self.log_db.lock();
            if let Some(ref db) = *log_db {
                let mut logs = db
                    .get("logs")
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default();

                let rid = entry.get("request_id").and_then(|v| v.as_str());

                if let Some(rid) = rid {
                    if let Some(pos) = logs
                        .iter()
                        .position(|e| e.get("request_id").and_then(|v| v.as_str()) == Some(rid))
                    {
                        logs[pos] = entry;
                        db.set("logs", serde_json::json!(logs));
                        true
                    } else {
                        logs.push(entry);
                        db.set("logs", serde_json::json!(logs));
                        true
                    }
                } else {
                    logs.push(entry);
                    db.set("logs", serde_json::json!(logs));
                    true
                }
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
}

static PROXY_DBS: once_cell::sync::Lazy<DashMap<String, Arc<ProxyDB>>> =
    once_cell::sync::Lazy::new(DashMap::new);

pub fn get_db(host: &str) -> Arc<ProxyDB> {
    PROXY_DBS
        .entry(host.to_string())
        .or_insert_with(|| {
            let settings = crate::config::settings::Settings::load();
            Arc::new(ProxyDB::new(host, &settings).expect("Failed to create ProxyDB"))
        })
        .clone()
}
