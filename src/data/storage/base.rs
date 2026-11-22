use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::data::storage::flusher_pool::{global_pool, FlushHandle};
use crate::error::WafResult;
use parking_lot::Mutex;

const MSGPACK_EXT: &str = "msgpack";

pub struct Database {
    path: PathBuf,
    auto_backup: bool,
    max_backup_count: usize,
    data: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    dirty: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    flusher_handle: Mutex<Option<JoinHandle<()>>>,
    _pool_handle: Mutex<Option<FlushHandle>>,
}

impl Database {
    /// Create a new Database with a dedicated OS thread for write-behind flushing.
    pub fn new(
        path: impl AsRef<Path>,
        auto_backup: bool,
        max_backup_count: usize,
        flush_interval: Duration,
    ) -> std::io::Result<Self> {
        let path = normalize_path(path);
        ensure_parent_dir(&path)?;

        let (data, dirty, stop_flag) = init_state(&path)?;

        let db = Database {
            path: path.clone(),
            auto_backup,
            max_backup_count,
            data: data.clone(),
            dirty: dirty.clone(),
            stop_flag: stop_flag.clone(),
            flusher_handle: Mutex::new(None),
            _pool_handle: Mutex::new(None),
        };

        if !db.path.exists() {
            let guard = db.data.lock();
            crate::data::storage::storage_utils::write_to_disk(&guard, &db.path)?;
        }

        // Spawn dedicated flusher thread
        let handle = spawn_flusher_thread(
            data,
            dirty,
            stop_flag,
            path,
            auto_backup,
            max_backup_count,
            flush_interval,
        )?;
        *db.flusher_handle.lock() = Some(handle);

        Ok(db)
    }

    /// Create a Database that uses the global shared flusher pool instead of a
    /// dedicated OS thread. Recommended for most use-cases to reduce thread count.
    pub fn new_with_pool(
        path: impl AsRef<Path>,
        auto_backup: bool,
        max_backup_count: usize,
    ) -> WafResult<Self> {
        let path = normalize_path(path);
        ensure_parent_dir(&path)?;

        let (data, dirty, stop_flag) = init_state(&path)?;

        let db = Database {
            path: path.clone(),
            auto_backup,
            max_backup_count,
            data: data.clone(),
            dirty: dirty.clone(),
            stop_flag,
            flusher_handle: Mutex::new(None),
            _pool_handle: Mutex::new(None),
        };

        if !db.path.exists() {
            let guard = db.data.lock();
            crate::data::storage::storage_utils::write_to_disk(&guard, &db.path)?;
        }

        // Register with global pool instead of spawning a thread
        let handle = global_pool().register(data, dirty, path, auto_backup, max_backup_count);
        *db._pool_handle.lock() = Some(handle);

        Ok(db)
    }

    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        self.data.lock().get(key).cloned()
    }

    /// Read a newest-first page from an indexed log collection while holding the
    /// database lock once. The predicate is applied before calculating offsets,
    /// so filtered pagination reports the correct total.
    pub fn get_indexed_page<F>(
        &self,
        index_key: &str,
        key_prefix: &str,
        offset: usize,
        limit: usize,
        mut predicate: F,
    ) -> (Vec<serde_json::Value>, usize)
    where
        F: FnMut(&serde_json::Value) -> bool,
    {
        let data = self.data.lock();
        let Some(serde_json::Value::Array(ids)) = data.get(index_key) else {
            let Some(serde_json::Value::Array(logs)) = data.get("logs") else {
                return (Vec::new(), 0);
            };

            let mut page = Vec::with_capacity(limit);
            let mut total = 0;
            for entry in logs.iter().rev().filter(|entry| predicate(entry)) {
                if total >= offset && page.len() < limit {
                    page.push(entry.clone());
                }
                total += 1;
            }
            return (page, total);
        };

        let mut page = Vec::with_capacity(limit);
        let mut total = 0;
        for id in ids.iter().rev().filter_map(serde_json::Value::as_str) {
            let key = format!("{key_prefix}{id}");
            let Some(entry) = data.get(&key) else {
                continue;
            };
            if !predicate(entry) {
                continue;
            }
            if total >= offset && page.len() < limit {
                page.push(entry.clone());
            }
            total += 1;
        }
        (page, total)
    }

    pub fn set(&self, key: &str, value: serde_json::Value) {
        let mut guard = self.data.lock();
        guard.insert(key.to_string(), value);
        self.dirty.store(true, Ordering::Release);
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.data.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.lock().is_empty()
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.data.lock().contains_key(key)
    }

    pub fn flush(&self) -> std::io::Result<()> {
        if !self.dirty.load(Ordering::Acquire) {
            return Ok(());
        }
        let guard = self.data.lock();
        if !self.dirty.load(Ordering::Relaxed) {
            return Ok(());
        }
        if self.auto_backup {
            let _ = crate::data::storage::storage_utils::create_backup(
                &self.path,
                self.max_backup_count,
            );
        }
        crate::data::storage::storage_utils::write_to_disk(&guard, &self.path)?;
        self.dirty.store(false, Ordering::Release);
        Ok(())
    }

    pub fn close(&self) {
        self.stop_flag.store(true, Ordering::Release);
        let mut handle_guard = self.flusher_handle.lock();
        if let Some(handle) = handle_guard.take() {
            let _ = handle.join();
        }
        // Pool handle is dropped via _pool_handle going out of scope
        let _ = self.flush();
    }
}

// --- Helpers ---

fn normalize_path(path: impl AsRef<Path>) -> PathBuf {
    let p = path.as_ref().to_path_buf();
    if p.extension().map(|e| e != MSGPACK_EXT).unwrap_or(true) {
        p.with_extension(MSGPACK_EXT)
    } else {
        p
    }
}

fn ensure_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn init_state(
    path: &Path,
) -> std::io::Result<(
    Arc<Mutex<HashMap<String, serde_json::Value>>>,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
)> {
    let data = if path.exists() {
        match fs::read(path) {
            Ok(buf) if !buf.is_empty() => rmp_serde::from_slice(&buf).unwrap_or_default(),
            _ => HashMap::new(),
        }
    } else {
        HashMap::new()
    };

    Ok((
        Arc::new(Mutex::new(data)),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    ))
}

fn spawn_flusher_thread(
    data: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    dirty: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    path: PathBuf,
    auto_backup: bool,
    max_backup_count: usize,
    flush_interval: Duration,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("db-write-behind".into())
        .spawn(move || loop {
            if stop_flag.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(flush_interval);
            if stop_flag.load(Ordering::Acquire) {
                break;
            }
            if !dirty.load(Ordering::Acquire) {
                continue;
            }
            let guard = data.lock();
            if !dirty.load(Ordering::Relaxed) {
                continue;
            }
            if auto_backup {
                let _ = crate::data::storage::storage_utils::create_backup(&path, max_backup_count);
            }
            match crate::data::storage::storage_utils::write_to_disk(&guard, &path) {
                Ok(()) => {
                    dirty.store(false, Ordering::Release);
                }
                Err(e) => {
                    tracing::error!("[WriteBehind] Flush error: {}", e);
                }
            }
        })
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

impl Drop for Database {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod indexed_page_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn indexed_page_filters_before_offset_and_returns_newest_first() {
        let path = std::env::temp_dir().join(format!(
            "biubo-indexed-page-{}.msgpack",
            uuid::Uuid::new_v4()
        ));
        let db = Database::new_with_pool(&path, false, 0).expect("create temporary database");
        db.set("log_index", json!(["1", "2", "3", "4"]));
        db.set("log:1", json!({"type":"normal", "id":1}));
        db.set("log:2", json!({"type":"hacker", "id":2}));
        db.set("log:3", json!({"type":"hacker", "id":3}));
        db.set("log:4", json!({"type":"hacker", "id":4}));

        let (page, total) = db.get_indexed_page("log_index", "log:", 1, 2, |entry| {
            entry.get("type").and_then(serde_json::Value::as_str) == Some("hacker")
        });

        assert_eq!(total, 3);
        assert_eq!(page.len(), 2);
        assert_eq!(page[0]["id"], 3);
        assert_eq!(page[1]["id"], 2);

        drop(db);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn indexed_page_supports_legacy_log_arrays() {
        let path = std::env::temp_dir().join(format!(
            "biubo-legacy-page-{}.msgpack",
            uuid::Uuid::new_v4()
        ));
        let db = Database::new_with_pool(&path, false, 0).expect("create temporary database");
        db.set("logs", json!([{"id":1}, {"id":2}, {"id":3}]));

        let (page, total) = db.get_indexed_page("log_index", "log:", 1, 1, |_| true);

        assert_eq!(total, 3);
        assert_eq!(page, vec![json!({"id":2})]);

        drop(db);
        let _ = fs::remove_file(&path);
    }
}
