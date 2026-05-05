use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MSGPACK_EXT: &str = "msgpack";

pub struct Database {
    path: PathBuf,
    auto_backup: bool,
    max_backup_count: usize,
    data: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    dirty: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    flusher_handle: Mutex<Option<JoinHandle<()>>>,
}

impl Database {
    pub fn new(
        path: impl AsRef<Path>,
        auto_backup: bool,
        max_backup_count: usize,
        flush_interval: Duration,
    ) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let path = if path
            .extension()
            .map(|e| e != MSGPACK_EXT)
            .unwrap_or(true)
        {
            path.with_extension(MSGPACK_EXT)
        } else {
            path
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let data = if path.exists() {
            match fs::read(&path) {
                Ok(buf) if !buf.is_empty() => rmp_serde::from_slice(&buf).unwrap_or_default(),
                _ => HashMap::new(),
            }
        } else {
            HashMap::new()
        };

        let data = Arc::new(Mutex::new(data));
        let dirty = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::new(AtomicBool::new(false));

        let db = Database {
            path: path.clone(),
            auto_backup,
            max_backup_count,
            data: data.clone(),
            dirty: dirty.clone(),
            stop_flag: stop_flag.clone(),
            flusher_handle: Mutex::new(None),
        };

        if !db.path.exists() {
            let guard = db.data.lock().unwrap();
            write_to_disk_impl(&guard, &db.path)?;
        }

        let flusher_data = data;
        let flusher_dirty = dirty;
        let flusher_stop = stop_flag;
        let flusher_path = path;
        let flusher_auto_backup = auto_backup;
        let flusher_max_backup = max_backup_count;

        let handle = thread::Builder::new()
            .name("db-write-behind".into())
            .spawn(move || {
                loop {
                    if flusher_stop.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(flush_interval);
                    if flusher_stop.load(Ordering::Acquire) {
                        break;
                    }
                    if !flusher_dirty.load(Ordering::Acquire) {
                        continue;
                    }
                    let Ok(guard) = flusher_data.lock() else {
                        continue;
                    };
                    if !flusher_dirty.load(Ordering::Relaxed) {
                        continue;
                    }
                    if flusher_auto_backup {
                        let _ = create_backup_impl(&flusher_path, flusher_max_backup);
                    }
                    match write_to_disk_impl(&guard, &flusher_path) {
                        Ok(()) => {
                            flusher_dirty.store(false, Ordering::Release);
                        }
                        Err(e) => {
                            tracing::error!("[WriteBehind] Flush error: {}", e);
                        }
                    }
                }
            })
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        *db.flusher_handle.lock().unwrap() = Some(handle);

        Ok(db)
    }

    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        self.data.lock().unwrap().get(key).cloned()
    }

    pub fn set(&self, key: &str, value: serde_json::Value) {
        let mut guard = self.data.lock().unwrap();
        guard.insert(key.to_string(), value);
        self.dirty.store(true, Ordering::Release);
    }

    #[allow(dead_code)]
    pub fn delete(&self, key: &str) -> bool {
        let mut guard = self.data.lock().unwrap();
        let removed = guard.remove(key).is_some();
        if removed {
            self.dirty.store(true, Ordering::Release);
        }
        removed
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.data.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.lock().unwrap().is_empty()
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.data.lock().unwrap().contains_key(key)
    }

    pub fn flush(&self) -> std::io::Result<()> {
        if !self.dirty.load(Ordering::Acquire) {
            return Ok(());
        }
        let guard = self.data.lock().unwrap();
        if !self.dirty.load(Ordering::Relaxed) {
            return Ok(());
        }
        if self.auto_backup {
            let _ = create_backup_impl(&self.path, self.max_backup_count);
        }
        write_to_disk_impl(&guard, &self.path)?;
        self.dirty.store(false, Ordering::Release);
        Ok(())
    }

    pub fn close(&self) {
        self.stop_flag.store(true, Ordering::Release);
        if let Ok(mut handle_guard) = self.flusher_handle.lock() {
            if let Some(handle) = handle_guard.take() {
                let _ = handle.join();
            }
        }
        let _ = self.flush();
    }
}

fn write_to_disk_impl(
    data: &HashMap<String, serde_json::Value>,
    path: &Path,
) -> std::io::Result<()> {
    let encoded = rmp_serde::to_vec(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let tmp_path = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(&encoded)?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn create_backup_impl(path: &Path, max_backup_count: usize) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let backup_name = format!("{}.backup_{}.{}", stem, ts, MSGPACK_EXT);
    let backup_path = path.with_file_name(backup_name);
    let _ = fs::copy(path, &backup_path);

    if let Some(parent) = path.parent() {
        let prefix = format!("{}.backup_", stem);
        let suffix = format!(".{}", MSGPACK_EXT);
        let mut backups: Vec<_> = fs::read_dir(parent)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let binding = e.file_name();
                let name = binding.to_string_lossy();
                name.starts_with(&prefix) && name.ends_with(&suffix)
            })
            .collect();

        backups.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));
        backups.reverse();

        for old in backups.iter().skip(max_backup_count) {
            let _ = fs::remove_file(old.path());
        }
    }

    Ok(())
}

impl Drop for Database {
    fn drop(&mut self) {
        self.close();
    }
}
