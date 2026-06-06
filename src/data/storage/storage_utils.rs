//! Shared I/O utilities for MsgPack-based storage.
//!
//! These functions are split out from `base.rs` to break a circular dependency
//! with `flusher_pool.rs` (which needs the write/backup functions but is imported
//! by base for pool-based Database creation).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn write_to_disk(
    data: &HashMap<String, serde_json::Value>,
    path: &Path,
) -> std::io::Result<()> {
    let encoded =
        rmp_serde::to_vec(data).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let tmp_path = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(&encoded)?;
    }
    fs::rename(&tmp_path, path).or_else(|_| {
        fs::copy(&tmp_path, path)?;
        fs::remove_file(&tmp_path)
    })?;
    Ok(())
}

pub fn create_backup(path: &Path, max_backup_count: usize) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let backup_name = format!("{}.backup_{}.{}", stem, ts, "msgpack");
    let backup_path = path.with_file_name(backup_name);
    let _ = fs::copy(path, &backup_path);

    if let Some(parent) = path.parent() {
        let prefix = format!("{}.backup_", stem);
        let suffix = ".msgpack";
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
