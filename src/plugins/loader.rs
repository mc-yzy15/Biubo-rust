use crate::plugins::types::{PluginConfig, PluginInstance, PluginMetadata, PluginType};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PluginFileConfig {
    metadata: PluginMetadata,
    config: PluginConfig,
}

pub struct PluginLoader {
    plugin_dirs: Vec<PathBuf>,
    watch_interval: Duration,
    last_scan: Instant,
}

impl PluginLoader {
    pub fn new(base_dir: &Path) -> Self {
        let detection_dir = base_dir.join("plugins").join("detection");
        let exporter_dir = base_dir.join("plugins").join("exporters");

        Self {
            plugin_dirs: vec![detection_dir, exporter_dir],
            watch_interval: Duration::from_secs(30),
            last_scan: Instant::now(),
        }
    }

    pub fn should_reload(&self) -> bool {
        self.last_scan.elapsed() >= self.watch_interval
    }

    pub fn scan_plugins(&mut self) -> Vec<PluginInstance> {
        self.last_scan = Instant::now();
        let mut plugins = Vec::new();

        for dir in &self.plugin_dirs {
            if !dir.exists() {
                if let Err(e) = fs::create_dir_all(dir) {
                    tracing::warn!("Failed to create plugin directory {}: {}", dir.display(), e);
                }
                continue;
            }

            match fs::read_dir(dir) {
                Ok(entries) => {
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("json") {
                            match self.load_plugin_file(&path) {
                                Ok(plugin) => {
                                    tracing::info!("Loaded plugin: {} ({})", plugin.metadata.name, plugin.metadata.version);
                                    plugins.push(plugin);
                                }
                                Err(e) => {
                                    tracing::error!("Failed to load plugin from {}: {}", path.display(), e);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read plugin directory {}: {}", dir.display(), e);
                }
            }
        }

        tracing::info!("Scanned {} plugins from {} directories", plugins.len(), self.plugin_dirs.len());
        plugins
    }

    fn load_plugin_file(&self, path: &Path) -> Result<PluginInstance, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        let file_config: PluginFileConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse JSON: {}", e))?;

        self.validate_plugin(&file_config)?;

        let plugin = PluginInstance::new(file_config.metadata, file_config.config)
            .with_file_path(path.to_path_buf());

        Ok(plugin)
    }

    fn validate_plugin(&self, config: &PluginFileConfig) -> Result<(), String> {
        if config.metadata.name.is_empty() {
            return Err("Plugin name cannot be empty".to_string());
        }

        if config.metadata.version.is_empty() {
            return Err("Plugin version cannot be empty".to_string());
        }

        match &config.metadata.plugin_type {
            PluginType::Detection => {
                if let PluginConfig::Detection(det_config) = &config.config {
                    if det_config.patterns.is_empty() {
                        return Err("Detection plugin must have at least one pattern".to_string());
                    }
                    if det_config.attack_type.is_empty() {
                        return Err("Detection plugin must specify attack_type".to_string());
                    }
                } else {
                    return Err("Detection plugin requires detection config".to_string());
                }
            }
            PluginType::Exporter => {
                if let PluginConfig::Exporter(exp_config) = &config.config {
                    if exp_config.export_endpoint.is_empty() {
                        return Err("Exporter plugin must specify export_endpoint".to_string());
                    }
                    if exp_config.format.is_empty() {
                        return Err("Exporter plugin must specify format".to_string());
                    }
                } else {
                    return Err("Exporter plugin requires exporter config".to_string());
                }
            }
        }

        Ok(())
    }
}
