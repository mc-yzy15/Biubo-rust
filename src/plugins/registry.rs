use crate::plugins::loader::PluginLoader;
use crate::plugins::types::{PluginInstance, PluginStatus, PluginType};
use dashmap::DashMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct PluginRegistry {
    plugins: Arc<DashMap<String, PluginInstance>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(DashMap::new()),
        }
    }

    pub fn register(&self, plugin: PluginInstance) -> Result<(), String> {
        let name = plugin.metadata.name.clone();
        if self.plugins.contains_key(&name) {
            return Err(format!("Plugin '{}' already registered", name));
        }
        self.plugins.insert(name, plugin);
        Ok(())
    }

    pub fn unregister(&self, name: &str) -> Result<(), String> {
        if self.plugins.remove(name).is_none() {
            return Err(format!("Plugin '{}' not found", name));
        }
        tracing::info!("Unregistered plugin: {}", name);
        Ok(())
    }

    pub fn enable(&self, name: &str) -> Result<(), String> {
        let mut plugin = self.plugins.get_mut(name)
            .ok_or_else(|| format!("Plugin '{}' not found", name))?;
        plugin.enable();
        tracing::info!("Enabled plugin: {}", name);
        Ok(())
    }

    pub fn disable(&self, name: &str) -> Result<(), String> {
        let mut plugin = self.plugins.get_mut(name)
            .ok_or_else(|| format!("Plugin '{}' not found", name))?;
        plugin.disable();
        tracing::info!("Disabled plugin: {}", name);
        Ok(())
    }

    pub fn update_config(&self, name: &str, new_config: crate::plugins::types::PluginConfig) -> Result<(), String> {
        let mut plugin = self.plugins.get_mut(name)
            .ok_or_else(|| format!("Plugin '{}' not found", name))?;
        plugin.config = new_config;
        tracing::info!("Updated config for plugin: {}", name);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<PluginInstance> {
        self.plugins.get(name).map(|r| r.value().clone())
    }

    pub fn list(&self) -> Vec<PluginInstance> {
        self.plugins.iter().map(|r| r.value().clone()).collect()
    }

    pub fn list_by_type(&self, plugin_type: &PluginType) -> Vec<PluginInstance> {
        self.plugins.iter()
            .filter(|r| &r.value().metadata.plugin_type == plugin_type)
            .map(|r| r.value().clone())
            .collect()
    }

    pub fn list_enabled(&self) -> Vec<PluginInstance> {
        self.plugins.iter()
            .filter(|r| r.value().is_enabled())
            .map(|r| r.value().clone())
            .collect()
    }

    pub fn reload(&self, loader: &mut PluginLoader) -> usize {
        let new_plugins = loader.scan_plugins();
        let mut reloaded = 0;

        for new_plugin in new_plugins {
            let name = &new_plugin.metadata.name;

            if let Some(existing) = self.plugins.get(name) {
                if existing.value().file_path == new_plugin.file_path {
                    let mut existing = self.plugins.get_mut(name).unwrap();
                    let status = existing.status.clone();
                    *existing.value_mut() = new_plugin;
                    existing.status = status;
                    reloaded += 1;
                }
            } else {
                let _ = self.register(new_plugin);
                reloaded += 1;
            }
        }

        tracing::info!("Reloaded {} plugins", reloaded);
        reloaded
    }

    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    pub fn load_from_directory(&self, loader: &mut PluginLoader, base_dir: &Path) -> Result<usize, String> {
        let plugins = loader.scan_plugins();
        let count = plugins.len();

        for plugin in plugins {
            if let Err(e) = self.register(plugin) {
                tracing::warn!("Failed to register plugin: {}", e);
            }
        }

        tracing::info!("Loaded {} plugins from {}", count, base_dir.display());
        Ok(count)
    }
}
