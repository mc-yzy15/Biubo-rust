use crate::plugins::loader::PluginLoader;
use crate::plugins::types::PluginInstance;
use dashmap::DashMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct PluginRegistry {
    plugins: Arc<DashMap<String, Arc<PluginInstance>>>,
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
        self.plugins.insert(name, Arc::new(plugin));
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
        let mut entry = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| format!("Plugin '{}' not found", name))?;
        // Arc::make_mut performs copy-on-write: outstanding Arc holders keep
        // their snapshot while the registry entry is updated in place.
        Arc::make_mut(&mut entry).enable();
        tracing::info!("Enabled plugin: {}", name);
        Ok(())
    }

    pub fn disable(&self, name: &str) -> Result<(), String> {
        let mut entry = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| format!("Plugin '{}' not found", name))?;
        Arc::make_mut(&mut entry).disable();
        tracing::info!("Disabled plugin: {}", name);
        Ok(())
    }

    pub fn update_config(
        &self,
        name: &str,
        new_config: crate::plugins::types::PluginConfig,
    ) -> Result<(), String> {
        let mut entry = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| format!("Plugin '{}' not found", name))?;
        Arc::make_mut(&mut entry).config = new_config;
        tracing::info!("Updated config for plugin: {}", name);
        Ok(())
    }

    /// Returns a shared reference to the plugin. No deep copy is performed;
    /// callers only pay for an atomic refcount increment.
    pub fn get(&self, name: &str) -> Option<Arc<PluginInstance>> {
        self.plugins.get(name).map(|r| Arc::clone(r.value()))
    }

    pub fn list(&self) -> Vec<Arc<PluginInstance>> {
        self.plugins.iter().map(|r| Arc::clone(r.value())).collect()
    }

    #[cfg(feature = "plugin-system")]
    pub fn reload(&self, loader: &mut PluginLoader) -> usize {
        let new_plugins = loader.scan_plugins();
        let mut reloaded = 0;

        for new_plugin in new_plugins {
            let name = &new_plugin.metadata.name;

            if let Some(mut entry) = self.plugins.get_mut(name) {
                if entry.file_path == new_plugin.file_path {
                    // Preserve status across the reload; Arc::make_mut
                    // copy-on-writes if other holders share this Arc.
                    let plugin = Arc::make_mut(&mut entry);
                    let status = plugin.status.clone();
                    *plugin = new_plugin;
                    plugin.status = status;
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

    #[cfg(feature = "plugin-system")]
    pub fn load_from_directory(
        &self,
        loader: &mut PluginLoader,
        base_dir: &Path,
    ) -> Result<usize, String> {
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
