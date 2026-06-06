
pub mod loader;
pub mod registry;
pub mod types;

use once_cell::sync::Lazy;
use std::path::PathBuf;

use crate::plugins::loader::PluginLoader;
use crate::plugins::registry::PluginRegistry;

static PLUGIN_REGISTRY: Lazy<PluginRegistry> = Lazy::new(PluginRegistry::new);

pub fn get_plugin_registry() -> &'static PluginRegistry {
    &PLUGIN_REGISTRY
}

#[cfg(feature = "plugin-system")]
pub fn init_plugins() {
    tracing::info!("Initializing plugin system...");

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut loader = PluginLoader::new(&project_root);

    match PLUGIN_REGISTRY.load_from_directory(&mut loader, &project_root) {
        Ok(count) => {
            tracing::info!("Plugin system initialized with {} plugins", count);
        }
        Err(e) => {
            tracing::error!("Failed to initialize plugin system: {}", e);
        }
    }
}
