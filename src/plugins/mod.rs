
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

/// Trigger all registered exporters with a log entry.
///
/// This function is called when a new log entry is written, allowing
/// plugins to export the data to external systems (e.g., SIEM, databases).
#[cfg(feature = "plugin-system")]
pub async fn trigger_exporters(entry: serde_json::Value) {
    // For now, this is a stub implementation.
    // In a full implementation, this would iterate through registered exporters
    // and call each one with the entry.
    tracing::debug!("Triggering exporters for entry: {:?}", entry.get("request_id"));

    // Placeholder: log the trigger for debugging
    if let Some(request_id) = entry.get("request_id").and_then(|v| v.as_str()) {
        tracing::trace!("Exporter triggered for request: {}", request_id);
    }
}
