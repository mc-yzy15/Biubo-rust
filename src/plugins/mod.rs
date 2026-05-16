#![allow(dead_code)]
#![allow(unused_imports)]

#[cfg(feature = "plugin-system")]
pub mod exporter_queue;
pub mod loader;
pub mod registry;
pub mod types;

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::plugins::loader::PluginLoader;
use crate::plugins::registry::PluginRegistry;
use crate::plugins::types::{PluginConfig, PluginType};

#[cfg(feature = "plugin-system")]
use crate::plugins::exporter_queue::{run_exporter_worker, ExporterQueue};

static PLUGIN_REGISTRY: Lazy<PluginRegistry> = Lazy::new(PluginRegistry::new);

#[cfg(feature = "plugin-system")]
static EXPORTER_QUEUE: Lazy<Arc<RwLock<Option<ExporterQueue>>>> =
    Lazy::new(|| Arc::new(RwLock::new(None)));

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

#[cfg(feature = "plugin-system")]
pub fn get_plugin_exporters() -> Vec<(String, crate::plugins::types::LogExporterConfig)> {
    let registry = get_plugin_registry();
    let enabled_plugins = registry.list_enabled();

    enabled_plugins
        .into_iter()
        .filter(|p| p.metadata.plugin_type == PluginType::Exporter)
        .filter_map(|p| {
            if let PluginConfig::Exporter(config) = &p.config {
                Some((p.metadata.name.clone(), config.clone()))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(feature = "plugin-system")]
pub async fn trigger_exporters(log_entry: serde_json::Value) {
    let queue_guard = EXPORTER_QUEUE.read().await;
    if let Some(ref queue) = *queue_guard {
        if !queue.enqueue(log_entry) {
            tracing::warn!("Exporter queue is full, dropping log entry");
        }
    }
}

#[cfg(feature = "plugin-system")]
pub async fn init_exporter_queue_worker() {
    let exporters = get_plugin_exporters();
    if exporters.is_empty() {
        tracing::info!("No exporter plugins registered, skipping exporter queue initialization");
        return;
    }

    tracing::info!("Initializing exporter queue with {} exporter(s)", exporters.len());

    let (queue, receiver) = ExporterQueue::new(None);

    let mut queue_guard = EXPORTER_QUEUE.write().await;
    *queue_guard = Some(queue);
    drop(queue_guard);

    tokio::spawn(async move {
        run_exporter_worker(receiver, exporters).await;
    });
}

#[cfg(feature = "plugin-system")]
pub fn get_plugin_detection_rules() -> HashMap<String, Vec<String>> {
    let mut rules = HashMap::new();

    let enabled_detection_plugins = PLUGIN_REGISTRY
        .list()
        .into_iter()
        .filter(|p| p.metadata.plugin_type == PluginType::Detection && p.is_enabled());

    for plugin in enabled_detection_plugins {
        if let PluginConfig::Detection(config) = &plugin.config {
            let patterns = rules
                .entry(config.attack_type.clone())
                .or_insert_with(Vec::new);
            patterns.extend(config.patterns.clone());
        }
    }

    rules
}
