use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PluginType {
    Detection,
    Exporter,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PluginStatus {
    Loaded,
    Enabled,
    Disabled,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    #[serde(rename = "type")]
    pub plugin_type: PluginType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRuleConfig {
    pub patterns: Vec<String>,
    pub attack_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogExporterConfig {
    pub export_endpoint: String,
    pub format: String,
    pub batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PluginConfig {
    Detection(DetectionRuleConfig),
    Exporter(LogExporterConfig),
    Generic(HashMap<String, serde_json::Value>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInstance {
    pub metadata: PluginMetadata,
    pub config: PluginConfig,
    pub status: PluginStatus,
    pub file_path: Option<PathBuf>,
}

impl PluginInstance {
    pub fn new(metadata: PluginMetadata, config: PluginConfig) -> Self {
        Self {
            metadata,
            config,
            status: PluginStatus::Loaded,
            file_path: None,
        }
    }

    pub fn with_file_path(mut self, path: PathBuf) -> Self {
        self.file_path = Some(path);
        self
    }

    pub fn is_enabled(&self) -> bool {
        matches!(self.status, PluginStatus::Enabled)
    }

    pub fn enable(&mut self) {
        self.status = PluginStatus::Enabled;
    }

    pub fn disable(&mut self) {
        self.status = PluginStatus::Disabled;
    }

    pub fn set_error(&mut self, message: String) {
        self.status = PluginStatus::Error(message);
    }
}

impl PluginMetadata {
    pub fn new(name: &str, version: &str, description: &str, author: &str, plugin_type: PluginType) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            description: description.to_string(),
            author: author.to_string(),
            plugin_type,
        }
    }
}
