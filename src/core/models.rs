
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationProviderConfig {
    pub provider_type: String,
    pub api_key: String,
    pub enabled: bool,
    #[serde(default)]
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationProviderResult {
    pub provider_name: String,
    pub score: f64,
    pub details: String,
    pub is_listed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedReputationScore {
    pub ip: String,
    pub score: f64,
    pub provider_results: Vec<ReputationProviderResult>,
    pub cached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterRole {
    #[serde(rename = "primary")]
    Primary,
    #[serde(rename = "secondary")]
    Secondary,
    #[serde(rename = "worker")]
    Worker,
}

impl std::fmt::Display for ClusterRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClusterRole::Primary => write!(f, "primary"),
            ClusterRole::Secondary => write!(f, "secondary"),
            ClusterRole::Worker => write!(f, "worker"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    pub id: String,
    pub role: ClusterRole,
    pub ip: String,
    pub status: String,
    pub last_heartbeat: DateTime<Utc>,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafApiKey {
    pub id: String,
    pub key: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub rate_limit: u64,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

impl WafApiKey {
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission || p == "*")
    }
}
