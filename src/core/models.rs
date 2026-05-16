#![allow(dead_code)]
#![allow(unused_imports)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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

#[cfg(feature = "behavior-profiling")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorMetric {
    pub metric_type: String,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
}

#[cfg(feature = "behavior-profiling")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorProfile {
    pub ip: String,
    pub request_count: u64,
    pub unique_paths: HashSet<String>,
    pub error_count: u64,
    pub user_agents: Vec<String>,
    pub window_start: DateTime<Utc>,
    pub metrics: Vec<BehaviorMetric>,
}

#[cfg(feature = "behavior-profiling")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorScoreBreakdown {
    pub velocity_score: f64,
    pub path_diversity_score: f64,
    pub error_rate_score: f64,
    pub session_consistency_score: f64,
}

#[cfg(feature = "behavior-profiling")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorScore {
    pub ip: String,
    pub score: f64,
    pub velocity_score: f64,
    pub diversity_score: f64,
    pub error_rate_score: f64,
    pub breakdown: BehaviorScoreBreakdown,
    pub factors: Vec<String>,
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

#[derive(Debug, Clone)]
pub struct RateLimiterState {
    pub request_count: u64,
    pub window_start: std::time::Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchSuggestion {
    pub id: String,
    pub detection_id: String,
    pub vulnerability_type: String,
    pub description: String,
    pub root_cause: String,
    pub fix_recommendation: String,
    pub code_example: String,
    pub prevention_tips: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}
