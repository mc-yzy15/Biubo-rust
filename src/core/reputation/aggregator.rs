use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::Mutex;

use crate::core::models::UnifiedReputationScore;
use crate::core::reputation::manager::ReputationManager;

#[derive(Debug, Clone)]
pub struct CachedReputation {
    pub score: UnifiedReputationScore,
    pub cached_at: Instant,
    pub expires_at: Instant,
    pub is_flagged: bool,
}

pub struct ReputationAggregatorConfig {
    pub max_cache_size: usize,
    pub clean_ttl: Duration,
    pub flagged_ttl: Duration,
}

impl Default for ReputationAggregatorConfig {
    fn default() -> Self {
        Self {
            max_cache_size: 100_000,
            clean_ttl: Duration::from_secs(3600),
            flagged_ttl: Duration::from_secs(300),
        }
    }
}

static DEFAULT_WEIGHTS: &[(&str, f64)] = &[
    ("AbuseIPDB", 0.30),
    ("GreyNoise", 0.25),
    ("VirusTotal", 0.20),
    ("Spamhaus", 0.15),
    ("IPInfo", 0.10),
];

pub struct ReputationAggregator {
    cache: DashMap<String, CachedReputation>,
    max_cache_size: usize,
    clean_ttl: Duration,
    flagged_ttl: Duration,
    cleanup_lock: Mutex<()>,
}

impl ReputationAggregator {
    pub fn new(config: ReputationAggregatorConfig) -> Self {
        Self {
            cache: DashMap::new(),
            max_cache_size: config.max_cache_size,
            clean_ttl: config.clean_ttl,
            flagged_ttl: config.flagged_ttl,
            cleanup_lock: Mutex::new(()),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(ReputationAggregatorConfig::default())
    }

    pub async fn aggregate(&self, ip: &str, manager: &ReputationManager) -> UnifiedReputationScore {
        if let Some(entry) = self.cache.get(ip) {
            if entry.value().expires_at > Instant::now() {
                tracing::debug!(ip = ip, "Reputation cache hit");
                let mut cached = entry.value().clone();
                cached.score.cached = true;
                return cached.score;
            }
        }

        let raw_score = manager.query_all(ip).await;

        let mut normalized_results: Vec<(String, f64, f64)> = Vec::new();

        for result in &raw_score.provider_results {
            let normalized = Self::normalize_score(&result.provider_name, result.score);
            let weight = self.get_provider_weight(&result.provider_name);
            normalized_results.push((result.provider_name.clone(), normalized, weight));
        }

        let final_score = if normalized_results.is_empty() {
            0.0
        } else {
            Self::compute_weighted_average(&normalized_results)
        };

        let normalized_providers = raw_score
            .provider_results
            .iter()
            .map(|r| {
                let mut normalized = r.clone();
                normalized.score = Self::normalize_score(&r.provider_name, r.score) / 100.0;
                normalized
            })
            .collect();

        let unified_score = UnifiedReputationScore {
            ip: ip.to_string(),
            score: final_score / 100.0,
            provider_results: normalized_providers,
            cached: false,
        };

        let is_flagged = final_score > 50.0;
        let ttl = if is_flagged {
            self.flagged_ttl
        } else {
            self.clean_ttl
        };

        let cached_entry = CachedReputation {
            score: unified_score.clone(),
            cached_at: Instant::now(),
            expires_at: Instant::now() + ttl,
            is_flagged,
        };

        self.cache.insert(ip.to_string(), cached_entry);

        if self.cache.len() > self.max_cache_size {
            self.enforce_max_cache_size();
        }

        tracing::info!(
            ip = ip,
            score = final_score,
            is_flagged = is_flagged,
            "Reputation aggregated and cached"
        );

        unified_score
    }

    pub fn normalize_score(provider: &str, raw_score: f64) -> f64 {
        match provider {
            "AbuseIPDB" => {
                (raw_score * 100.0).clamp(0.0, 100.0)
            }
            "GreyNoise" => {
                let score_100 = raw_score * 100.0;
                if score_100 >= 99.0 {
                    100.0
                } else if score_100 >= 79.0 {
                    60.0
                } else if score_100 >= 1.0 {
                    0.0
                } else {
                    20.0
                }
            }
            "VirusTotal" => {
                (raw_score * 100.0).clamp(0.0, 100.0)
            }
            "Spamhaus" => {
                if raw_score > 0.0 {
                    100.0
                } else {
                    0.0
                }
            }
            "IPInfo" => {
                if raw_score > 0.0 {
                    50.0
                } else {
                    0.0
                }
            }
            _ => {
                (raw_score * 100.0).clamp(0.0, 100.0)
            }
        }
    }

    pub fn compute_weighted_average(results: &[(String, f64, f64)]) -> f64 {
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        for (_provider, score, weight) in results {
            weighted_sum += score * weight;
            total_weight += weight;
        }

        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        }
    }

    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let mut removed_count = 0;

        let expired_keys: Vec<String> = self
            .cache
            .iter()
            .filter(|entry| entry.value().expires_at <= now)
            .map(|entry| entry.key().clone())
            .collect();

        for key in &expired_keys {
            self.cache.remove(key);
            removed_count += 1;
        }

        if removed_count > 0 {
            tracing::info!(
                removed = removed_count,
                remaining = self.cache.len(),
                "Cleaned up expired reputation cache entries"
            );
        }

        removed_count
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    pub fn cache_hits(&self, ip: &str) -> bool {
        if let Some(entry) = self.cache.get(ip) {
            entry.value().expires_at > Instant::now()
        } else {
            false
        }
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
        tracing::info!("Reputation cache cleared");
    }

    fn get_provider_weight(&self, provider_name: &str) -> f64 {
        DEFAULT_WEIGHTS
            .iter()
            .find(|(name, _)| *name == provider_name)
            .map(|(_, weight)| *weight)
            .unwrap_or(1.0)
    }

    fn enforce_max_cache_size(&self) {
        if self.cache.len() <= self.max_cache_size {
            return;
        }

        let mut entries: Vec<(String, Instant)> = self
            .cache
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().cached_at))
            .collect();

        entries.sort_by_key(|(_, cached_at)| *cached_at);

        let excess = self.cache.len() - self.max_cache_size;
        for (key, _) in entries.iter().take(excess) {
            self.cache.remove(key);
        }

        tracing::info!(
            removed = excess,
            max_size = self.max_cache_size,
            "Enforced max cache size, removed oldest entries"
        );
    }
}

#[cfg(test)]
mod aggregator_tests {
    use super::*;
    use mockito::Server;

    use crate::core::models::ReputationProviderConfig;

    #[test]
    fn test_normalize_abuseipdb() {
        assert!((ReputationAggregator::normalize_score("AbuseIPDB", 0.8) - 80.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("AbuseIPDB", 0.0) - 0.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("AbuseIPDB", 1.0) - 100.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("AbuseIPDB", 0.45) - 45.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_normalize_greynoise() {
        assert!((ReputationAggregator::normalize_score("GreyNoise", 1.0) - 100.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("GreyNoise", 0.8) - 60.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("GreyNoise", 0.0) - 20.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("GreyNoise", 0.5) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_normalize_virustotal() {
        assert!((ReputationAggregator::normalize_score("VirusTotal", 0.75) - 75.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("VirusTotal", 0.0) - 0.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("VirusTotal", 1.0) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_normalize_spamhaus() {
        assert!((ReputationAggregator::normalize_score("Spamhaus", 1.0) - 100.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("Spamhaus", 0.9) - 100.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("Spamhaus", 0.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_normalize_ipinfo() {
        assert!((ReputationAggregator::normalize_score("IPInfo", 0.3) - 50.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("IPInfo", 0.8) - 50.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("IPInfo", 0.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_normalize_unknown_provider() {
        assert!((ReputationAggregator::normalize_score("UnknownProvider", 0.5) - 50.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("CustomProvider", 0.75) - 75.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_weighted_average_single_provider() {
        let results = vec![
            ("AbuseIPDB".to_string(), 80.0, 0.30),
        ];
        let avg = ReputationAggregator::compute_weighted_average(&results);
        assert!((avg - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_weighted_average_multiple_providers() {
        let results = vec![
            ("AbuseIPDB".to_string(), 80.0, 0.30),
            ("GreyNoise".to_string(), 100.0, 0.25),
            ("VirusTotal".to_string(), 50.0, 0.20),
            ("Spamhaus".to_string(), 100.0, 0.15),
            ("IPInfo".to_string(), 50.0, 0.10),
        ];
        let avg = ReputationAggregator::compute_weighted_average(&results);
        let expected = (80.0 * 0.30 + 100.0 * 0.25 + 50.0 * 0.20 + 100.0 * 0.15 + 50.0 * 0.10)
            / (0.30 + 0.25 + 0.20 + 0.15 + 0.10);
        assert!((avg - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn test_weighted_average_empty_results() {
        let results: Vec<(String, f64, f64)> = vec![];
        let avg = ReputationAggregator::compute_weighted_average(&results);
        assert!((avg - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_weighted_average_zero_weights() {
        let results = vec![
            ("Custom".to_string(), 50.0, 0.0),
            ("Other".to_string(), 80.0, 0.0),
        ];
        let avg = ReputationAggregator::compute_weighted_average(&results);
        assert!((avg - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_cache_miss_triggers_query() {
        let mut server = Server::new_async().await;

        let _mock = server
            .mock("GET", "/api/v2/check")
            .match_query("ipAddress=1.2.3.4")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"
            {
                "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 75,
                    "totalReports": 10,
                    "lastReportedAt": "2024-01-01T00:00:00Z"
                }
            }
            "#)
            .create_async()
            .await;

        let configs = vec![ReputationProviderConfig {
            provider_type: "abuseipdb".to_string(),
            api_key: "test-key".to_string(),
            enabled: true,
            base_url: Some(server.url()),
        }];

        let manager = ReputationManager::new(&configs);
        let aggregator = ReputationAggregator::with_defaults();

        assert!(!aggregator.cache_hits("1.2.3.4"));

        let score = aggregator.aggregate("1.2.3.4", &manager).await;

        assert_eq!(score.ip, "1.2.3.4");
        assert!(!score.cached);
        assert!(aggregator.cache_hits("1.2.3.4"));
    }

    #[tokio::test]
    async fn test_cache_hit_returns_cached_result() {
        let mut server = Server::new_async().await;

        let _mock = server
            .mock("GET", "/api/v2/check")
            .match_query("ipAddress=5.6.7.8")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"
            {
                "data": {
                    "ipAddress": "5.6.7.8",
                    "abuseConfidenceScore": 50,
                    "totalReports": 5,
                    "lastReportedAt": "2024-01-01T00:00:00Z"
                }
            }
            "#)
            .create_async()
            .await;

        let configs = vec![ReputationProviderConfig {
            provider_type: "abuseipdb".to_string(),
            api_key: "test-key".to_string(),
            enabled: true,
            base_url: Some(server.url()),
        }];

        let manager = ReputationManager::new(&configs);
        let aggregator = ReputationAggregator::with_defaults();

        let score1 = aggregator.aggregate("5.6.7.8", &manager).await;
        assert!(!score1.cached);

        let score2 = aggregator.aggregate("5.6.7.8", &manager).await;
        assert!(score2.cached);

        assert!((score1.score - score2.score).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let mut server = Server::new_async().await;

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let _mock = server
            .mock("GET", "/api/v2/check")
            .match_query("ipAddress=9.10.11.12")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"
            {
                "data": {
                    "ipAddress": "9.10.11.12",
                    "abuseConfidenceScore": 90,
                    "totalReports": 100,
                    "lastReportedAt": "2024-01-01T00:00:00Z"
                }
            }
            "#)
            .expect_at_least(2)
            .create_async()
            .await;

        let configs = vec![ReputationProviderConfig {
            provider_type: "abuseipdb".to_string(),
            api_key: "test-key".to_string(),
            enabled: true,
            base_url: Some(server.url()),
        }];

        let manager = ReputationManager::new(&configs);

        let mut config = ReputationAggregatorConfig::default();
        config.flagged_ttl = Duration::from_millis(100);
        let aggregator = ReputationAggregator::new(config);

        let _score1 = aggregator.aggregate("9.10.11.12", &manager).await;
        call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        tokio::time::sleep(Duration::from_millis(150)).await;

        let _score2 = aggregator.aggregate("9.10.11.12", &manager).await;
        call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        assert_eq!(aggregator.cache_size(), 1);
    }

    #[test]
    fn test_cleanup_expired() {
        let aggregator = ReputationAggregator::with_defaults();

        let now = Instant::now();

        let valid_entry = CachedReputation {
            score: create_test_score("1.1.1.1", 30.0),
            cached_at: now,
            expires_at: now + Duration::from_secs(3600),
            is_flagged: false,
        };
        aggregator.cache.insert("1.1.1.1".to_string(), valid_entry);

        let expired_entry = CachedReputation {
            score: create_test_score("2.2.2.2", 80.0),
            cached_at: now - Duration::from_secs(3700),
            expires_at: now - Duration::from_secs(100),
            is_flagged: true,
        };
        aggregator.cache.insert("2.2.2.2".to_string(), expired_entry);

        assert_eq!(aggregator.cache_size(), 2);

        let removed = aggregator.cleanup_expired();

        assert_eq!(removed, 1);
        assert_eq!(aggregator.cache_size(), 1);
        assert!(aggregator.cache_hits("1.1.1.1"));
        assert!(!aggregator.cache_hits("2.2.2.2"));
    }

    #[tokio::test]
    async fn test_max_cache_size_enforcement() {
        let mut server = Server::new_async().await;

        for i in 0..15 {
            let ip = format!("10.0.0.{}", i);
            let body = format!(
                r#"{{"data": {{"ipAddress": "{}", "abuseConfidenceScore": 10, "totalReports": 1, "lastReportedAt": "2024-01-01T00:00:00Z"}}}}"#,
                ip
            );
            let _mock = server
                .mock("GET", "/api/v2/check")
                .match_query(format!("ipAddress={}", ip).as_str())
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(&body)
                .create_async()
                .await;
        }

        let configs = vec![ReputationProviderConfig {
            provider_type: "abuseipdb".to_string(),
            api_key: "test-key".to_string(),
            enabled: true,
            base_url: Some(server.url()),
        }];

        let manager = ReputationManager::new(&configs);

        let mut config = ReputationAggregatorConfig::default();
        config.max_cache_size = 10;
        let aggregator = ReputationAggregator::new(config);

        for i in 0..15 {
            let ip = format!("10.0.0.{}", i);
            let _score = aggregator.aggregate(&ip, &manager).await;
        }

        assert!(aggregator.cache_size() <= 10);
    }

    #[test]
    fn test_is_flagged_threshold() {
        let aggregator = ReputationAggregator::with_defaults();

        let flagged_entry = CachedReputation {
            score: create_test_score("3.3.3.3", 75.0),
            cached_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(300),
            is_flagged: true,
        };
        aggregator.cache.insert("3.3.3.3".to_string(), flagged_entry);

        let clean_entry = CachedReputation {
            score: create_test_score("4.4.4.4", 20.0),
            cached_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(3600),
            is_flagged: false,
        };
        aggregator.cache.insert("4.4.4.4".to_string(), clean_entry);

        let flagged = aggregator.cache.get("3.3.3.3").unwrap();
        assert!(flagged.value().is_flagged);

        let clean = aggregator.cache.get("4.4.4.4").unwrap();
        assert!(!clean.value().is_flagged);
    }

    #[test]
    fn test_clear_cache() {
        let aggregator = ReputationAggregator::with_defaults();

        for i in 0..5 {
            let entry = CachedReputation {
                score: create_test_score(&format!("5.5.5.{}", i), 50.0),
                cached_at: Instant::now(),
                expires_at: Instant::now() + Duration::from_secs(3600),
                is_flagged: false,
            };
            aggregator.cache.insert(format!("5.5.5.{}", i), entry);
        }

        assert_eq!(aggregator.cache_size(), 5);

        aggregator.clear_cache();

        assert_eq!(aggregator.cache_size(), 0);
    }

    #[tokio::test]
    async fn test_aggregate_with_multiple_providers() {
        let mut server1 = Server::new_async().await;
        let mut server2 = Server::new_async().await;

        let _mock1 = server1
            .mock("GET", "/api/v2/check")
            .match_query("ipAddress=7.8.9.10")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"
            {
                "data": {
                    "ipAddress": "7.8.9.10",
                    "abuseConfidenceScore": 60,
                    "totalReports": 30,
                    "lastReportedAt": "2024-01-01T00:00:00Z"
                }
            }
            "#)
            .create_async()
            .await;

        let _mock2 = server2
            .mock("GET", "/v3/community/7.8.9.10")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"
            {
                "ip": "7.8.9.10",
                "verdict": "malicious",
                "noise": true,
                "spoofable": false
            }
            "#)
            .create_async()
            .await;

        let configs = vec![
            ReputationProviderConfig {
                provider_type: "abuseipdb".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: Some(server1.url()),
            },
            ReputationProviderConfig {
                provider_type: "greynoise".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: Some(server2.url()),
            },
        ];

        let manager = ReputationManager::new(&configs);
        let aggregator = ReputationAggregator::with_defaults();

        let score = aggregator.aggregate("7.8.9.10", &manager).await;

        assert_eq!(score.ip, "7.8.9.10");
        assert_eq!(score.provider_results.len(), 2);

        assert_eq!(score.provider_results.len(), 2);

        let abuseipdb_result = score
            .provider_results
            .iter()
            .find(|r| r.provider_name == "AbuseIPDB")
            .unwrap();
        let greynoise_result = score
            .provider_results
            .iter()
            .find(|r| r.provider_name == "GreyNoise")
            .unwrap();

        assert!((abuseipdb_result.score - 0.6).abs() < 0.01);
        assert!((greynoise_result.score - 1.0).abs() < 0.01);

        let expected_normalized = (60.0 * 0.30 + 100.0 * 0.25) / (0.30 + 0.25);
        assert!((score.score - expected_normalized / 100.0).abs() < 0.01);
    }

    #[test]
    fn test_score_clamping() {
        assert!((ReputationAggregator::normalize_score("AbuseIPDB", 1.5) - 100.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("AbuseIPDB", -0.5) - 0.0).abs() < f64::EPSILON);
        assert!((ReputationAggregator::normalize_score("VirusTotal", 2.0) - 100.0).abs() < f64::EPSILON);
    }

    fn create_test_score(ip: &str, score: f64) -> UnifiedReputationScore {
        UnifiedReputationScore {
            ip: ip.to_string(),
            score: score / 100.0,
            provider_results: vec![],
            cached: false,
        }
    }
}
