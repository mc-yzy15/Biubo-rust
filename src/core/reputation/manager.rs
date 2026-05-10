use std::sync::Arc;
use std::time::Duration;

use crate::core::models::{ReputationProviderConfig, ReputationProviderResult, UnifiedReputationScore};
use crate::core::reputation::providers::{
    AbuseIPDBProvider, GreyNoiseProvider, IPInfoProvider, ReputationProvider, SpamhausProvider,
    VirusTotalProvider,
};

const PROVIDER_TIMEOUT_SECS: u64 = 3;

pub struct ReputationManager {
    providers: Vec<Arc<dyn ReputationProvider>>,
}

impl ReputationManager {
    pub fn new(configs: &[ReputationProviderConfig]) -> Self {
        let mut providers: Vec<Arc<dyn ReputationProvider>> = Vec::new();

        for config in configs {
            if !config.enabled {
                continue;
            }

            match config.provider_type.as_str() {
                "abuseipdb" => {
                    providers.push(Arc::new(AbuseIPDBProvider::new(
                        config.api_key.clone(),
                        1.0,
                        config.base_url.clone(),
                    )));
                }
                "greynoise" => {
                    providers.push(Arc::new(GreyNoiseProvider::new(
                        config.api_key.clone(),
                        1.0,
                        config.base_url.clone(),
                    )));
                }
                "virustotal" => {
                    providers.push(Arc::new(VirusTotalProvider::new(
                        config.api_key.clone(),
                        1.0,
                        config.base_url.clone(),
                    )));
                }
                "ipinfo" => {
                    providers.push(Arc::new(IPInfoProvider::new(
                        1.0,
                        config.base_url.clone(),
                    )));
                }
                "spamhaus" => {
                    providers.push(Arc::new(SpamhausProvider::new(1.0)));
                }
                _ => {
                    tracing::warn!("Unknown reputation provider type: {}", config.provider_type);
                }
            }
        }

        tracing::info!("Initialized {} reputation providers", providers.len());

        Self { providers }
    }

    pub async fn query_all(&self, ip: &str) -> UnifiedReputationScore {
        let mut provider_results = Vec::new();
        let mut total_weight = 0.0;
        let mut weighted_score = 0.0;

        let futures: Vec<_> = self
            .providers
            .iter()
            .map(|provider| {
                let provider_clone = provider.clone();
                let ip_clone = ip.to_string();
                tokio::spawn(async move {
                    let timeout_result = tokio::time::timeout(
                        Duration::from_secs(PROVIDER_TIMEOUT_SECS),
                        provider_clone.query(&ip_clone),
                    )
                    .await;

                    match timeout_result {
                        Ok(result) => match result {
                            Ok(res) => Some(res),
                            Err(e) => {
                                tracing::warn!(
                                    "Provider {} query failed for {}: {}",
                                    provider_clone.name(),
                                    ip_clone,
                                    e
                                );
                                None
                            }
                        },
                        Err(_) => {
                            tracing::warn!(
                                "Provider {} timed out for {}",
                                provider_clone.name(),
                                ip_clone
                            );
                            None
                        }
                    }
                })
            })
            .collect();

        for future in futures {
            match future.await {
                Ok(Some(result)) => {
                    let weight = self
                        .providers
                        .iter()
                        .find(|p| p.name() == result.provider_name)
                        .map(|p| p.weight())
                        .unwrap_or(1.0);

                    weighted_score += result.score * weight;
                    total_weight += weight;
                    provider_results.push(result);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!("Task join error in reputation query: {}", e);
                }
            }
        }

        let final_score = if total_weight > 0.0 {
            weighted_score / total_weight
        } else {
            0.0
        };

        UnifiedReputationScore {
            ip: ip.to_string(),
            score: final_score,
            provider_results,
            cached: false,
        }
    }

    pub async fn query_single(
        &self,
        provider_name: &str,
        ip: &str,
    ) -> Option<ReputationProviderResult> {
        let provider = self
            .providers
            .iter()
            .find(|p| p.name().to_lowercase() == provider_name.to_lowercase())?;

        let timeout_result = tokio::time::timeout(
            Duration::from_secs(PROVIDER_TIMEOUT_SECS),
            provider.query(ip),
        )
        .await;

        match timeout_result {
            Ok(result) => match result {
                Ok(res) => Some(res),
                Err(e) => {
                    tracing::warn!(
                        "Provider {} query failed for {}: {}",
                        provider.name(),
                        ip,
                        e
                    );
                    None
                }
            },
            Err(_) => {
                tracing::warn!("Provider {} timed out for {}", provider.name(), ip);
                None
            }
        }
    }

    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    pub fn provider_names(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.name()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_empty_manager() {
        let manager = ReputationManager::new(&[]);
        assert_eq!(manager.provider_count(), 0);

        let score = manager.query_all("1.2.3.4").await;
        assert_eq!(score.ip, "1.2.3.4");
        assert_eq!(score.score, 0.0);
        assert!(score.provider_results.is_empty());
    }

    #[tokio::test]
    async fn test_disabled_providers() {
        let configs = vec![ReputationProviderConfig {
            provider_type: "abuseipdb".to_string(),
            api_key: "test-key".to_string(),
            enabled: false,
            base_url: None,
        }];

        let manager = ReputationManager::new(&configs);
        assert_eq!(manager.provider_count(), 0);
    }

    #[tokio::test]
    async fn test_unknown_provider_type() {
        let configs = vec![ReputationProviderConfig {
            provider_type: "unknown_provider".to_string(),
            api_key: "test-key".to_string(),
            enabled: true,
            base_url: None,
        }];

        let manager = ReputationManager::new(&configs);
        assert_eq!(manager.provider_count(), 0);
    }
}