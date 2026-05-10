use async_trait::async_trait;
use reqwest::Client;
use std::fmt;

use crate::core::models::ReputationProviderResult;

#[derive(Debug)]
pub enum ProviderError {
    HttpError(reqwest::Error),
    DnsError(String),
    ParseError(String),
    TimeoutError,
    ApiError { status: u16, message: String },
    Other(String),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderError::HttpError(e) => write!(f, "HTTP error: {}", e),
            ProviderError::DnsError(e) => write!(f, "DNS error: {}", e),
            ProviderError::ParseError(e) => write!(f, "Parse error: {}", e),
            ProviderError::TimeoutError => write!(f, "Provider query timed out"),
            ProviderError::ApiError { status, message } => {
                write!(f, "API error ({}): {}", status, message)
            }
            ProviderError::Other(e) => write!(f, "Error: {}", e),
        }
    }
}

impl std::error::Error for ProviderError {}

impl From<reqwest::Error> for ProviderError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            ProviderError::TimeoutError
        } else {
            ProviderError::HttpError(e)
        }
    }
}

#[async_trait]
pub trait ReputationProvider: Send + Sync {
    async fn query(&self, ip: &str) -> Result<ReputationProviderResult, ProviderError>;

    fn name(&self) -> &str;

    fn weight(&self) -> f64;
}

pub struct AbuseIPDBProvider {
    client: Client,
    api_key: String,
    weight: f64,
    base_url: String,
}

impl AbuseIPDBProvider {
    pub fn new(api_key: String, weight: f64, base_url: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_default();

        Self {
            client,
            api_key,
            weight,
            base_url: base_url.unwrap_or_else(|| "https://api.abuseipdb.com".to_string()),
        }
    }
}

#[async_trait]
impl ReputationProvider for AbuseIPDBProvider {
    async fn query(&self, ip: &str) -> Result<ReputationProviderResult, ProviderError> {
        let url = format!(
            "{}/api/v2/check?ipAddress={}",
            self.base_url, ip
        );

        let response = self
            .client
            .get(&url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ProviderError::ApiError {
                status: status.as_u16(),
                message: body,
            });
        }

        let json: serde_json::Value = response.json().await?;
        let confidence = json
            .get("data")
            .and_then(|d| d.get("abuseConfidenceScore"))
            .and_then(|s| s.as_f64())
            .unwrap_or(0.0);

        let normalized_score = confidence / 100.0;
        let is_listed = confidence > 50.0;

        Ok(ReputationProviderResult {
            provider_name: self.name().to_string(),
            score: normalized_score,
            details: format!("AbuseIPDB confidence score: {:.1}%", confidence),
            is_listed,
        })
    }

    fn name(&self) -> &str {
        "AbuseIPDB"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}

pub struct GreyNoiseProvider {
    client: Client,
    api_key: String,
    weight: f64,
    base_url: String,
}

impl GreyNoiseProvider {
    pub fn new(api_key: String, weight: f64, base_url: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_default();

        Self {
            client,
            api_key,
            weight,
            base_url: base_url.unwrap_or_else(|| "https://api.greynoise.io".to_string()),
        }
    }

    fn map_verdict_to_score(verdict: &str) -> (f64, bool) {
        match verdict.to_lowercase().as_str() {
            "malicious" => (1.0, true),
            "bad" => (0.8, true),
            "suspicious" => (0.5, true),
            "unknown" => (0.0, false),
            "good" => (0.0, false),
            _ => (0.0, false),
        }
    }
}

#[async_trait]
impl ReputationProvider for GreyNoiseProvider {
    async fn query(&self, ip: &str) -> Result<ReputationProviderResult, ProviderError> {
        let url = format!(
            "{}/v3/community/{}",
            self.base_url, ip
        );

        let response = self
            .client
            .get(&url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ProviderError::ApiError {
                status: status.as_u16(),
                message: body,
            });
        }

        let json: serde_json::Value = response.json().await?;
        let verdict = json
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let (score, is_listed) = Self::map_verdict_to_score(verdict);
        let noise = json
            .get("noise")
            .and_then(|n| n.as_bool())
            .unwrap_or(false);

        let details = format!(
            "GreyNoise verdict: {}, noise: {}",
            verdict, noise
        );

        Ok(ReputationProviderResult {
            provider_name: self.name().to_string(),
            score,
            details,
            is_listed,
        })
    }

    fn name(&self) -> &str {
        "GreyNoise"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}

pub struct VirusTotalProvider {
    client: Client,
    api_key: String,
    weight: f64,
    base_url: String,
}

impl VirusTotalProvider {
    pub fn new(api_key: String, weight: f64, base_url: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_default();

        Self {
            client,
            api_key,
            weight,
            base_url: base_url.unwrap_or_else(|| "https://www.virustotal.com".to_string()),
        }
    }
}

#[async_trait]
impl ReputationProvider for VirusTotalProvider {
    async fn query(&self, ip: &str) -> Result<ReputationProviderResult, ProviderError> {
        let url = format!(
            "{}/api/v3/ip_addresses/{}",
            self.base_url, ip
        );

        let response = self
            .client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ProviderError::ApiError {
                status: status.as_u16(),
                message: body,
            });
        }

        let json: serde_json::Value = response.json().await?;
        let attributes = json
            .get("data")
            .and_then(|d| d.get("attributes"));

        let last_analysis_stats = attributes
            .and_then(|a| a.get("last_analysis_stats"));

        let malicious = last_analysis_stats
            .and_then(|s| s.get("malicious"))
            .and_then(|m| m.as_f64())
            .unwrap_or(0.0);

        let total = last_analysis_stats
            .map(|s| {
                s.as_object()
                    .map(|obj| {
                        obj.values()
                            .filter_map(|v| v.as_f64())
                            .sum::<f64>()
                    })
                    .unwrap_or(0.0)
            })
            .unwrap_or(0.0);

        let malicious_ratio = if total > 0.0 {
            malicious / total
        } else {
            0.0
        };

        let is_listed = malicious > 5.0;

        let details = format!(
            "VirusTotal: {}/{} engines flagged as malicious",
            malicious as u64,
            total as u64
        );

        Ok(ReputationProviderResult {
            provider_name: self.name().to_string(),
            score: malicious_ratio,
            details,
            is_listed,
        })
    }

    fn name(&self) -> &str {
        "VirusTotal"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}

pub struct IPInfoProvider {
    client: Client,
    weight: f64,
    base_url: String,
}

impl IPInfoProvider {
    pub fn new(weight: f64, base_url: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_default();

        Self { client, weight, base_url: base_url.unwrap_or_else(|| "https://ipinfo.io".to_string()) }
    }

    fn calculate_risk_score(
        hosting: bool,
        privacy: bool,
        proxy: bool,
        tor: bool,
    ) -> (f64, bool) {
        let mut score: f64 = 0.0;

        if hosting {
            score += 0.3;
        }
        if privacy {
            score += 0.4;
        }
        if proxy {
            score += 0.5;
        }
        if tor {
            score += 0.8;
        }

        let is_listed = score >= 0.5;
        (score.min(1.0), is_listed)
    }
}

#[async_trait]
impl ReputationProvider for IPInfoProvider {
    async fn query(&self, ip: &str) -> Result<ReputationProviderResult, ProviderError> {
        let url = format!(
            "{}/{}/json",
            self.base_url, ip
        );

        let response = self.client.get(&url).send().await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ProviderError::ApiError {
                status: status.as_u16(),
                message: body,
            });
        }

        let json: serde_json::Value = response.json().await?;
        let privacy = json.get("privacy");

        let hosting = privacy
            .and_then(|p| p.get("hosting"))
            .and_then(|h| h.as_bool())
            .unwrap_or(false);

        let proxy = privacy
            .and_then(|p| p.get("proxy"))
            .and_then(|p| p.as_bool())
            .unwrap_or(false);

        let tor = privacy
            .and_then(|p| p.get("tor"))
            .and_then(|t| t.as_bool())
            .unwrap_or(false);

        let vpn = privacy
            .and_then(|p| p.get("vpn"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let privacy_flag = hosting || proxy || tor || vpn;

        let (score, is_listed) =
            Self::calculate_risk_score(hosting, privacy_flag, proxy, tor);

        let details = format!(
            "IPInfo: hosting={}, proxy={}, tor={}, vpn={}",
            hosting, proxy, tor, vpn
        );

        Ok(ReputationProviderResult {
            provider_name: self.name().to_string(),
            score,
            details,
            is_listed,
        })
    }

    fn name(&self) -> &str {
        "IPInfo"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}

pub struct SpamhausProvider {
    resolver: hickory_resolver::TokioAsyncResolver,
    weight: f64,
}

impl SpamhausProvider {
    pub fn new(weight: f64) -> Self {
        let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()
            .unwrap_or_else(|_| {
                hickory_resolver::TokioAsyncResolver::tokio(
                    hickory_resolver::config::ResolverConfig::default(),
                    hickory_resolver::config::ResolverOpts::default(),
                )
            });

        Self { resolver, weight }
    }

    fn reverse_ip(ip: &str) -> String {
        ip.split('.')
            .rev()
            .collect::<Vec<&str>>()
            .join(".")
    }
}

#[async_trait]
impl ReputationProvider for SpamhausProvider {
    async fn query(&self, ip: &str) -> Result<ReputationProviderResult, ProviderError> {
        let reversed = Self::reverse_ip(ip);
        let query_name = format!("{}.zen.spamhaus.org", reversed);

        let lookup_result = self.resolver.lookup_ip(&query_name).await;

        match lookup_result {
            Ok(lookup) => {
                let addresses: Vec<std::net::IpAddr> = lookup.iter().collect();
                let is_listed = !addresses.is_empty();

                let mut details = String::from("Spamhaus DNSBL: Listed");
                let mut score: f64 = 0.0;

                for addr in &addresses {
                    if let std::net::IpAddr::V4(addr_v4) = addr {
                        let octets = addr_v4.octets();
                        let last_octet = octets[3];

                        match last_octet {
                            2 | 3 => {
                                details.push_str(&format!(", SBL({})", last_octet));
                                score = score.max(0.9);
                            }
                            4..=7 => {
                                details.push_str(&format!(", XBL({})", last_octet));
                                score = score.max(0.95);
                            }
                            10..=11 => {
                                details.push_str(&format!(", PBL({})", last_octet));
                                score = score.max(0.7);
                            }
                            _ => {
                                details.push_str(&format!(", code={}", last_octet));
                                score = score.max(0.5);
                            }
                        }
                    }
                }

                if !is_listed {
                    details = String::from("Spamhaus DNSBL: Not listed");
                    score = 0.0;
                }

                Ok(ReputationProviderResult {
                    provider_name: self.name().to_string(),
                    score,
                    details,
                    is_listed,
                })
            }
            Err(e) => {
                if let hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                    Ok(ReputationProviderResult {
                        provider_name: self.name().to_string(),
                        score: 0.0,
                        details: "Spamhaus DNSBL: Not listed".to_string(),
                        is_listed: false,
                    })
                } else {
                    Err(ProviderError::DnsError(e.to_string()))
                }
            }
        }
    }

    fn name(&self) -> &str {
        "Spamhaus"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}
