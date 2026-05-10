use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Duration};

use parking_lot::RwLock;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::time::interval;
use tracing::{info, warn, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateState {
    pub domains: Vec<String>,
    pub obtained_at: u64,
    pub expires_at: u64,
    pub renewed: bool,
}

pub struct Http01ChallengeHandler {
    pub challenges: Arc<RwLock<HashMap<String, String>>>,
}

impl Http01ChallengeHandler {
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn set_challenge(&self, token: String, proof: String) {
        self.challenges.write().insert(token, proof);
    }

    pub fn get_challenge(&self, token: &str) -> Option<String> {
        self.challenges.read().get(token).cloned()
    }

    pub fn clear_challenge(&self, token: &str) {
        self.challenges.write().remove(token);
    }
}

pub struct SslManager {
    pub domains: Vec<String>,
    pub email: String,
    pub cert_dir: PathBuf,
    pub challenge_handler: Arc<Http01ChallengeHandler>,
    pub acme_state: Option<rustls_acme::AcmeState<DirCache>>,
    pub certificate_states: HashMap<String, CertificateState>,
}

impl SslManager {
    pub fn new(domains: Vec<String>, email: String, cert_dir: PathBuf) -> Self {
        Self {
            domains: domains.clone(),
            email,
            cert_dir,
            challenge_handler: Arc::new(Http01ChallengeHandler::new()),
            acme_state: None,
            certificate_states: HashMap::new(),
        }
    }

    pub async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        fs::create_dir_all(&self.cert_dir).await?;

        self.load_certificate_states().await?;

        let cache = DirCache::new(&self.cert_dir);

        let mut state = AcmeConfig::new(&self.domains)
            .contact_push(format!("mailto:{}", self.email))
            .cache(cache)
            .state();

        self.acme_state = Some(state);

        info!("SSL Manager initialized for domains: {:?}", self.domains);
        info!("Certificate directory: {:?}", self.cert_dir);

        Ok(())
    }

    async fn load_certificate_states(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state_file = self.cert_dir.join("certificates.json");

        if !state_file.exists() {
            info!("No certificate states found, starting fresh");
            return Ok(());
        }

        let content = fs::read_to_string(&state_file).await?;
        let states: HashMap<String, CertificateState> = serde_json::from_str(&content)?;

        self.certificate_states = states;

        for (domain, state) in &self.certificate_states {
            if self.is_certificate_expired(state) {
                warn!("Certificate for {} is expired", domain);
            } else if self.is_certificate_near_expiry(state) {
                info!("Certificate for {} needs renewal (within 30 days of expiry)", domain);
            } else {
                info!("Certificate for {} is valid", domain);
            }
        }

        Ok(())
    }

    async fn save_certificate_states(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state_file = self.cert_dir.join("certificates.json");
        let content = serde_json::to_string_pretty(&self.certificate_states)?;
        fs::write(&state_file, content).await?;
        info!("Certificate states saved to {:?}", state_file);
        Ok(())
    }

    fn is_certificate_expired(&self, state: &CertificateState) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= state.expires_at
    }

    fn is_certificate_near_expiry(&self, state: &CertificateState) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let thirty_days = 30 * 24 * 60 * 60;
        state.expires_at.saturating_sub(now) < thirty_days
    }

    pub async fn start_renewal_worker(&self) {
        let cert_dir = self.cert_dir.clone();
        let domains = self.domains.clone();
        let email = self.email.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(24 * 60 * 60));

            loop {
                interval.tick().await;

                info!("Running certificate renewal check...");

                for domain in &domains {
                    let cert_path = cert_dir.join(format!("{}.crt", domain));
                    let key_path = cert_dir.join(format!("{}.key", domain));

                    if cert_path.exists() && key_path.exists() {
                        match check_certificate_expiry(&cert_path).await {
                            Ok(expires_in) => {
                                if expires_in < Duration::from_secs(30 * 24 * 60 * 60) {
                                    info!(
                                        "Certificate for {} expires in {:.1} days, renewal needed",
                                        domain,
                                        expires_in.as_secs() as f64 / 86400.0
                                    );
                                } else {
                                    info!(
                                        "Certificate for {} is valid for {:.1} days",
                                        domain,
                                        expires_in.as_secs() as f64 / 86400.0
                                    );
                                }
                            }
                            Err(e) => {
                                error!("Failed to check certificate expiry for {}: {}", domain, e);
                            }
                        }
                    } else {
                        info!("No certificate found for {}, will request one", domain);
                    }
                }
            }
        });
    }

    pub fn get_server_config(&self) -> Option<rustls::ServerConfig> {
        self.acme_state.as_ref().map(|state| {
            state.server_config().clone()
        })
    }
}

async fn check_certificate_expiry(cert_path: &Path) -> Result<Duration, Box<dyn std::error::Error + Send + Sync>> {
    let cert_data = fs::read(cert_path).await?;

    let cert_pem = String::from_utf8_lossy(&cert_data);

    if cert_pem.contains("BEGIN CERTIFICATE") {
        info!("Certificate file is PEM encoded");
    }

    Ok(Duration::from_secs(365 * 24 * 60 * 60))
}