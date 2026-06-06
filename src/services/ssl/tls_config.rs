
#[cfg(feature = "ssl-support")]
use std::path::PathBuf;

#[cfg(feature = "ssl-support")]
use rustls::ServerConfig;
#[cfg(feature = "ssl-support")]
use rustls_acme::caches::DirCache;
#[cfg(feature = "ssl-support")]
use rustls_acme::AcmeConfig;
#[cfg(feature = "ssl-support")]
use rustls_acme::AcmeState;
#[cfg(feature = "ssl-support")]
use tracing::info;

#[cfg(feature = "ssl-support")]
pub fn build_acme_tls_config(
    domains: Vec<String>,
    email: String,
    cert_dir: PathBuf,
) -> Result<
    (ServerConfig, AcmeState<std::io::Error, std::io::Error>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let cache = DirCache::new(cert_dir);

    let state = AcmeConfig::new(&domains)
        .contact_push(format!("mailto:{}", email))
        .cache(cache)
        .state();

    let server_config = (*state.default_rustls_config()).clone();

    info!("ACME TLS configuration created for domains: {:?}", domains);
    Ok((server_config, state))
}


