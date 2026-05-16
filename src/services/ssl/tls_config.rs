#![allow(dead_code)]

#[cfg(feature = "ssl-support")]
use std::path::PathBuf;
#[cfg(feature = "ssl-support")]
use std::sync::Arc;

#[cfg(feature = "ssl-support")]
use rustls::ServerConfig;
#[cfg(feature = "ssl-support")]
use rustls_acme::caches::DirCache;
#[cfg(feature = "ssl-support")]
use rustls_acme::AcmeConfig;
#[cfg(feature = "ssl-support")]
use rustls_acme::AcmeState;
#[cfg(feature = "ssl-support")]
use tokio_rustls::TlsAcceptor;
#[cfg(feature = "ssl-support")]
use tracing::info;

#[cfg(feature = "ssl-support")]
pub fn build_tls_config_from_files(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::CertificateDer;
    use std::fs;
    use std::io::BufReader;

    let cert_file = fs::File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    let key_file = fs::File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or("No private key found")?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    info!("TLS configuration loaded from certificate files");
    Ok(config)
}

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

#[cfg(feature = "ssl-support")]
pub struct TlsConfig {
    pub server_config: ServerConfig,
    pub port: u16,
}

#[cfg(feature = "ssl-support")]
impl TlsConfig {
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(Arc::new(self.server_config.clone()))
    }
}
