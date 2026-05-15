use crate::api::app::create_app_with_async_detection;
use crate::config::settings::{Settings, SharedSettings};
use crate::core::engine::async_detection_queue::start_async_detection_workers;
use crate::services::ssl::SslManager;
use axum::response::Redirect;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

mod api;
mod cluster;
mod config;
mod core;
mod data;
mod plugins;
mod services;
mod utils;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Starting Biubo WAF Protective Proxy (Rust Edition)...");

    plugins::init_plugins();

    let settings: SharedSettings = Arc::new(parking_lot::RwLock::new(Settings::load()));
    let port = settings.read().waf_port;

    let ssl_enabled = settings.read().ssl_enabled;
    let ssl_port = settings.read().ssl_port;
    let ssl_domains = settings.read().ssl_domains.clone();
    let ssl_acme_email = settings.read().ssl_acme_email.clone();
    let ssl_cert_dir = settings.read().ssl_cert_dir.clone();

    let session_timeout = settings.read().session_timeout as u64;
    let session_gc_interval = settings.read().session_gc_interval as u64;
    let cache_ttl = settings.read().cache_ttl as u64;
    let cache_gc_interval = settings.read().cache_gc_interval as u64;
    let rate_gc_interval = settings.read().rate_gc_interval as u64;

    core::session::manager::start_session_gc_worker(session_timeout, session_gc_interval);
    core::session::manager::start_log_gc_worker(settings.clone());
    core::engine::waf_engine::start_cache_gc_worker(cache_ttl, cache_gc_interval);
    core::security::rate_limit::start_rate_gc_worker(rate_gc_interval);

    let host_count = settings.read().proxy_map.keys().count();
    if host_count > 0 {
        let hosts: Vec<String> = settings.read().proxy_map.keys().cloned().collect();
        core::engine::waf_engine::initialize_waf_cache_background(hosts);
        tracing::info!(
            "WAF cache preloading started for {} hosts (background)",
            host_count
        );
    }

    let async_detection_queue = start_async_detection_workers(4, 1000, settings.clone());

    tracing::info!("Background GC workers started");

    let app = create_app_with_async_detection(settings.clone(), async_detection_queue);

    if ssl_enabled && !ssl_domains.is_empty() && !ssl_acme_email.is_empty() {
        tracing::info!("HTTPS mode enabled on port {}", ssl_port);

        let redirect_app = Router::new()
            .route("/{*path}", get(https_redirect_handler))
            .with_state(());

        let redirect_addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        let redirect_listener = match tokio::net::TcpListener::bind(redirect_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    "Failed to bind HTTP redirect listener to {}: {}",
                    redirect_addr,
                    e
                );
                std::process::exit(1);
            }
        };

        tracing::info!("HTTP redirect server serving on 0.0.0.0:{} -> HTTPS", port);

        tokio::spawn(async move {
            if let Err(e) = axum::serve(redirect_listener, redirect_app).await {
                tracing::error!("HTTP redirect server error: {}", e);
            }
        });

        let mut ssl_manager = SslManager::new(ssl_domains, ssl_acme_email, ssl_cert_dir);

        if let Err(e) = ssl_manager.initialize().await {
            tracing::error!("Failed to initialize SSL manager: {}", e);
            std::process::exit(1);
        }

        ssl_manager.start_renewal_worker().await;

        let tls_addr = std::net::SocketAddr::from(([0, 0, 0, 0], ssl_port));
        let tls_listener = match tokio::net::TcpListener::bind(tls_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind TLS listener to {}: {}", tls_addr, e);
                std::process::exit(1);
            }
        };

        tracing::info!("HTTPS server serving on 0.0.0.0:{}...", ssl_port);

        let tls_acceptor = TlsAcceptor::from(Arc::new(
            ssl_manager
                .get_server_config()
                .expect("TLS config not available"),
        ));

        loop {
            let (tcp_stream, peer_addr) = match tls_listener.accept().await {
                Ok(tuple) => tuple,
                Err(e) => {
                    tracing::error!("Failed to accept TLS connection: {}", e);
                    continue;
                }
            };

            let tls_acceptor = tls_acceptor.clone();
            let app = app.clone();

            tokio::spawn(async move {
                match tls_acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        let _ = axum::serve(
                            TlsListenerWrapper {
                                tls_stream: Some(tls_stream),
                                peer_addr,
                            },
                            app,
                        )
                        .await;
                    }
                    Err(e) => {
                        tracing::warn!("TLS handshake failed for {}: {}", peer_addr, e);
                    }
                }
            });
        }
    } else {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        tracing::info!("Serving on host 0.0.0.0, port {}...", port);

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind to {}: {}", addr, e);
                std::process::exit(1);
            }
        };

        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Server error: {}", e);
        }
    }
}

async fn https_redirect_handler() -> impl axum::response::IntoResponse {
    Redirect::permanent("https://localhost")
}

struct TlsListenerWrapper {
    tls_stream: Option<TlsStream<tokio::net::TcpStream>>,
    peer_addr: std::net::SocketAddr,
}

impl axum::serve::Listener for TlsListenerWrapper {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        if let Some(stream) = self.tls_stream.take() {
            (stream, self.peer_addr)
        } else {
            std::future::pending().await
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.peer_addr)
    }
}
