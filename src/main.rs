#![allow(unused_imports)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use crate::api::app::create_app_with_async_detection;
use crate::config::settings::{Settings, SharedSettings};
use crate::core::engine::async_detection_queue::{default_worker_count, start_async_detection_workers};
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[cfg(feature = "ssl-support")]
use crate::services::ssl::SslManager;
#[cfg(feature = "ssl-support")]
use axum::response::Redirect;
#[cfg(feature = "ssl-support")]
use tokio_rustls::server::TlsStream;
#[cfg(feature = "ssl-support")]
use tokio_rustls::TlsAcceptor;

#[cfg(feature = "commercial")]
use ee_license::verifier;
#[cfg(feature = "commercial")]
use ee_license::error::LicenseError;
#[cfg(feature = "commercial")]
use ee_license::tui_setup;

mod api;
mod cluster;
mod config;
mod core;
mod data;
mod error;
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

    // ── Commercial Edition: License Verification ──────────────────────
    #[cfg(feature = "commercial")]
    {
        tracing::info!("Commercial Edition detected, verifying license...");

        // Check if config.json exists → if not, launch TUI setup wizard
        let config_path = std::env::args().find(|a| a == "--config")
            .and_then(|_| std::env::args().nth(std::env::args().position(|a| a == "--config").unwrap_or(0) + 1))
            .unwrap_or_else(|| "./config.json".to_string());

        if !std::path::Path::new(&config_path).exists() && !std::env::args().any(|a| a == "--config") {
            tracing::info!("No configuration file found, launching TUI setup wizard...");
            match tui_setup::run_setup_wizard() {
                Ok(Some(setup)) => {
                    // Save config from wizard
                    tracing::info!("TUI setup wizard completed. License: {:?}", setup.license_path);
                    // TODO: Save setup result to config.json
                }
                Ok(None) => {
                    tracing::info!("TUI setup wizard cancelled by user.");
                    std::process::exit(0);
                }
                Err(e) => {
                    tracing::warn!("TUI setup wizard failed: {}. Continuing with defaults.", e);
                }
            }
        }

        // Locate license file
        let license_path = std::env::args().find(|a| a == "--license-file")
            .and_then(|_| {
                let pos = std::env::args().position(|a| a == "--license-file").unwrap_or(0);
                std::env::args().nth(pos + 1)
            })
            .or_else(|| std::env::var("BIUBO_LICENSE_PATH").ok())
            .unwrap_or_else(|| "./biubo-waf-ee.license".to_string());

        let state_dir = std::path::PathBuf::from("./.biubo-license-state");

        match verifier::verify(std::path::Path::new(&license_path), &state_dir) {
            Ok(result) => {
                let payload = &result.payload;
                tracing::info!(
                    "License OK: {} | {} | {} | → {}",
                    payload.license_id,
                    payload.customer_name,
                    payload.edition,
                    payload.end_date.format("%Y-%m-%d")
                );
                eprintln!("Edition: {} (Licensed: {})", payload.edition, payload.license_id);
            }
            Err(e) => {
                tracing::error!("[{}] {}", e.error_id(), e.user_message());
                eprintln!("[{}] {}", e.error_id(), e.user_message());
                std::process::exit(e.exit_code());
            }
        }
    }
    // ── End Commercial Edition ────────────────────────────────────────

    #[cfg(feature = "plugin-system")]
    plugins::init_plugins();

    let settings: SharedSettings = match Settings::load_and_validate() {
        Ok(s) => Arc::new(parking_lot::RwLock::new(Arc::new(s))),
        Err(e) => {
            tracing::error!("Configuration validation failed: {}", e);
            std::process::exit(1);
        }
    };
    let port = settings.read().waf_port;

    #[cfg(feature = "ssl-support")]
    let ssl_enabled = settings.read().ssl_enabled;
    #[cfg(feature = "ssl-support")]
    let ssl_port = settings.read().ssl_port;
    #[cfg(feature = "ssl-support")]
    let ssl_domains = settings.read().ssl_domains.clone();
    #[cfg(feature = "ssl-support")]
    let ssl_acme_email = settings.read().ssl_acme_email.clone();
    #[cfg(feature = "ssl-support")]
    let ssl_cert_dir = settings.read().ssl_cert_dir.clone();

    let session_timeout = settings.read().session_timeout as u64;
    let session_gc_interval = settings.read().session_gc_interval as u64;
    let rate_gc_interval = settings.read().rate_gc_interval as u64;

    core::session::manager::start_session_gc_worker(session_timeout, session_gc_interval);
    core::session::manager::start_log_gc_worker(settings.clone());
    core::security::rate_limit::start_rate_gc_worker(rate_gc_interval);
    core::security::challenge::start_token_gc_worker();
    crate::api::routes::proxy::start_strike_gc_worker();
    core::engine::waf_engine::start_cache_gc_worker();

    let host_count = settings.read().proxy_map.keys().count();
    if host_count > 0 {
        let hosts: Vec<String> = settings.read().proxy_map.keys().cloned().collect();
        core::engine::waf_engine::initialize_waf_cache_background(hosts);
        tracing::info!(
            "WAF cache preloading started for {} hosts (background)",
            host_count
        );
    }

    let worker_count = default_worker_count();
    let async_detection_queue = start_async_detection_workers(worker_count, 1000, settings.clone());

    tracing::info!("Background GC workers started");

    let app = create_app_with_async_detection(settings.clone(), async_detection_queue);

    let shutdown_signal = {
        use tokio::signal;

        #[cfg(unix)]
        let sigterm = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                Box::pin(async move { sig.recv().await; }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            }
            Err(e) => {
                tracing::warn!("Failed to register SIGTERM handler ({}), using only SIGINT", e);
                Box::pin(std::future::pending::<()>()) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            }
        };
        #[cfg(not(unix))]
        let sigterm = Box::pin(std::future::pending::<()>()) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

        async move {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    tracing::info!("Received SIGINT, shutting down gracefully...");
                }
                _ = sigterm => {
                    tracing::info!("Received SIGTERM, shutting down gracefully...");
                }
            }
        }
    };

    #[cfg(feature = "ssl-support")]
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

    #[cfg(not(feature = "ssl-support"))]
    {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        tracing::info!("Serving on host 0.0.0.0, port {}...", port);

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind to {}: {}", addr, e);
                std::process::exit(1);
            }
        };

        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal)
            .await
        {
            tracing::error!("Server error: {}", e);
        }
    }
}

#[cfg(feature = "ssl-support")]
async fn https_redirect_handler(req: axum::extract::Request) -> impl axum::response::IntoResponse {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    Redirect::permanent(&format!("https://{}{}", host, path))
}

#[cfg(feature = "ssl-support")]
struct TlsListenerWrapper {
    tls_stream: Option<TlsStream<tokio::net::TcpStream>>,
    peer_addr: std::net::SocketAddr,
}

#[cfg(feature = "ssl-support")]
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
