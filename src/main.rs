#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use crate::api::app::create_app_with_async_detection;
use crate::config::settings::{Settings, SharedSettings};
use crate::core::engine::async_detection_queue::{
    default_worker_count, start_async_detection_workers,
};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

// These imports are only referenced inside #[cfg(feature = "ssl-support")] blocks.
#[cfg(feature = "ssl-support")]
use axum::routing::get;
#[cfg(feature = "ssl-support")]
use axum::Router;

#[cfg(feature = "ssl-support")]
use crate::services::ssl::SslManager;
#[cfg(feature = "ssl-support")]
use axum::response::Redirect;
#[cfg(feature = "ssl-support")]
use tokio_rustls::server::TlsStream;
#[cfg(feature = "ssl-support")]
use tokio_rustls::TlsAcceptor;

#[cfg(feature = "commercial")]
use ee_license::tui_setup;
#[cfg(feature = "commercial")]
use ee_license::verifier;

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
    let ee_features: Option<ee_license::FeatureGate>;

    #[cfg(feature = "commercial")]
    {
        tracing::info!("Commercial Edition detected, verifying license...");

        // Check if config.json exists → if not, launch TUI setup wizard
        let config_path = std::env::args()
            .find(|a| a == "--config")
            .and_then(|_| {
                std::env::args()
                    .nth(std::env::args().position(|a| a == "--config").unwrap_or(0) + 1)
            })
            .unwrap_or_else(|| "./config.json".to_string());

        if !std::path::Path::new(&config_path).exists()
            && !std::env::args().any(|a| a == "--config")
        {
            tracing::info!("No configuration file found, launching TUI setup wizard...");
            match tui_setup::run_setup_wizard() {
                Ok(Some(setup)) => {
                    // Save config from wizard
                    tracing::info!(
                        "TUI setup wizard completed. License: {:?}",
                        setup.license_path
                    );
                    // TODO: Save setup result to config.json
                }
                Ok(None) => {
                    tracing::info!("TUI setup wizard cancelled by user.");
                    std::process::exit(1);
                }
                Err(e) => {
                    tracing::warn!("TUI setup wizard failed: {}. Continuing with defaults.", e);
                }
            }
        }

        // Locate license file
        let license_path = std::env::args()
            .find(|a| a == "--license-file")
            .and_then(|_| {
                let pos = std::env::args()
                    .position(|a| a == "--license-file")
                    .unwrap_or(0);
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
                eprintln!(
                    "Edition: {} (Licensed: {})",
                    payload.edition, payload.license_id
                );
                let gate = ee_license::FeatureGate::new(&payload.features).unwrap_or_else(|e| {
                    tracing::warn!(
                        "Feature gate warning: {}. Some EE features may be unavailable.",
                        e
                    );
                    ee_license::FeatureGate::new(&[]).expect("empty feature gate always succeeds")
                });
                ee_features = Some(gate);
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
        Ok(s) => {
            // In commercial builds, inject the active feature gate before freezing settings.
            #[cfg(feature = "commercial")]
            let s = {
                let mut s = s;
                s.active_features = ee_features;
                s
            };
            Arc::new(parking_lot::RwLock::new(Arc::new(s)))
        }
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

    #[cfg(feature = "ssl-support")]
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

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

        let redirect_shutdown_rx = shutdown_rx.clone();
        let redirect_server = tokio::spawn(async move {
            if let Err(e) = axum::serve(redirect_listener, redirect_app)
                .with_graceful_shutdown(shutdown_from_watch(redirect_shutdown_rx))
                .await
            {
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

        let mut connections = tokio::task::JoinSet::new();
        let mut shutdown_signal = Box::pin(wait_for_shutdown_signal());
        loop {
            tokio::select! {
                _ = &mut shutdown_signal => {
                    crate::api::routes::internal::mark_draining();
                    shutdown_tx.send_replace(true);
                    break;
                }
                accepted = tls_listener.accept() => {
                    let (tcp_stream, peer_addr) = match accepted {
                        Ok(connection) => connection,
                        Err(e) => {
                            tracing::error!("Failed to accept TLS connection: {}", e);
                            continue;
                        }
                    };
                    let tls_acceptor = tls_acceptor.clone();
                    let app = app.clone();
                    let shutdown_rx = shutdown_rx.clone();
                    connections.spawn(async move {
                        let handshake_shutdown = shutdown_rx.clone();
                        let tls_stream = tokio::select! {
                            result = tls_acceptor.accept(tcp_stream) => match result {
                                Ok(stream) => stream,
                                Err(e) => {
                                    tracing::warn!("TLS handshake failed for {}: {}", peer_addr, e);
                                    return;
                                }
                            },
                            _ = shutdown_from_watch(handshake_shutdown) => return,
                        };

                        if let Err(e) = axum::serve(
                            TlsListenerWrapper {
                                tls_stream: Some(tls_stream),
                                peer_addr,
                            },
                            app,
                        )
                        .with_graceful_shutdown(shutdown_from_watch(shutdown_rx))
                        .await
                        {
                            tracing::error!("TLS connection server error for {}: {}", peer_addr, e);
                        }
                    });
                }
            }
        }

        while let Some(result) = connections.join_next().await {
            if let Err(e) = result {
                tracing::error!("TLS connection task failed: {}", e);
            }
        }

        if let Err(e) = redirect_server.await {
            tracing::error!("HTTP redirect server task failed: {}", e);
        }
        crate::data::storage::manager::flush_all().await;
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

        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                wait_for_shutdown_signal().await;
                crate::api::routes::internal::mark_draining();
            })
            .await
        {
            tracing::error!("Server error: {}", e);
        }
        crate::data::storage::manager::flush_all().await;
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
            .with_graceful_shutdown(async {
                wait_for_shutdown_signal().await;
                crate::api::routes::internal::mark_draining();
            })
            .await
        {
            tracing::error!("Server error: {}", e);
        }
        crate::data::storage::manager::flush_all().await;
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

#[cfg(feature = "ssl-support")]
async fn shutdown_from_watch(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let _ = shutdown.changed().await;
}

async fn wait_for_shutdown_signal() {
    use tokio::signal;

    #[cfg(unix)]
    {
        let mut sigterm = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(signal) => Some(signal),
            Err(e) => {
                tracing::warn!(
                    "Failed to register SIGTERM handler ({}), using only SIGINT",
                    e
                );
                None
            }
        };

        tokio::select! {
            _ = signal::ctrl_c() => tracing::info!("Received SIGINT, shutting down gracefully..."),
            _ = async {
                if let Some(signal) = sigterm.as_mut() {
                    signal.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => tracing::info!("Received SIGTERM, shutting down gracefully..."),
        }
    }

    #[cfg(windows)]
    {
        let mut ctrl_break = match signal::windows::ctrl_break() {
            Ok(signal) => Some(signal),
            Err(e) => {
                tracing::warn!(
                    "Failed to register Ctrl-Break handler ({}), using Ctrl-C",
                    e
                );
                None
            }
        };

        tokio::select! {
            _ = signal::ctrl_c() => tracing::info!("Received Ctrl-C, shutting down gracefully..."),
            _ = async {
                if let Some(signal) = ctrl_break.as_mut() {
                    signal.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => tracing::info!("Received Ctrl-Break, shutting down gracefully..."),
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        if let Err(e) = signal::ctrl_c().await {
            tracing::warn!("Failed to receive Ctrl-C signal: {}", e);
        }
        tracing::info!("Received Ctrl-C, shutting down gracefully...");
    }
}
