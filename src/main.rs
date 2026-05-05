use crate::api::app::create_app;
use crate::config::settings::{Settings, SharedSettings};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod api;
mod config;
mod core;
mod data;
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

    let settings: SharedSettings = Arc::new(parking_lot::RwLock::new(Settings::load()));
    let port = settings.read().waf_port;

    let session_timeout = settings.read().session_timeout as u64;
    let session_gc_interval = settings.read().session_gc_interval as u64;
    let cache_ttl = settings.read().cache_ttl as u64;
    let cache_gc_interval = settings.read().cache_gc_interval as u64;
    let rate_gc_interval = settings.read().rate_gc_interval as u64;

    core::session::manager::start_session_gc_worker(session_timeout, session_gc_interval);
    core::session::manager::start_log_gc_worker(settings.clone());
    core::engine::waf_engine::start_cache_gc_worker(cache_ttl, cache_gc_interval);
    core::security::rate_limit::start_rate_gc_worker(rate_gc_interval);

    tracing::info!("Background GC workers started");

    let app = create_app(settings);

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
