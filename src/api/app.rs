use crate::api::routes;
use crate::config::settings::{Settings, SharedSettings};
use crate::core::engine::async_detection_queue::AsyncDetectionQueue;
use axum::Router;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

pub type ErrorPages = HashMap<String, String>;

pub struct AppState {
    pub settings: SharedSettings,
    pub error_pages: ErrorPages,
    pub async_detection_queue: Option<AsyncDetectionQueue>,
}

pub fn create_app(settings: SharedSettings) -> Router {
    let error_pages = load_error_pages(&settings.read());

    let state = Arc::new(AppState {
        settings: settings.clone(),
        error_pages,
        async_detection_queue: None,
    });

    let cors = CorsLayer::new()
        .allow_origin(
            settings
                .read()
                .cors_origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect::<Vec<_>>(),
        )
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
            axum::http::Method::PATCH,
            axum::http::Method::HEAD,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
            axum::http::header::ORIGIN,
            axum::http::HeaderName::from_static("x-requested-with"),
            axum::http::header::COOKIE,
        ]);

    let internal_routes = routes::internal::router(state.clone());
    let dashboard_routes = routes::dashboard::router(state.clone());
    let init_routes = routes::init::router(state.clone());
    let proxy_routes = routes::proxy::router(state.clone());

    Router::new()
        .merge(internal_routes)
        .merge(dashboard_routes)
        .merge(init_routes)
        .merge(proxy_routes)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

pub fn create_app_with_async_detection(
    settings: SharedSettings,
    async_detection_queue: AsyncDetectionQueue,
) -> Router {
    let error_pages = load_error_pages(&settings.read());

    let state = Arc::new(AppState {
        settings: settings.clone(),
        error_pages,
        async_detection_queue: Some(async_detection_queue),
    });

    let cors = CorsLayer::new()
        .allow_origin(
            settings
                .read()
                .cors_origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect::<Vec<_>>(),
        )
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
            axum::http::Method::PATCH,
            axum::http::Method::HEAD,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
            axum::http::header::ORIGIN,
            axum::http::HeaderName::from_static("x-requested-with"),
            axum::http::header::COOKIE,
        ]);

    let internal_routes = routes::internal::router(state.clone());
    let dashboard_routes = routes::dashboard::router(state.clone());
    let init_routes = routes::init::router(state.clone());
    let proxy_routes = routes::proxy::router(state.clone());

    Router::new()
        .merge(internal_routes)
        .merge(dashboard_routes)
        .merge(init_routes)
        .merge(proxy_routes)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

fn load_error_pages(settings: &Settings) -> ErrorPages {
    let page_files = [
        ("404", "404.html"),
        ("400", "400.html"),
        ("403", "403.html"),
        ("429", "429.html"),
        ("500", "500.html"),
        ("challenge", "challenge.html"),
        ("captcha", "captcha.html"),
        ("loading", "loading.html"),
    ];

    let mut pages = ErrorPages::new();
    for (key, filename) in &page_files {
        let path = settings.page_root.join(filename);
        match fs::read_to_string(&path) {
            Ok(content) => {
                pages.insert(key.to_string(), content);
            }
            Err(_) => {
                pages.insert(
                    key.to_string(),
                    format!("<h1>{} Error (Template Missing)</h1>", key),
                );
            }
        }
    }
    pages
}
