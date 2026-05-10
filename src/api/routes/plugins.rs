use crate::api::app::AppState;
use crate::plugins::{get_plugin_registry, loader::PluginLoader};
use axum::Router;
use axum::extract::Path;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post, put};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct PluginConfigUpdate {
    config: HashMap<String, serde_json::Value>,
}

pub fn router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(list_plugins))
        .route("/reload", post(reload_plugins))
        .route("/{name}", delete(remove_plugin))
        .route("/{name}/enable", post(enable_plugin))
        .route("/{name}/disable", post(disable_plugin))
        .route("/{name}/config", put(update_plugin_config))
}

async fn list_plugins() -> Response {
    let registry = get_plugin_registry();
    let plugins = registry.list();

    let plugin_list: Vec<serde_json::Value> = plugins
        .iter()
        .map(|p| {
            let status_str = match &p.status {
                crate::plugins::types::PluginStatus::Loaded => "loaded".to_string(),
                crate::plugins::types::PluginStatus::Enabled => "enabled".to_string(),
                crate::plugins::types::PluginStatus::Disabled => "disabled".to_string(),
                crate::plugins::types::PluginStatus::Error(msg) => format!("error: {}", msg),
            };

            let type_str = match &p.metadata.plugin_type {
                crate::plugins::types::PluginType::Detection => "detection".to_string(),
                crate::plugins::types::PluginType::Exporter => "exporter".to_string(),
            };

            json!({
                "name": p.metadata.name,
                "version": p.metadata.version,
                "description": p.metadata.description,
                "author": p.metadata.author,
                "type": type_str,
                "status": status_str,
                "config": serialize_config(&p.config),
            })
        })
        .collect();

    Json(json!({
        "status": "success",
        "data": plugin_list,
        "total": plugin_list.len(),
    }))
    .into_response()
}

async fn enable_plugin(Path(name): Path<String>) -> Response {
    if name.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Plugin name cannot be empty");
    }

    let registry = get_plugin_registry();

    match registry.enable(&name) {
        Ok(()) => Json(json!({
            "status": "success",
            "message": format!("Plugin '{}' enabled", name),
        }))
        .into_response(),
        Err(e) => {
            if e.contains("not found") {
                error_response(StatusCode::NOT_FOUND, &e)
            } else {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, &e)
            }
        }
    }
}

async fn disable_plugin(Path(name): Path<String>) -> Response {
    if name.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Plugin name cannot be empty");
    }

    let registry = get_plugin_registry();

    match registry.disable(&name) {
        Ok(()) => Json(json!({
            "status": "success",
            "message": format!("Plugin '{}' disabled", name),
        }))
        .into_response(),
        Err(e) => {
            if e.contains("not found") {
                error_response(StatusCode::NOT_FOUND, &e)
            } else {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, &e)
            }
        }
    }
}

async fn update_plugin_config(
    Path(name): Path<String>,
    Json(payload): Json<PluginConfigUpdate>,
) -> Response {
    if name.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Plugin name cannot be empty");
    }

    let registry = get_plugin_registry();

    match registry.update_config(&name, crate::plugins::types::PluginConfig::Generic(payload.config)) {
        Ok(()) => Json(json!({
            "status": "success",
            "message": format!("Configuration for plugin '{}' updated", name),
        }))
        .into_response(),
        Err(e) => {
            if e.contains("not found") {
                error_response(StatusCode::NOT_FOUND, &e)
            } else {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, &e)
            }
        }
    }
}

async fn remove_plugin(Path(name): Path<String>) -> Response {
    if name.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Plugin name cannot be empty");
    }

    let registry = get_plugin_registry();
    let plugin = registry.get(&name);

    if let Some(p) = &plugin {
        if let Some(ref file_path) = p.file_path {
            if file_path.exists() {
                if let Err(e) = std::fs::remove_file(file_path) {
                    tracing::warn!("Failed to delete plugin file {}: {}", file_path.display(), e);
                } else {
                    tracing::info!("Deleted plugin file: {}", file_path.display());
                }
            }
        }
    }

    match registry.unregister(&name) {
        Ok(()) => Json(json!({
            "status": "success",
            "message": format!("Plugin '{}' removed", name),
        }))
        .into_response(),
        Err(e) => {
            if e.contains("not found") {
                error_response(StatusCode::NOT_FOUND, &e)
            } else {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, &e)
            }
        }
    }
}

async fn reload_plugins(_state: State<Arc<AppState>>) -> Response {
    let registry = get_plugin_registry();
    let project_root = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let mut loader = PluginLoader::new(&project_root);

    let count = registry.reload(&mut loader);

    Json(json!({
        "status": "success",
        "message": format!("Reloaded {} plugins", count),
        "count": count,
    }))
    .into_response()
}

fn serialize_config(config: &crate::plugins::types::PluginConfig) -> serde_json::Value {
    match config {
        crate::plugins::types::PluginConfig::Detection(det) => json!({
            "type": "detection",
            "patterns": det.patterns,
            "attack_type": det.attack_type,
        }),
        crate::plugins::types::PluginConfig::Exporter(exp) => json!({
            "type": "exporter",
            "export_endpoint": exp.export_endpoint,
            "format": exp.format,
            "batch_size": exp.batch_size,
        }),
        crate::plugins::types::PluginConfig::Generic(map) => json!(map),
    }
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({
            "status": "error",
            "message": message,
        })),
    )
        .into_response()
}
