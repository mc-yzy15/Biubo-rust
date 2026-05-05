use crate::api::app::AppState;
use crate::data::storage::manager::get_db;
use crate::utils::compression::decompress_json;
use crate::utils::query_parser::{evaluate, parse};
use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct GreetingRequest {
    #[allow(dead_code)]
    ts: Option<String>,
    ip: Option<String>,
    visitor_id: Option<String>,
    browser_info: Option<Value>,
    request_id: Option<String>,
    host: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ScreenRequest {
    #[allow(dead_code)]
    ts: Option<String>,
    events: Option<Vec<Value>>,
    request_id: Option<String>,
    host: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SearchQuery {
    statement: Option<String>,
    host: Option<String>,
    #[allow(dead_code)]
    date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HostQuery {
    host: Option<String>,
    ip: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpQuery {
    ip: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GeocodeQuery {
    city: Option<String>,
    country: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DateQuery {
    host: Option<String>,
    date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RrwebQuery {
    host: Option<String>,
    #[allow(dead_code)]
    date: Option<String>,
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WhitelistRequest {
    host: Option<String>,
    ip: Option<String>,
    remark: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BanRequest {
    host: Option<String>,
    ip: Option<String>,
    reason: Option<String>,
    expire: Option<u32>,
}

pub fn router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/scripts/biubo/beacon.js", get(beacon))
        .route("/handle/biubo/greeting", post(greeting))
        .route("/handle/biubo/screen", post(receive_screen_data))
        .route("/info/biubo/system", get(system_info))
        .route("/info/biubo/waf", get(waf_info))
        .route("/info/biubo/setting", post(waf_setting))
        .route("/info/biubo/location", get(server_location))
        .route("/api/biubo/ipinfo", get(ipinfo))
        .route("/api/biubo/geocode", get(geocode))
        .route("/info/biubo/log", get(waf_log))
        .route("/info/biubo/rrweb", get(waf_rrweb))
        .route("/info/biubo/search", get(waf_search))
        .route("/info/biubo/blacklist", get(waf_blacklist))
        .route("/info/biubo/unban", get(waf_unban))
        .route("/info/biubo/whitelist", get(waf_whitelist))
        .route("/info/biubo/remove_whitelist", get(waf_remove_whitelist))
        .route("/info/biubo/add_whitelist", post(add_whitelist))
        .route("/info/biubo/ban", post(add_blacklist))
}

async fn beacon(State(state): State<Arc<AppState>>) -> Response {
    let path = state.settings.read().template_root.join("beacon.js");
    match std::fs::read_to_string(&path) {
        Ok(content) => (
            StatusCode::OK,
            [("Content-Type", "application/javascript")],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "console.error('Beacon JS missing')").into_response(),
    }
}

async fn greeting(
    State(_state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<GreetingRequest>,
) -> Response {
    let request_id = match &payload.request_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => return Json(json!({"status": "error", "msg": "request_id required"})).into_response(),
    };
    let host = match &payload.host {
        Some(h) if !h.is_empty() => h.clone(),
        _ => return Json(json!({"status": "error", "msg": "host required"})).into_response(),
    };

    let mut updates = std::collections::HashMap::new();

    if let Some(ip) = &payload.ip {
        let info = crate::utils::http_utils::get_ip_info(ip).await;
        if let Some(country) = info
            .get("country")
            .or(info.get("countryName"))
            .and_then(|v| v.as_str())
        {
            updates.insert("country".to_string(), serde_json::json!(country));
        }
        if let Some(city) = info
            .get("city")
            .or(info.get("cityName"))
            .and_then(|v| v.as_str())
        {
            updates.insert("city".to_string(), serde_json::json!(city));
        }
        updates.insert("cdn_ip".to_string(), serde_json::json!(ip));
    }

    if let Some(vid) = &payload.visitor_id {
        updates.insert("fingerprint".to_string(), serde_json::json!(vid));
    }

    if let Some(bi) = &payload.browser_info {
        updates.insert("browser_info".to_string(), bi.clone());
    }

    if !updates.is_empty() {
        crate::core::session::manager::update_session_log(&request_id, &host, updates);
    }

    Json(json!({"status": "success"})).into_response()
}

async fn receive_screen_data(
    State(_state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<ScreenRequest>,
) -> Response {
    let request_id = match &payload.request_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => return Json(json!({"status": "error", "msg": "request_id required"})).into_response(),
    };
    let host = match &payload.host {
        Some(h) if !h.is_empty() => h.clone(),
        _ => return Json(json!({"status": "error", "msg": "host required"})).into_response(),
    };
    let events = payload.events.unwrap_or_default();

    if !events.is_empty() {
        crate::core::session::manager::update_rrweb_events(&request_id, &host, events);
    }

    Json(json!({"status": "success"})).into_response()
}

async fn system_info(State(_state): State<Arc<AppState>>) -> Response {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu_percent = sys.global_cpu_usage();
    let cpu_cores = sys.cpus().len();

    let total_mem_gb = sys.total_memory() as f64 / (1024.0_f64.powi(3));
    let used_mem_gb = sys.used_memory() as f64 / (1024.0_f64.powi(3));
    let mem_percent = if sys.total_memory() > 0 {
        (sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0
    } else {
        0.0
    };

    Json(json!({
        "status": "success",
        "data": {
            "os": format!("{} {}", System::name().unwrap_or_default(), System::os_version().unwrap_or_default()),
            "cpu": {
                "percent": cpu_percent,
                "cores": cpu_cores,
            },
            "memory": {
                "total_gb": (total_mem_gb * 100.0).round() / 100.0,
                "used_gb": (used_mem_gb * 100.0).round() / 100.0,
                "percent": (mem_percent * 100.0).round() / 100.0,
            },
        }
    }))
    .into_response()
}

async fn waf_info(State(_state): State<Arc<AppState>>, Query(query): Query<HostQuery>) -> Response {
    let host = query.host.unwrap_or_default();
    if host.is_empty() {
        return Json(json!({"status": "error", "msg": "host required"})).into_response();
    }

    let db = get_db(&host);
    let ram_data: serde_json::Map<String, Value> = {
        let security = db.ram_get("security").unwrap_or(json!({}));
        let site = db.ram_get("site").unwrap_or(json!({}));
        let analytics = db.ram_get("analytics").unwrap_or(json!({}));
        let mut map = serde_json::Map::new();
        map.insert("security".into(), security);
        map.insert("site".into(), site);
        map.insert("analytics".into(), analytics);
        map
    };

    Json(json!({
        "status": "success",
        "data": ram_data
    }))
    .into_response()
}

async fn waf_setting(
    State(_state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<Value>,
) -> Response {
    let host = payload.get("host").and_then(|v| v.as_str()).unwrap_or("");
    if host.is_empty() {
        return Json(json!({"status": "error", "msg": "host required"})).into_response();
    }

    let db = get_db(host);

    if let Some(description) = payload.get("description").and_then(|v| v.as_str()) {
        let mut site = db
            .ram_get("site")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        site.insert("description".into(), json!(description));
        db.ram_set("site", Value::Object(site));
    }

    if let Some(domain) = payload.get("domain").and_then(|v| v.as_str()) {
        let mut site = db
            .ram_get("site")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        site.insert("domain".into(), json!(domain));
        db.ram_set("site", Value::Object(site));
    }

    if let Some(status) = payload.get("status").and_then(|v| v.as_str()) {
        let mut site = db
            .ram_get("site")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        site.insert("status".into(), json!(status));
        db.ram_set("site", Value::Object(site));
    }

    Json(json!({"status": "success"})).into_response()
}

async fn server_location(State(_state): State<Arc<AppState>>) -> Response {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let ip_info: Value = match client.get("https://ipinfo.io/json").send().await {
        Ok(resp) => resp.json().await.unwrap_or(json!({})),
        Err(_) => json!({}),
    };

    let ip = ip_info
        .get("ip")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let country = ip_info
        .get("country")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let city = ip_info
        .get("city")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let region = ip_info
        .get("region")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    Json(json!({
        "status": "success",
        "data": {
            "ip": ip,
            "country": country,
            "city": city,
            "region": region,
        }
    }))
    .into_response()
}

async fn ipinfo(Query(query): Query<IpQuery>) -> Response {
    let ip = query.ip.unwrap_or_default();
    if ip.is_empty() {
        return Json(json!({"status": "error", "msg": "ip required"})).into_response();
    }

    let info = crate::utils::http_utils::get_ip_info(&ip).await;
    Json(json!({"status": "success", "data": info})).into_response()
}

async fn geocode(Query(query): Query<GeocodeQuery>) -> Response {
    let city = query.city.unwrap_or_default();
    let country = query.country.unwrap_or_default();

    if city.is_empty() && country.is_empty() {
        return Json(json!({"status": "error", "msg": "city or country required"})).into_response();
    }

    let info = crate::utils::http_utils::get_geo_info(&city, &country).await;
    Json(json!({"status": "success", "data": info})).into_response()
}

async fn waf_log(State(_state): State<Arc<AppState>>, Query(query): Query<DateQuery>) -> Response {
    let host = query.host.unwrap_or_default();
    let _date = query
        .date
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());

    if host.is_empty() {
        return Json(json!({"status": "error", "msg": "host required"})).into_response();
    }

    let db = get_db(&host);
    let _ = db.ensure_log_db();

    let log_db = match db.get_log_db() {
        Some(ldb) => ldb,
        None => return Json(json!({"status": "success", "data": []})).into_response(),
    };

    let logs = log_db
        .get("logs")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let overview = log_db.get("overview").unwrap_or(json!({}));

    Json(json!({
        "status": "success",
        "data": {
            "logs": logs,
            "overview": overview,
        }
    }))
    .into_response()
}

async fn waf_rrweb(
    State(_state): State<Arc<AppState>>,
    Query(query): Query<RrwebQuery>,
) -> Response {
    let host = query.host.unwrap_or_default();
    let id = query.id.unwrap_or_default();

    if host.is_empty() || id.is_empty() {
        return Json(json!({"status": "error", "msg": "host and id required"})).into_response();
    }

    let db = get_db(&host);
    let log_db = match db.get_log_db() {
        Some(ldb) => ldb,
        None => return Json(json!({"status": "success", "data": null})).into_response(),
    };

    let logs = log_db
        .get("logs")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let entry = logs
        .iter()
        .find(|e| e.get("request_id").and_then(|v| v.as_str()) == Some(&id));

    let rrweb = entry
        .and_then(|e| e.get("rrweb").cloned())
        .unwrap_or(json!(null));

    let events = if rrweb.is_string() {
        let bytes = rrweb.as_str().unwrap_or("").as_bytes();
        let decoded = decompress_json(bytes);
        decoded.get("events").cloned().unwrap_or(json!([]))
    } else if rrweb.is_object() {
        rrweb.get("events").cloned().unwrap_or(json!([]))
    } else {
        json!([])
    };

    Json(json!({"status": "success", "data": events})).into_response()
}

async fn waf_search(
    State(_state): State<Arc<AppState>>,
    Query(query): Query<SearchQuery>,
) -> Response {
    let host = query.host.unwrap_or_default();
    let statement = query.statement.unwrap_or_default();

    if host.is_empty() {
        return Json(json!({"status": "error", "msg": "host required"})).into_response();
    }

    let db = get_db(&host);
    let log_db = match db.get_log_db() {
        Some(ldb) => ldb,
        None => return Json(json!({"status": "success", "data": []})).into_response(),
    };

    let logs = log_db
        .get("logs")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    if statement.is_empty() {
        return Json(json!({"status": "success", "data": logs})).into_response();
    }

    let ast = match parse(&statement) {
        Ok(a) => a,
        Err(e) => {
            return Json(json!({"status": "error", "msg": format!("Parse error: {}", e)}))
                .into_response();
        }
    };

    let results: Vec<Value> = logs.iter().filter(|r| evaluate(&ast, r)).cloned().collect();

    Json(json!({"status": "success", "data": results})).into_response()
}

async fn waf_blacklist(
    State(_state): State<Arc<AppState>>,
    Query(query): Query<HostQuery>,
) -> Response {
    let host = query.host.unwrap_or_default();
    if host.is_empty() {
        return Json(json!({"status": "error", "msg": "host required"})).into_response();
    }

    let db = get_db(&host);
    let blacklist = db
        .ram_get("security")
        .and_then(|v| v.get("blacklist").cloned())
        .unwrap_or(json!({}));

    Json(json!({"status": "success", "data": blacklist})).into_response()
}

async fn waf_unban(
    State(_state): State<Arc<AppState>>,
    Query(query): Query<HostQuery>,
) -> Response {
    let host = query.host.unwrap_or_default();
    let ip = query.ip.unwrap_or_default();

    if host.is_empty() || ip.is_empty() {
        return Json(json!({"status": "error", "msg": "host and ip required"})).into_response();
    }

    let db = get_db(&host);
    let removed = db.unban_ip(&ip);

    if removed {
        Json(json!({"status": "success"})).into_response()
    } else {
        Json(json!({"status": "error", "msg": "IP not in blacklist"})).into_response()
    }
}

async fn waf_whitelist(
    State(_state): State<Arc<AppState>>,
    Query(query): Query<HostQuery>,
) -> Response {
    let host = query.host.unwrap_or_default();
    if host.is_empty() {
        return Json(json!({"status": "error", "msg": "host required"})).into_response();
    }

    let db = get_db(&host);
    let whitelist = db
        .ram_get("security")
        .and_then(|v| v.get("whitelist").cloned())
        .unwrap_or(json!({}));

    Json(json!({"status": "success", "data": whitelist})).into_response()
}

async fn waf_remove_whitelist(
    State(_state): State<Arc<AppState>>,
    Query(query): Query<HostQuery>,
) -> Response {
    let host = query.host.unwrap_or_default();
    let ip = query.ip.unwrap_or_default();

    if host.is_empty() || ip.is_empty() {
        return Json(json!({"status": "error", "msg": "host and ip required"})).into_response();
    }

    let db = get_db(&host);
    let removed = db.remove_whitelist(&ip);

    if removed {
        Json(json!({"status": "success"})).into_response()
    } else {
        Json(json!({"status": "error", "msg": "IP not in whitelist"})).into_response()
    }
}

async fn add_whitelist(
    State(_state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<WhitelistRequest>,
) -> Response {
    let host = payload.host.unwrap_or_default();
    let ip = payload.ip.unwrap_or_default();
    let remark = payload.remark.unwrap_or_else(|| "manual".to_string());

    if host.is_empty() || ip.is_empty() {
        return Json(json!({"status": "error", "msg": "host and ip required"})).into_response();
    }

    let db = get_db(&host);
    db.add_whitelist(&ip, &remark);

    Json(json!({"status": "success"})).into_response()
}

async fn add_blacklist(
    State(_state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<BanRequest>,
) -> Response {
    let host = payload.host.unwrap_or_default();
    let ip = payload.ip.unwrap_or_default();
    let reason = payload.reason.unwrap_or_else(|| "manual".to_string());

    if host.is_empty() || ip.is_empty() {
        return Json(json!({"status": "error", "msg": "host and ip required"})).into_response();
    }

    let db = get_db(&host);
    db.ban_ip(&ip, &reason, payload.expire).await;

    Json(json!({"status": "success"})).into_response()
}
