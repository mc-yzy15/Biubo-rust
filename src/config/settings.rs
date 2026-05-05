use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub type SharedSettings = Arc<RwLock<Settings>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpHeaderConfig {
    pub state: bool,
    pub order: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub waf_port: u16,
    pub dashboard_password: String,
    pub cors_origins: Vec<String>,

    pub host_forward: bool,
    pub proxy_map: HashMap<String, String>,

    pub api_key: String,
    pub llm_model: String,
    pub llm_base_url: String,

    pub session_timeout: i64,
    pub cache_ttl: i64,
    pub session_gc_interval: i64,
    pub cache_gc_interval: i64,

    pub get_ip_from_headers: IpHeaderConfig,
    pub rate_limit_per_sec: i64,
    pub rate_ban_threshold: i64,
    pub rate_ban_duration_min: i64,
    pub rate_gc_interval: i64,

    #[serde(skip)]
    pub static_extensions: HashSet<String>,

    pub project_root: PathBuf,
    pub db_root: PathBuf,
    pub template_root: PathBuf,
    pub page_root: PathBuf,

    pub challenge_secret: String,
    pub challenge_expire: i64,

    pub upload_max_size: usize,
    #[serde(skip)]
    pub upload_allowed_extensions: HashSet<String>,

    pub dashboard_path: String,

    pub log_auto_delete: bool,
    pub log_retention_days: i64,
    pub log_retain: String,
}

fn generate_challenge_secret() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    hex::encode(hasher.finalize())
}

fn generate_random_password() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    hasher.update(chrono::Utc::now().timestamp().to_string().as_bytes());
    hex::encode(hasher.finalize())[..16].to_string()
}

impl Default for Settings {
    fn default() -> Self {
        let project_root = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

        let default_password = generate_random_password();

        Settings {
            waf_port: 80,
            dashboard_password: default_password,
            cors_origins: vec!["http://ip.zplb.org.cn:7000".to_string()],

            host_forward: false,
            proxy_map: HashMap::new(),

            api_key: String::new(),
            llm_model: "qwen-plus".to_string(),
            llm_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1".to_string(),

            session_timeout: 20,
            cache_ttl: 3600,
            session_gc_interval: 5,
            cache_gc_interval: 30,

            get_ip_from_headers: IpHeaderConfig {
                state: true,
                order: vec![
                    "CF-Connecting-IP".to_string(),
                    "X-Real-IP".to_string(),
                    "X-Forwarded-For".to_string(),
                ],
            },
            rate_limit_per_sec: 15,
            rate_ban_threshold: 30,
            rate_ban_duration_min: 60,
            rate_gc_interval: 10,

            static_extensions: DEFAULT_STATIC_EXTENSIONS
                .iter()
                .map(|s| s.to_string())
                .collect(),

            project_root: project_root.clone(),
            db_root: project_root.join("data"),
            template_root: project_root.join("templates"),
            page_root: project_root.join("page"),

            challenge_secret: generate_challenge_secret(),
            challenge_expire: 3600,

            upload_max_size: 10 * 1024 * 1024,
            upload_allowed_extensions: DEFAULT_UPLOAD_EXTENSIONS
                .iter()
                .map(|s| s.to_string())
                .collect(),

            dashboard_path: "/biubo-cgi".to_string(),

            log_auto_delete: false,
            log_retention_days: 30,
            log_retain: "type:hacker".to_string(),
        }
    }
}

const DEFAULT_STATIC_EXTENSIONS: &[&str] = &[
    ".js", ".css", ".png", ".jpg", ".jpeg", ".ico", ".woff", ".woff2", ".svg", ".gif", ".webp",
];

const DEFAULT_UPLOAD_EXTENSIONS: &[&str] = &[
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff", ".pdf", ".doc",
    ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".md", ".csv", ".zip", ".tar", ".gz", ".7z",
    ".rar", ".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct PersistedConfig {
    waf_port: Option<u16>,
    dashboard_password: Option<String>,
    cors_origins: Option<Vec<String>>,
    proxy_map: Option<HashMap<String, String>>,
    dashboard_path: Option<String>,
    api_key: Option<String>,
    llm_model: Option<String>,
    llm_base_url: Option<String>,
}

impl Settings {
    pub fn load() -> Self {
        let mut settings = Settings::default();

        settings.load_config_file();
        settings.apply_env_vars();

        settings
    }

    pub fn is_initialized(&self) -> bool {
        !self.proxy_map.is_empty()
    }

    pub fn save_config(&self) {
        let config_path = self.project_root.join("config.json");
        let config_data = serde_json::json!({
            "WAF_PORT": self.waf_port,
            "DASHBOARD_PASSWORD": self.dashboard_password,
            "CORS_ORIGINS": self.cors_origins,
            "PROXY_MAP": self.proxy_map,
            "DASHBOARD_PATH": self.dashboard_path,
            "API_KEY": self.api_key,
            "LLM_MODEL": self.llm_model,
            "LLM_BASE_URL": self.llm_base_url
        });

        match fs::write(
            &config_path,
            serde_json::to_string_pretty(&config_data).unwrap_or_default(),
        ) {
            Ok(_) => tracing::info!("Configuration saved to {:?}", config_path),
            Err(e) => tracing::error!("Failed to save config.json: {}", e),
        }
    }

    fn load_config_file(&mut self) {
        let config_path = self.project_root.join("config.json");
        if !config_path.exists() {
            return;
        }

        match fs::read_to_string(&config_path) {
            Ok(content) => match serde_json::from_str::<PersistedConfig>(&content) {
                Ok(cfg) => {
                    if let Some(v) = cfg.waf_port {
                        self.waf_port = v;
                    }
                    if let Some(v) = cfg.dashboard_password {
                        self.dashboard_password = v;
                    }
                    if let Some(v) = cfg.cors_origins {
                        self.cors_origins = v;
                    }
                    if let Some(v) = cfg.proxy_map {
                        self.proxy_map = v;
                    }
                    if let Some(v) = cfg.dashboard_path {
                        self.dashboard_path = v;
                    }
                    if let Some(v) = cfg.api_key {
                        self.api_key = v;
                    }
                    if let Some(v) = cfg.llm_model {
                        self.llm_model = v;
                    }
                    if let Some(v) = cfg.llm_base_url {
                        self.llm_base_url = v;
                    }
                }
                Err(e) => tracing::error!("Failed to parse config.json: {}", e),
            },
            Err(e) => tracing::error!("Failed to load config.json: {}", e),
        }
    }

    fn apply_env_vars(&mut self) {
        if let Ok(v) = env::var("WAF_PORT") {
            if let Ok(port) = v.parse() {
                self.waf_port = port;
            }
        }
        if let Ok(v) = env::var("WAF_DASHBOARD_PASSWORD") {
            self.dashboard_password = v;
        }
        if let Ok(v) = env::var("WAF_CORS_ORIGINS") {
            if let Ok(origins) = serde_json::from_str(&v) {
                self.cors_origins = origins;
            }
        }
        if let Ok(v) = env::var("WAF_API_KEY") {
            self.api_key = v;
        }
        if let Ok(v) = env::var("WAF_LLM_MODEL") {
            self.llm_model = v;
        }
        if let Ok(v) = env::var("WAF_LLM_BASE_URL") {
            self.llm_base_url = v;
        }
        if let Ok(v) = env::var("WAF_SESSION_TIMEOUT") {
            if let Ok(val) = v.parse() {
                self.session_timeout = val;
            }
        }
        if let Ok(v) = env::var("WAF_CACHE_TTL") {
            if let Ok(val) = v.parse() {
                self.cache_ttl = val;
            }
        }
        if let Ok(v) = env::var("WAF_SESSION_GC_INTERVAL") {
            if let Ok(val) = v.parse() {
                self.session_gc_interval = val;
            }
        }
        if let Ok(v) = env::var("WAF_CACHE_GC_INTERVAL") {
            if let Ok(val) = v.parse() {
                self.cache_gc_interval = val;
            }
        }
        if let Ok(v) = env::var("WAF_TRUST_HEADERS") {
            self.get_ip_from_headers.state = v.to_lowercase() == "true";
        }
        if let Ok(v) = env::var("WAF_IP_HEADER_ORDER") {
            if let Ok(order) = serde_json::from_str(&v) {
                self.get_ip_from_headers.order = order;
            }
        }
        if let Ok(v) = env::var("WAF_RATE_LIMIT") {
            if let Ok(val) = v.parse() {
                self.rate_limit_per_sec = val;
            }
        }
        if let Ok(v) = env::var("WAF_BAN_THRESHOLD") {
            if let Ok(val) = v.parse() {
                self.rate_ban_threshold = val;
            }
        }
        if let Ok(v) = env::var("WAF_BAN_DURATION") {
            if let Ok(val) = v.parse() {
                self.rate_ban_duration_min = val;
            }
        }
        if let Ok(v) = env::var("WAF_RATE_GC_INTERVAL") {
            if let Ok(val) = v.parse() {
                self.rate_gc_interval = val;
            }
        }
        if let Ok(v) = env::var("WAF_CHALLENGE_SECRET") {
            self.challenge_secret = v;
        }
        if let Ok(v) = env::var("WAF_CHALLENGE_EXPIRE") {
            if let Ok(val) = v.parse() {
                self.challenge_expire = val;
            }
        }
        if let Ok(v) = env::var("WAF_MAX_UPLOAD_SIZE") {
            if let Ok(val) = v.parse() {
                self.upload_max_size = val;
            }
        }
        if let Ok(v) = env::var("WAF_DASHBOARD_PATH") {
            self.dashboard_path = v;
        }
        if let Ok(v) = env::var("WAF_LOG_AUTO_DELETE") {
            self.log_auto_delete = v.to_lowercase() == "true";
        }
        if let Ok(v) = env::var("WAF_LOG_RETENTION_DAYS") {
            if let Ok(val) = v.parse() {
                self.log_retention_days = val;
            }
        }
        if let Ok(v) = env::var("WAF_LOG_RETAIN_LIST") {
            self.log_retain = v;
        }
    }
}
