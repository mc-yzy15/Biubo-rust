use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::core::models::{ClusterRole, WafApiKey};
use crate::data::storage::StorageDriverType;

pub type SharedSettings = Arc<RwLock<Settings>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpHeaderConfig {
    pub state: bool,
    pub order: Vec<String>,
    pub trusted_proxies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEngineConfig {
    pub paranoia_level: u8,
    pub rule_paths: Vec<PathBuf>,
    pub crs_auto_update: bool,
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

    pub storage_driver: StorageDriverType,
    pub redis_url: String,
    pub postgres_url: String,

    pub ssl_enabled: bool,
    pub ssl_domains: Vec<String>,
    pub ssl_acme_email: String,
    pub ssl_cert_dir: PathBuf,
    pub ssl_port: u16,

    pub rule_engine: RuleEngineConfig,

    pub ip_reputation_providers: Vec<crate::core::models::ReputationProviderConfig>,

    pub behavior_profiling_enabled: bool,
    pub behavior_window_seconds: u64,

    pub llm_quick_model: String,
    pub llm_quick_base_url: String,
    pub llm_quick_api_key: String,
    pub llm_deep_model: String,
    pub llm_deep_base_url: String,
    pub llm_deep_api_key: String,

    pub cluster_mode: bool,
    pub cluster_role: ClusterRole,
    pub cluster_redis_url: Option<String>,

    pub waf_api_enabled: bool,
    pub waf_api_keys: Vec<WafApiKey>,

    pub auto_patch_enabled: bool,
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
                trusted_proxies: Vec::new(),
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

            storage_driver: StorageDriverType::MsgPack,
            redis_url: String::new(),
            postgres_url: String::new(),

            ssl_enabled: false,
            ssl_domains: Vec::new(),
            ssl_acme_email: String::new(),
            ssl_cert_dir: project_root.join("ssl"),
            ssl_port: 443,

            rule_engine: RuleEngineConfig {
                paranoia_level: 1,
                rule_paths: Vec::new(),
                crs_auto_update: false,
            },

            ip_reputation_providers: Vec::new(),

            behavior_profiling_enabled: false,
            behavior_window_seconds: 3600,

            llm_quick_model: "qwen-turbo".to_string(),
            llm_quick_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1".to_string(),
            llm_quick_api_key: String::new(),
            llm_deep_model: "qwen-plus".to_string(),
            llm_deep_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1".to_string(),
            llm_deep_api_key: String::new(),

            cluster_mode: false,
            cluster_role: ClusterRole::Worker,
            cluster_redis_url: None,

            waf_api_enabled: false,
            waf_api_keys: Vec::new(),

            auto_patch_enabled: false,
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
#[allow(dead_code)]
struct PersistedConfig {
    waf_port: Option<u16>,
    dashboard_password: Option<String>,
    cors_origins: Option<Vec<String>>,
    proxy_map: Option<HashMap<String, String>>,
    dashboard_path: Option<String>,
    api_key: Option<String>,
    llm_model: Option<String>,
    llm_base_url: Option<String>,
    storage_driver: Option<StorageDriverType>,
    redis_url: Option<String>,
    postgres_url: Option<String>,
    ssl_enabled: Option<bool>,
    ssl_domains: Option<Vec<String>>,
    ssl_acme_email: Option<String>,
    ssl_cert_dir: Option<PathBuf>,
    ssl_port: Option<u16>,
    rule_engine: Option<RuleEngineConfig>,
    ip_reputation_providers: Option<Vec<crate::core::models::ReputationProviderConfig>>,
    behavior_profiling_enabled: Option<bool>,
    behavior_window_seconds: Option<u64>,
    llm_quick_model: Option<String>,
    llm_quick_base_url: Option<String>,
    llm_quick_api_key: Option<String>,
    llm_deep_model: Option<String>,
    llm_deep_base_url: Option<String>,
    llm_deep_api_key: Option<String>,
    cluster_mode: Option<bool>,
    cluster_role: Option<ClusterRole>,
    cluster_redis_url: Option<String>,
    waf_api_enabled: Option<bool>,
    waf_api_keys: Option<Vec<WafApiKey>>,
    auto_patch_enabled: Option<bool>,
}

impl Settings {
    pub fn load() -> Self {
        let mut settings = Settings::default();

        settings.load_config_file();
        settings.apply_env_vars();

        settings
    }

    pub fn load_and_validate() -> Result<Self, String> {
        let settings = Self::load();
        settings.validate()?;
        Ok(settings)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.waf_port == 0 {
            return Err("WAF_PORT cannot be 0".to_string());
        }

        if self.ssl_enabled && self.ssl_port == 0 {
            return Err("SSL_PORT cannot be 0 when SSL is enabled".to_string());
        }

        if self.session_timeout <= 0 {
            return Err("SESSION_TIMEOUT must be positive".to_string());
        }

        if self.cache_ttl <= 0 {
            return Err("CACHE_TTL must be positive".to_string());
        }

        if self.rate_limit_per_sec <= 0 {
            return Err("RATE_LIMIT_PER_SEC must be positive".to_string());
        }

        if self.upload_max_size == 0 {
            return Err("UPLOAD_MAX_SIZE cannot be 0".to_string());
        }

        if self.challenge_secret.is_empty() {
            return Err("CHALLENGE_SECRET cannot be empty".to_string());
        }

        if self.challenge_expire <= 0 {
            return Err("CHALLENGE_EXPIRE must be positive".to_string());
        }

        for (host, target) in &self.proxy_map {
            if host.is_empty() {
                return Err("PROXY_MAP contains empty host key".to_string());
            }
            if target.is_empty() {
                return Err(format!("PROXY_MAP[{}] has empty target URL", host));
            }
            if !target.starts_with("http://") && !target.starts_with("https://") {
                return Err(format!("PROXY_MAP[{}] target must start with http:// or https://", host));
            }
        }

        if self.ssl_enabled {
            if self.ssl_domains.is_empty() {
                return Err("SSL_DOMAINS cannot be empty when SSL is enabled".to_string());
            }
            if self.ssl_acme_email.is_empty() {
                return Err("SSL_ACME_EMAIL cannot be empty when SSL is enabled".to_string());
            }
        }

        Ok(())
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
            "LLM_BASE_URL": self.llm_base_url,
            "STORAGE_DRIVER": match self.storage_driver {
                StorageDriverType::MsgPack => "msgpack",
                #[cfg(feature = "redis-support")]
                StorageDriverType::Redis => "redis",
                #[cfg(feature = "postgres-support")]
                StorageDriverType::PostgreSQL => "postgresql",
            },
            "STORAGE_REDIS_URL": self.redis_url,
            "STORAGE_POSTGRES_URL": self.postgres_url,
            "SSL_ENABLED": self.ssl_enabled,
            "SSL_DOMAINS": self.ssl_domains,
            "SSL_ACME_EMAIL": self.ssl_acme_email,
            "SSL_CERT_DIR": self.ssl_cert_dir.to_string_lossy(),
            "SSL_PORT": self.ssl_port
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
                    if let Some(v) = cfg.storage_driver {
                        self.storage_driver = v;
                    }
                    if let Some(v) = cfg.redis_url {
                        self.redis_url = v;
                    }
                    if let Some(v) = cfg.postgres_url {
                        self.postgres_url = v;
                    }
                    if let Some(v) = cfg.ssl_enabled {
                        self.ssl_enabled = v;
                    }
                    if let Some(v) = cfg.ssl_domains {
                        self.ssl_domains = v;
                    }
                    if let Some(v) = cfg.ssl_acme_email {
                        self.ssl_acme_email = v;
                    }
                    if let Some(v) = cfg.ssl_cert_dir {
                        self.ssl_cert_dir = v;
                    }
                    if let Some(v) = cfg.ssl_port {
                        self.ssl_port = v;
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
        if let Ok(v) = env::var("STORAGE_DRIVER") {
            match v.to_lowercase().as_str() {
                "msgpack" => self.storage_driver = StorageDriverType::MsgPack,
                #[cfg(feature = "redis-support")]
                "redis" => self.storage_driver = StorageDriverType::Redis,
                #[cfg(feature = "postgres-support")]
                "postgresql" => self.storage_driver = StorageDriverType::PostgreSQL,
                _ => tracing::warn!("Invalid STORAGE_DRIVER value: {}, using default", v),
            }
        }
        if let Ok(v) = env::var("STORAGE_REDIS_URL") {
            self.redis_url = v;
        }
        if let Ok(v) = env::var("STORAGE_POSTGRES_URL") {
            self.postgres_url = v;
        }
        if let Ok(v) = env::var("SSL_ENABLED") {
            self.ssl_enabled = v.to_lowercase() == "true";
        }
        if let Ok(v) = env::var("SSL_DOMAINS") {
            self.ssl_domains = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }
        if let Ok(v) = env::var("SSL_ACME_EMAIL") {
            self.ssl_acme_email = v;
        }
        if let Ok(v) = env::var("SSL_CERT_DIR") {
            self.ssl_cert_dir = PathBuf::from(v);
        }
        if let Ok(v) = env::var("SSL_PORT") {
            if let Ok(port) = v.parse() {
                self.ssl_port = port;
            }
        }
    }
}
