use std::fmt;

/// Unified error type for Biubo WAF operations.
#[derive(Debug)]
pub enum WafError {
    /// I/O error (file operations, network, etc.)
    IoError(std::io::Error),
    /// Configuration error
    ConfigError(String),
    /// Storage error
    StorageError(String),
    /// Security error (rate limit, ban, challenge)
    SecurityError(String),
    /// WAF detection error
    DetectionError(String),
    /// Proxy forwarding error
    ProxyError(String),
    /// Plugin error
    PluginError(String),
    /// Serialization/deserialization error
    SerdeError(String),
    /// Generic error with message
    Generic(String),
}

impl fmt::Display for WafError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WafError::IoError(e) => write!(f, "I/O error: {}", e),
            WafError::ConfigError(s) => write!(f, "Configuration error: {}", s),
            WafError::StorageError(s) => write!(f, "Storage error: {}", s),
            WafError::SecurityError(s) => write!(f, "Security error: {}", s),
            WafError::DetectionError(s) => write!(f, "Detection error: {}", s),
            WafError::ProxyError(s) => write!(f, "Proxy error: {}", s),
            WafError::PluginError(s) => write!(f, "Plugin error: {}", s),
            WafError::SerdeError(s) => write!(f, "Serialization error: {}", s),
            WafError::Generic(s) => write!(f, "Error: {}", s),
        }
    }
}

impl std::error::Error for WafError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WafError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for WafError {
    fn from(e: std::io::Error) -> Self {
        WafError::IoError(e)
    }
}

impl From<serde_json::Error> for WafError {
    fn from(e: serde_json::Error) -> Self {
        WafError::SerdeError(e.to_string())
    }
}

/// Result type alias for WAF operations.
pub type WafResult<T> = std::result::Result<T, WafError>;