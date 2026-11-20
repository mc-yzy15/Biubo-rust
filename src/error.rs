use std::fmt;

/// Unified error type for Biubo WAF operations.
#[derive(Debug)]
pub enum WafError {
    /// I/O error (file operations, network, etc.)
    IoError(std::io::Error),
    /// Serialization/deserialization error
    SerdeError(String),
}

impl fmt::Display for WafError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WafError::IoError(e) => write!(f, "I/O error: {}", e),
            WafError::SerdeError(s) => write!(f, "Serialization error: {}", s),
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
