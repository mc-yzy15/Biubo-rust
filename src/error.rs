use thiserror::Error;

#[derive(Debug, Error)]
pub enum WafError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Security error: {0}")]
    Security(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("IP is banned")]
    IpBanned,

    #[error("Challenge verification failed")]
    ChallengeFailed,

    #[error("SSRF attempt detected: {0}")]
    SSRFDetected(String),

    #[error("Request too large: {0} bytes")]
    RequestTooLarge(usize),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Regex error: {0}")]
    Regex(String),

    #[error("LLM error: {0}")]
    Llm(String),

    #[error("Plugin error: {0}")]
    Plugin(String),

    #[error("Cluster error: {0}")]
    Cluster(String),
}

impl From<regex::Error> for WafError {
    fn from(e: regex::Error) -> Self {
        WafError::Regex(e.to_string())
    }
}

impl From<reqwest::Error> for WafError {
    fn from(e: reqwest::Error) -> Self {
        WafError::Http(e.to_string())
    }
}

pub type WafResult<T> = Result<T, WafError>;

pub trait ErrorContext<T> {
    fn context(self, msg: &str) -> WafResult<T>;
    fn with_context<F: FnOnce() -> String>(self, f: F) -> WafResult<T>;
}

impl<T> ErrorContext<T> for Result<T, std::io::Error> {
    fn context(self, msg: &str) -> WafResult<T> {
        self.map_err(|e| WafError::Io(e)).map_err(|e| {
            if let WafError::Io(io_err) = e {
                WafError::Internal(format!("{}: {}", msg, io_err))
            } else {
                e
            }
        })
    }

    fn with_context<F: FnOnce() -> String>(self, f: F) -> WafResult<T> {
        self.map_err(|e| WafError::Internal(format!("{}: {}", f(), e)))
    }
}

impl<T> ErrorContext<T> for Result<T, serde_json::Error> {
    fn context(self, msg: &str) -> WafResult<T> {
        self.map_err(|e| WafError::Json(e)).map_err(|e| {
            if let WafError::Json(json_err) = e {
                WafError::Internal(format!("{}: {}", msg, json_err))
            } else {
                e
            }
        })
    }

    fn with_context<F: FnOnce() -> String>(self, f: F) -> WafResult<T> {
        self.map_err(|e| WafError::Internal(format!("{}: {}", f(), e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = WafError::Config("Invalid port".to_string());
        assert_eq!(err.to_string(), "Configuration error: Invalid port");

        let err = WafError::RateLimitExceeded;
        assert_eq!(err.to_string(), "Rate limit exceeded");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let waf_err: WafError = io_err.into();
        assert!(matches!(waf_err, WafError::Io(_)));
    }

    #[test]
    fn test_error_context() {
        let result: Result<String, std::io::Error> = 
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "test"));
        let waf_result = result.context("Failed to read config");
        assert!(waf_result.is_err());
    }
}
