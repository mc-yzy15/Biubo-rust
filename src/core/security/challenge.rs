use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

static USED_TOKENS: LazyLock<DashMap<String, SystemTime>> = LazyLock::new(DashMap::new);
const TOKEN_REUSE_WINDOW_SECS: u64 = 600;
const NONCE_LENGTH: usize = 16;

fn generate_nonce() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    hasher.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_be_bytes()
            .as_slice(),
    );
    hex::encode(hasher.finalize())[..NONCE_LENGTH].to_string()
}

fn current_time_window() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 300
}

pub fn get_challenge_token(ip: &str, user_agent: &str, secret: &str) -> String {
    let ts = current_time_window();
    let nonce = generate_nonce();
    let raw = format!("{}|{}|{}|{}", ip, user_agent, ts, nonce);

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(raw.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    format!("{}|{}|{}", ts, nonce, signature)
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeStatus {
    Valid,
    Invalid,
    Expired,
    Missing,
    Replayed,
}

pub fn verify_challenge_token(
    token: Option<&str>,
    ip: &str,
    user_agent: &str,
    secret: &str,
) -> ChallengeStatus {
    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => return ChallengeStatus::Missing,
    };

    let parts: Vec<&str> = token.split('|').collect();
    if parts.len() != 3 {
        return ChallengeStatus::Invalid;
    }

    let ts_str = parts[0];
    let nonce = parts[1];
    let signature = parts[2];

    let ts: u64 = match ts_str.parse() {
        Ok(v) => v,
        Err(_) => return ChallengeStatus::Invalid,
    };

    let current_ts = current_time_window();

    if ts != current_ts && ts != current_ts - 1 {
        return ChallengeStatus::Expired;
    }

    let token_key = format!("{}|{}|{}", ts, nonce, signature);
    if let Some(used_time) = USED_TOKENS.get(&token_key) {
        let elapsed = SystemTime::now()
            .duration_since(*used_time)
            .unwrap_or(Duration::from_secs(TOKEN_REUSE_WINDOW_SECS + 1));
        if elapsed.as_secs() < TOKEN_REUSE_WINDOW_SECS {
            return ChallengeStatus::Replayed;
        }
    }

    let raw = format!("{}|{}|{}|{}", ip, user_agent, ts_str, nonce);

    let sig_bytes = match hex::decode(signature) {
        Ok(b) => b,
        Err(_) => return ChallengeStatus::Invalid,
    };

    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return ChallengeStatus::Invalid,
    };
    mac.update(raw.as_bytes());

    let is_valid = match mac.verify_slice(&sig_bytes) {
        Ok(()) => true,
        Err(_) => false,
    };

    if is_valid {
        USED_TOKENS.insert(token_key, SystemTime::now());
        cleanup_used_tokens();
        ChallengeStatus::Valid
    } else {
        ChallengeStatus::Invalid
    }
}

fn cleanup_used_tokens() {
    let now = SystemTime::now();
    let cutoff = Duration::from_secs(TOKEN_REUSE_WINDOW_SECS);
    
    USED_TOKENS.retain(|_, used_time| {
        now.duration_since(*used_time)
            .map(|elapsed| elapsed < cutoff)
            .unwrap_or(false)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation_and_verification() {
        let ip = "192.168.1.1";
        let user_agent = "Mozilla/5.0";
        let secret = "test_secret_key";

        let token = get_challenge_token(ip, user_agent, secret);
        
        let parts: Vec<&str> = token.split('|').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1].len(), NONCE_LENGTH);

        let status = verify_challenge_token(Some(&token), ip, user_agent, secret);
        assert_eq!(status, ChallengeStatus::Valid);
    }

    #[test]
    fn test_token_replay_detection() {
        let ip = "192.168.1.1";
        let user_agent = "Mozilla/5.0";
        let secret = "test_secret_key";

        let token = get_challenge_token(ip, user_agent, secret);
        
        let status1 = verify_challenge_token(Some(&token), ip, user_agent, secret);
        assert_eq!(status1, ChallengeStatus::Valid);

        let status2 = verify_challenge_token(Some(&token), ip, user_agent, secret);
        assert_eq!(status2, ChallengeStatus::Replayed);
    }

    #[test]
    fn test_invalid_token_format() {
        let status = verify_challenge_token(Some("invalid"), "ip", "ua", "secret");
        assert_eq!(status, ChallengeStatus::Invalid);

        let status = verify_challenge_token(Some("a|b"), "ip", "ua", "secret");
        assert_eq!(status, ChallengeStatus::Invalid);
    }

    #[test]
    fn test_missing_token() {
        let status = verify_challenge_token(None, "ip", "ua", "secret");
        assert_eq!(status, ChallengeStatus::Missing);

        let status = verify_challenge_token(Some(""), "ip", "ua", "secret");
        assert_eq!(status, ChallengeStatus::Missing);
    }
}
