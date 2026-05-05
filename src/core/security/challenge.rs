use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn get_challenge_token(ip: &str, user_agent: &str, secret: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 300;

    let raw = format!("{}|{}|{}", ip, user_agent, ts);

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(raw.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    format!("{}|{}", ts, signature)
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeStatus {
    Valid,
    Invalid,
    Expired,
    Missing,
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
    if parts.len() != 2 {
        return ChallengeStatus::Invalid;
    }

    let ts_str = parts[0];
    let signature = parts[1];

    let ts: u64 = match ts_str.parse() {
        Ok(v) => v,
        Err(_) => return ChallengeStatus::Invalid,
    };

    let current_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 300;

    if ts != current_ts && ts != current_ts - 1 {
        return ChallengeStatus::Expired;
    }

    let raw = format!("{}|{}|{}", ip, user_agent, ts_str);

    let sig_bytes = match hex::decode(signature) {
        Ok(b) => b,
        Err(_) => return ChallengeStatus::Invalid,
    };

    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return ChallengeStatus::Invalid,
    };
    mac.update(raw.as_bytes());

    match mac.verify_slice(&sig_bytes) {
        Ok(()) => ChallengeStatus::Valid,
        Err(_) => ChallengeStatus::Invalid,
    }
}
