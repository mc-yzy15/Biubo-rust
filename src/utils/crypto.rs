use bcrypt::{hash, verify, DEFAULT_COST};
use subtle::ConstantTimeEq;

/// Hash a password with bcrypt. Currently only referenced by unit tests;
/// gated with `#[cfg(test)]` per the project's dead-code zero-tolerance rule.
#[cfg(test)]
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    verify(password, hash).unwrap_or(false)
}

pub fn is_bcrypt_hash(value: &str) -> bool {
    value.starts_with("$2a$") || value.starts_with("$2b$") || value.starts_with("$2y$")
}

pub fn hash_secret_if_needed(secret: &str) -> Result<String, bcrypt::BcryptError> {
    if secret.is_empty() || is_bcrypt_hash(secret) {
        Ok(secret.to_string())
    } else {
        hash(secret, DEFAULT_COST)
    }
}

pub fn verify_secret(secret: &str, stored: &str) -> bool {
    if stored.is_empty() {
        return false;
    }

    if is_bcrypt_hash(stored) {
        verify(secret, stored).unwrap_or(false)
    } else {
        constant_time_compare(secret.as_bytes(), stored.as_bytes())
    }
}

pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    let len_eq = subtle::ConstantTimeEq::ct_eq(&a.len(), &b.len());
    let mut result = 0u8;
    for i in 0..a.len().min(b.len()) {
        result |= a[i] ^ b[i];
    }
    (len_eq & result.ct_eq(&0u8)).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello worlD";
        let d = b"hello";

        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
        assert!(!constant_time_compare(a, d));
    }

    #[test]
    fn test_hash_secret_if_needed_keeps_bcrypt_hashes() {
        let hashed = hash_password("secret").unwrap();
        let result = hash_secret_if_needed(&hashed).unwrap();
        assert_eq!(result, hashed);
    }

    #[test]
    fn test_verify_secret_supports_plaintext_and_bcrypt() {
        let hashed = hash_secret_if_needed("secret-value").unwrap();

        assert!(verify_secret("secret-value", "secret-value"));
        assert!(!verify_secret("wrong", "secret-value"));
        assert!(verify_secret("secret-value", &hashed));
        assert!(!verify_secret("wrong", &hashed));
    }
}
