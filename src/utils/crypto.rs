use bcrypt::{hash, verify, DEFAULT_COST};
use subtle::ConstantTimeEq;

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    verify(password, hash).unwrap_or(false)
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
}
