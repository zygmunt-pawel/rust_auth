use base64::Engine as _;
use rand::{TryRngCore, rngs::OsRng};

#[derive(Debug, Clone)]
pub struct MagicLinkToken(String);

#[derive(Debug, Clone)]
pub struct SessionToken(String);

#[derive(Debug, Clone)]
pub struct VerifyCode(String);

fn random_32_bytes_base64url() -> String {
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes).expect("OsRng fill");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

impl MagicLinkToken {
    pub fn generate() -> Self { Self(random_32_bytes_base64url()) }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn from_string(s: String) -> Self { Self(s) }
}

impl SessionToken {
    pub fn generate() -> Self { Self(random_32_bytes_base64url()) }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn from_string(s: String) -> Self { Self(s) }
}

impl VerifyCode {
    /// Rejection sampling to avoid modulo bias.
    /// 4_294_000_000 is the largest multiple of 1_000_000 ≤ u32::MAX.
    pub fn generate() -> Self {
        const REJECT_THRESHOLD: u32 = 4_294_000_000;
        let mut buf = [0u8; 4];
        let n = loop {
            OsRng.try_fill_bytes(&mut buf).expect("OsRng fill");
            let n = u32::from_le_bytes(buf);
            if n < REJECT_THRESHOLD { break n; }
        };
        Self(format!("{:06}", n % 1_000_000))
    }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn from_string(s: String) -> Self { Self(s) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_link_token_is_43_chars_url_safe_base64() {
        let t = MagicLinkToken::generate();
        assert_eq!(t.as_str().len(), 43);
        assert!(t.as_str().chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn session_token_same_format_as_magic_link() {
        let s = SessionToken::generate();
        assert_eq!(s.as_str().len(), 43);
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(MagicLinkToken::generate().as_str(), MagicLinkToken::generate().as_str());
        assert_ne!(SessionToken::generate().as_str(), SessionToken::generate().as_str());
    }

    #[test]
    fn verify_code_is_six_digits() {
        for _ in 0..50 {
            let c = VerifyCode::generate();
            assert_eq!(c.as_str().len(), 6);
            assert!(c.as_str().chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn verify_code_uses_rejection_sampling() {
        // 1000 codes — sanity check distribution is roughly uniform across decades.
        let codes: Vec<_> = (0..1000).map(|_| VerifyCode::generate()).collect();
        let zero_prefixed = codes.iter().filter(|c| c.as_str().starts_with('0')).count();
        // ~10% start with '0'. Wide window for randomness.
        assert!(zero_prefixed > 50 && zero_prefixed < 200, "got {zero_prefixed}/1000");
    }
}
