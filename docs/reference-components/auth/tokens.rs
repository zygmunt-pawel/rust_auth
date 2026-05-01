// Wspólne helpery do tokenów: magic-link i session token używają tego samego
// schematu (32B CSPRNG → base64url, lookup po SHA-256 hex).

use std::fmt::Write as _;

use base64::Engine as _;
use rand::TryRngCore as _;
use sha2::{Digest, Sha256};

// 32B z OsRng → base64url (no-pad) ≈ 43 znaki.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut bytes).expect("OsRng fill");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in digest {
        write!(hex, "{b:02x}").unwrap();
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_has_expected_length() {
        // 32B base64url no-pad → ceil(32 * 4 / 3) = 43 chars
        assert_eq!(generate_token().len(), 43);
    }

    #[test]
    fn token_is_url_safe() {
        let t = generate_token();
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(generate_token(), generate_token());
    }

    #[test]
    fn sha256_hex_is_64_lowercase_hex() {
        let h = sha256_hex("abc");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // znana wartość SHA-256("abc")
        assert_eq!(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
