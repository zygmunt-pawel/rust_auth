use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::core::Pepper;

/// HMAC-SHA256(pepper, plaintext) → lowercase hex string (64 chars).
/// Used for ALL stored hashes: token_hash, code_hash, session_token_hash.
pub(crate) fn hmac_sha256_hex(pepper: &Pepper, plaintext: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper.expose())
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(plaintext.as_bytes());
    let bytes = mac.finalize().into_bytes();
    hex_lower(&bytes)
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = vec![0u8; bytes.len() * 2];
    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = TABLE[(b >> 4) as usize];
        out[2 * i + 1] = TABLE[(b & 0x0f) as usize];
    }
    // SAFETY: TABLE contains only ASCII bytes; output is valid UTF-8.
    unsafe { String::from_utf8_unchecked(out) }
}

/// Constant-time equal for two hex strings of equal length. Returns false if lengths differ.
pub(crate) fn ct_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_is_64_hex_chars() {
        let p = Pepper::from_bytes([0u8; 32]);
        let h = hmac_sha256_hex(&p, "hello");
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn different_peppers_produce_different_hashes() {
        let h1 = hmac_sha256_hex(&Pepper::from_bytes([1u8; 32]), "x");
        let h2 = hmac_sha256_hex(&Pepper::from_bytes([2u8; 32]), "x");
        assert_ne!(h1, h2);
    }

    #[test]
    fn same_pepper_same_input_same_hash() {
        let p = Pepper::from_bytes([7u8; 32]);
        assert_eq!(hmac_sha256_hex(&p, "abc"), hmac_sha256_hex(&p, "abc"));
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq_hex("abc123", "abc123"));
        assert!(!ct_eq_hex("abc123", "abc124"));
        assert!(!ct_eq_hex("abc123", "abc12"));
    }

    #[test]
    fn hex_lower_matches_format_for_all_bytes() {
        // Regression guard for the LUT-based hex_lower — must produce byte-for-byte
        // identical output to the `{:02x}` formatter across the full u8 range.
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let got = hex_lower(&all_bytes);
        let mut expected = String::with_capacity(all_bytes.len() * 2);
        use std::fmt::Write as _;
        for b in &all_bytes {
            write!(expected, "{b:02x}").unwrap();
        }
        assert_eq!(got, expected);
    }

    #[test]
    fn hex_lower_handles_empty_and_single() {
        assert_eq!(hex_lower(&[]), "");
        assert_eq!(hex_lower(&[0]), "00");
        assert_eq!(hex_lower(&[0xff]), "ff");
        assert_eq!(hex_lower(&[0xab, 0xcd]), "abcd");
    }
}
