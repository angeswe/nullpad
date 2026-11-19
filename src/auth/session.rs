//! Token and nonce generation for authentication.

use base64::{engine::general_purpose, Engine as _};
use rand::RngExt;

/// Generate a cryptographically random session token.
///
/// Returns a base64-encoded string (44 characters) from 32 random bytes.
pub fn generate_session_token() -> String {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    general_purpose::STANDARD.encode(bytes)
}

/// Generate a cryptographically random challenge nonce.
///
/// Returns a base64-encoded string (44 characters) from 32 random bytes.
pub fn generate_challenge_nonce() -> String {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    general_purpose::STANDARD.encode(bytes)
}

/// Generate a random challenge ID: 32 lowercase hex characters from 16 random bytes.
pub fn generate_challenge_id() -> String {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// True if `id` has the exact format [`generate_challenge_id`] produces.
pub fn is_valid_challenge_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;

    #[test]
    fn test_generate_session_token() {
        let token = generate_session_token();

        // Base64 of 32 bytes is 44 characters (with padding)
        assert_eq!(token.len(), 44);

        // Verify it's valid base64
        assert!(general_purpose::STANDARD.decode(&token).is_ok());

        // Verify decoded length
        let decoded = general_purpose::STANDARD.decode(&token).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_generate_challenge_nonce() {
        let nonce = generate_challenge_nonce();

        // Base64 of 32 bytes is 44 characters (with padding)
        assert_eq!(nonce.len(), 44);

        // Verify it's valid base64
        assert!(general_purpose::STANDARD.decode(&nonce).is_ok());

        // Verify decoded length
        let decoded = general_purpose::STANDARD.decode(&nonce).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_generated_challenge_id_is_valid_and_unique() {
        let id = generate_challenge_id();
        assert_eq!(id.len(), 32);
        assert!(is_valid_challenge_id(&id));
        assert_ne!(id, generate_challenge_id());
    }

    #[test]
    fn test_is_valid_challenge_id_rejects_other_formats() {
        let ok = "0123456789abcdef0123456789abcdef";
        assert!(is_valid_challenge_id(ok));
        for bad in [
            "",
            &ok[..31],
            &format!("{ok}0"),
            "0123456789ABCDEF0123456789abcdef",
            "0123456789abcdef0123456789abcde:",
            "../../../../../../../../../../ab",
            "0123456789abcdef0123456789abcdé",
        ] {
            assert!(!is_valid_challenge_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn test_tokens_are_unique() {
        let token1 = generate_session_token();
        let token2 = generate_session_token();
        assert_ne!(token1, token2);

        let nonce1 = generate_challenge_nonce();
        let nonce2 = generate_challenge_nonce();
        assert_ne!(nonce1, nonce2);
    }
}
