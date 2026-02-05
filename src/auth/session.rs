//! Token and nonce generation for authentication.

use base64::{Engine as _, engine::general_purpose};
use rand::Rng;

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
    fn test_tokens_are_unique() {
        let token1 = generate_session_token();
        let token2 = generate_session_token();
        assert_ne!(token1, token2);

        let nonce1 = generate_challenge_nonce();
        let nonce2 = generate_challenge_nonce();
        assert_ne!(nonce1, nonce2);
    }
}
