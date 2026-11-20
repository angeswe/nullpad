//! Authentication layer for Ed25519 signature verification and session management.

pub mod middleware;
pub mod session;
pub mod verify;

pub use middleware::{check_rate_limit, AdminSession, AppState, AuthSession, RateLimitResult};
pub use session::{generate_challenge_nonce, generate_session_token};
pub use verify::verify_signature;

/// Same minimum as `MIN_SECRET_LENGTH` in static/js/invite.js.
pub const MIN_SECRET_LENGTH: usize = 12;

/// Counts UTF-16 code units, as JavaScript's `String.length` does in invite.js.
pub fn check_secret_length(secret: &str) -> Result<(), String> {
    if secret.encode_utf16().count() < MIN_SECRET_LENGTH {
        return Err(format!("Secret must be at least {MIN_SECRET_LENGTH} characters long. Your keypair is derived from this secret — a longer secret resists offline cracking."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_rejects_secret_shorter_than_12() {
        assert_eq!(
            check_secret_length(&"a".repeat(11)),
            Err("Secret must be at least 12 characters long. Your keypair is derived from this secret — a longer secret resists offline cracking.".to_string())
        );
        assert_eq!(check_secret_length(&"a".repeat(12)), Ok(()));
    }
}
