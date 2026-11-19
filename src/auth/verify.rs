//! Ed25519 signature verification.

use crate::error::AppError;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};

/// Verify an Ed25519 signature against a message.
///
/// # Arguments
/// * `pubkey_base64` - Base64-encoded public key (32 bytes)
/// * `message` - The message bytes that were signed
/// * `signature_base64` - Base64-encoded signature (64 bytes)
///
/// # Returns
/// * `Ok(true)` if signature is valid
/// * `Ok(false)` if signature is invalid
/// * `Err(AppError)` if decoding fails or keys are malformed
pub fn verify_signature(
    pubkey_base64: &str,
    message: &[u8],
    signature_base64: &str,
) -> Result<bool, AppError> {
    let verifying_key = parse_pubkey(pubkey_base64)?;

    // Decode signature from base64
    let signature_bytes = general_purpose::STANDARD
        .decode(signature_base64)
        .map_err(|e| {
            tracing::debug!(error = %e, "Invalid signature base64");
            AppError::BadRequest("Invalid signature format".to_string())
        })?;

    if signature_bytes.len() != 64 {
        tracing::debug!(
            expected = 64,
            got = signature_bytes.len(),
            "Invalid signature length"
        );
        return Err(AppError::BadRequest("Invalid signature format".to_string()));
    }

    // Create Signature from signature bytes
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| AppError::Internal("Failed to convert signature to array".to_string()))?;

    let signature = Signature::from_bytes(&signature_array);

    // Verify signature (constant-time comparison is built into ed25519-dalek)
    match verifying_key.verify_strict(message, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Decode a base64 Ed25519 public key, rejecting malformed and small-order (weak) keys.
pub fn parse_pubkey(pubkey_base64: &str) -> Result<VerifyingKey, AppError> {
    let invalid = || AppError::BadRequest("Invalid public key format".to_string());

    let pubkey_bytes = general_purpose::STANDARD
        .decode(pubkey_base64)
        .map_err(|e| {
            tracing::debug!(error = %e, "Invalid pubkey base64");
            invalid()
        })?;

    let pubkey_array: [u8; 32] = pubkey_bytes.try_into().map_err(|bytes: Vec<u8>| {
        tracing::debug!(expected = 32, got = bytes.len(), "Invalid pubkey length");
        invalid()
    })?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_array).map_err(|e| {
        tracing::debug!(error = %e, "Invalid Ed25519 public key");
        invalid()
    })?;

    if verifying_key.is_weak() {
        tracing::debug!("Rejected small-order Ed25519 public key");
        return Err(invalid());
    }

    Ok(verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::RngExt;

    fn generate_test_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rng().fill(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn test_verify_signature_valid() {
        let signing_key = generate_test_signing_key();
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let signature = signing_key.sign(message);

        let pubkey_base64 = general_purpose::STANDARD.encode(verifying_key.to_bytes());
        let signature_base64 = general_purpose::STANDARD.encode(signature.to_bytes());

        let result = verify_signature(&pubkey_base64, message, &signature_base64);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_signature_invalid() {
        let signing_key = generate_test_signing_key();
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let signature = signing_key.sign(message);

        let pubkey_base64 = general_purpose::STANDARD.encode(verifying_key.to_bytes());
        let signature_base64 = general_purpose::STANDARD.encode(signature.to_bytes());

        // Verify with different message
        let wrong_message = b"wrong message";
        let result = verify_signature(&pubkey_base64, wrong_message, &signature_base64);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should be false
    }

    #[test]
    fn test_verify_signature_invalid_pubkey_length() {
        let pubkey_base64 = general_purpose::STANDARD.encode(b"too_short");
        let signature_base64 = general_purpose::STANDARD.encode([0u8; 64]);
        let message = b"test";

        let result = verify_signature(&pubkey_base64, message, &signature_base64);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }

    #[test]
    fn test_verify_signature_invalid_signature_length() {
        let pubkey_base64 = general_purpose::STANDARD.encode([0u8; 32]);
        let signature_base64 = general_purpose::STANDARD.encode(b"too_short");
        let message = b"test";

        let result = verify_signature(&pubkey_base64, message, &signature_base64);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }

    const ALL_ZEROS_ORDER4: [u8; 32] = [0u8; 32];
    const ORDER8_POINT: [u8; 32] = [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ];

    #[test]
    fn test_parse_pubkey_rejects_small_order_points() {
        for weak in [ALL_ZEROS_ORDER4, ORDER8_POINT] {
            assert!(VerifyingKey::from_bytes(&weak).unwrap().is_weak());
            let result = parse_pubkey(&general_purpose::STANDARD.encode(weak));
            assert!(matches!(result, Err(AppError::BadRequest(_))));
        }
    }

    #[test]
    fn test_parse_pubkey_accepts_valid_key() {
        let verifying_key = generate_test_signing_key().verifying_key();
        let pubkey_base64 = general_purpose::STANDARD.encode(verifying_key.to_bytes());
        assert_eq!(parse_pubkey(&pubkey_base64).unwrap(), verifying_key);
    }

    #[test]
    fn test_verify_signature_rejects_weak_pubkey() {
        let pubkey_base64 = general_purpose::STANDARD.encode(ALL_ZEROS_ORDER4);
        let signature_base64 = general_purpose::STANDARD.encode([0u8; 64]);
        let result = verify_signature(&pubkey_base64, b"test", &signature_base64);
        assert!(matches!(result, Err(AppError::BadRequest(_))));
    }

    #[test]
    fn test_verify_signature_invalid_base64() {
        let result = verify_signature("not-base64!", b"test", "also-not-base64!");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }
}
