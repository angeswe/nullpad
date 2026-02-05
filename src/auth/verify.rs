//! Ed25519 signature verification.

use crate::error::AppError;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

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
    // Decode public key from base64
    let pubkey_bytes = general_purpose::STANDARD
        .decode(pubkey_base64)
        .map_err(|e| AppError::BadRequest(format!("Invalid pubkey base64: {}", e)))?;

    if pubkey_bytes.len() != 32 {
        return Err(AppError::BadRequest(format!(
            "Invalid pubkey length: expected 32 bytes, got {}",
            pubkey_bytes.len()
        )));
    }

    // Decode signature from base64
    let signature_bytes = general_purpose::STANDARD
        .decode(signature_base64)
        .map_err(|e| AppError::BadRequest(format!("Invalid signature base64: {}", e)))?;

    if signature_bytes.len() != 64 {
        return Err(AppError::BadRequest(format!(
            "Invalid signature length: expected 64 bytes, got {}",
            signature_bytes.len()
        )));
    }

    // Create VerifyingKey from pubkey bytes
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| AppError::Internal("Failed to convert pubkey to array".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| AppError::BadRequest(format!("Invalid public key: {}", e)))?;

    // Create Signature from signature bytes
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| AppError::Internal("Failed to convert signature to array".to_string()))?;

    let signature = Signature::from_bytes(&signature_array);

    // Verify signature (constant-time comparison is built into ed25519-dalek)
    match verifying_key.verify(message, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use ed25519_dalek::{Signer, SigningKey};

    fn generate_test_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::fill(&mut seed);
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

    #[test]
    fn test_verify_signature_invalid_base64() {
        let result = verify_signature("not-base64!", b"test", "also-not-base64!");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }
}
