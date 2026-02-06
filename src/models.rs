//! Request and response models for the API.
//!
//! All models use serde for serialization/deserialization.
//! Storage models represent Redis data structures.

use serde::{Deserialize, Serialize};

// ============================================================================
// Paste Models
// ============================================================================

/// Metadata for paste creation (sent as JSON in multipart form).
#[derive(Debug, Deserialize)]
pub struct PasteMetadata {
    pub filename: String,
    pub content_type: String,
    /// TTL in seconds. If omitted, uses server config DEFAULT_TTL_SECS.
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub burn_after_reading: bool,
}

/// Response after creating a paste.
#[derive(Debug, Serialize)]
pub struct CreatePasteResponse {
    pub id: String,
    pub url: String,
}

/// Response when fetching a paste.
#[derive(Debug, Serialize)]
pub struct GetPasteResponse {
    pub encrypted_content: String, // base64
    pub filename: String,
    pub content_type: String,
    pub burn_after_reading: bool,
    pub created_at: u64,
}

/// Paste data as stored in Redis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPaste {
    pub id: String,
    pub encrypted_content: Vec<u8>,
    pub filename: String,
    pub content_type: String,
    pub burn_after_reading: bool,
    pub created_at: u64,
    pub owner_id: Option<String>,
}

/// Paste info for admin listing.
#[derive(Debug, Serialize)]
pub struct PasteInfo {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub created_at: u64,
    pub ttl: u64,
    pub burn_after_reading: bool,
    pub owner_id: Option<String>,
}

// ============================================================================
// Auth Models
// ============================================================================

/// Request for authentication challenge.
#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub alias: String,
}

/// Response containing nonce for signing.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub nonce: String, // base64
}

/// Request to verify signed challenge.
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub alias: String,
    pub signature: String, // base64
}

/// Response after successful verification.
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub token: String,
    pub role: String,
}

/// Request to register with an invite token.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub token: String,
    pub alias: String,
    pub pubkey: String, // base64 Ed25519 public key
}

// ============================================================================
// Admin Models
// ============================================================================

/// Response after creating an invite.
#[derive(Debug, Serialize)]
pub struct CreateInviteResponse {
    pub token: String,
    pub url: String,
}

/// Invite info for admin listing.
#[derive(Debug, Serialize)]
pub struct InviteInfo {
    pub token: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// User info for admin listing.
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub alias: String,
    pub pubkey: String,
    pub role: String,
    pub created_at: u64,
}

// ============================================================================
// Storage Models
// ============================================================================

/// User data as stored in Redis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub id: String,
    pub alias: String,
    pub pubkey: String, // base64
    pub role: String,
    pub created_at: u64,
}

/// Invite data as stored in Redis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredInvite {
    pub token: String,
    pub created_at: u64,
}

/// Challenge data as stored in Redis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChallenge {
    pub nonce: String, // base64
    pub created_at: u64,
}

/// Session data as stored in Redis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub token: String,
    pub user_id: String,
    pub role: String,
    pub created_at: u64,
}

// ============================================================================
// User Roles
// ============================================================================

/// User role types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Trusted,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Trusted => "trusted",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Role::Admin),
            "trusted" => Ok(Role::Trusted),
            _ => Err(format!("Invalid role: {}", s)),
        }
    }
}
