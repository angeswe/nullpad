//! Auth API endpoints.

use crate::auth::middleware::{check_rate_limit, AppState, AuthSession};
use crate::auth::session::{generate_challenge_nonce, generate_session_token};
use crate::auth::verify::verify_signature;
use crate::error::AppError;
use crate::models::{
    ChallengeRequest, ChallengeResponse, RegisterRequest, Role, StoredChallenge, StoredSession,
    StoredUser, VerifyRequest, VerifyResponse,
};
use crate::storage;
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;

/// POST /api/auth/challenge — Request challenge nonce
pub async fn request_challenge(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<ChallengeRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Rate limit by IP
    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    let rate_limit_key = format!("ratelimit:auth:{}", addr.ip());
    let allowed = check_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_auth_per_min,
        60,
    )
    .await
    .map_err(|e| AppError::Internal(format!("Rate limit check failed: {}", e)))?;

    // Validate alias
    if req.alias.len() < 2 || req.alias.len() > 64 {
        return Err(AppError::BadRequest(
            "Alias must be 2-64 characters".to_string(),
        ));
    }
    if !req
        .alias
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest(
            "Alias may only contain alphanumeric characters, hyphens, and underscores".to_string(),
        ));
    }

    if !allowed {
        let mut hasher = std::hash::DefaultHasher::new();
        addr.ip().hash(&mut hasher);
        let ip_hash = format!("{:x}", hasher.finish());
        tracing::warn!(action = "rate_limited", endpoint = "auth/challenge", ip_hash = %ip_hash, "Rate limit exceeded");
        return Err(AppError::RateLimited);
    }

    // Look up user by alias (verify user exists)
    let _user = storage::user::get_user_by_alias(&mut con, &req.alias)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Generate nonce
    let nonce = generate_challenge_nonce();

    // Store challenge
    let challenge = StoredChallenge {
        nonce: nonce.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    storage::session::store_challenge(
        &mut con,
        &req.alias,
        &challenge,
        state.config.challenge_ttl_secs,
    )
    .await?;

    Ok(Json(ChallengeResponse { nonce }))
}

/// POST /api/auth/verify — Verify signature and create session
pub async fn verify_challenge(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    // Get and delete challenge (single-use)
    let challenge = storage::session::get_and_delete_challenge(&mut con, &req.alias)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Challenge not found or expired".to_string()))?;

    // Look up user to get pubkey
    let user = storage::user::get_user_by_alias(&mut con, &req.alias)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    // Verify signature (nonce is base64-encoded bytes)
    let nonce_bytes = general_purpose::STANDARD
        .decode(&challenge.nonce)
        .map_err(|e| AppError::Internal(format!("Invalid nonce encoding: {}", e)))?;

    let valid = verify_signature(&user.pubkey, &nonce_bytes, &req.signature)?;

    if !valid {
        tracing::warn!(action = "auth_failed", alias = %req.alias, "Invalid signature");
        return Err(AppError::Unauthorized("Invalid signature".to_string()));
    }

    // Parse role
    let role = user
        .role
        .parse::<Role>()
        .map_err(|e| AppError::Internal(format!("Invalid role: {}", e)))?;

    // Generate session token
    let token = generate_session_token();

    // Create session
    let session = StoredSession {
        token: token.clone(),
        user_id: user.id.clone(),
        role: role.as_str().to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    storage::session::store_session(&mut con, &session, state.config.session_ttl_secs).await?;

    tracing::info!(action = "auth_success", alias = %req.alias, user_id = %user.id, role = %role.as_str(), "User authenticated");

    Ok(Json(VerifyResponse {
        token,
        role: role.as_str().to_string(),
    }))
}

/// POST /api/register — Register with invite token
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    // Validate alias
    if req.alias.len() < 2 || req.alias.len() > 64 {
        return Err(AppError::BadRequest(
            "Alias must be 2-64 characters".to_string(),
        ));
    }
    if !req
        .alias
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest(
            "Alias may only contain alphanumeric characters, hyphens, and underscores".to_string(),
        ));
    }

    // Atomically get and delete invite (single-use)
    let _invite = storage::user::get_and_delete_invite(&mut con, &req.token)
        .await?
        .ok_or_else(|| AppError::NotFound("Invite not found or expired".to_string()))?;

    // Check if alias is already taken
    let existing = storage::user::get_user_by_alias(&mut con, &req.alias).await?;
    if existing.is_some() {
        return Err(AppError::BadRequest(format!(
            "Alias '{}' is already taken",
            req.alias
        )));
    }

    // Create user
    let user_id = nanoid::nanoid!(12);
    let user = StoredUser {
        id: user_id,
        alias: req.alias,
        pubkey: req.pubkey,
        role: Role::Trusted.as_str().to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Store user with idle TTL (will be updated to active TTL on first upload)
    storage::user::store_user(&mut con, &user, state.config.user_idle_ttl_secs).await?;

    tracing::info!(action = "user_registered", user_id = %user.id, alias = %user.alias, "New user registered via invite");

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Registration successful"
    })))
}

/// POST /api/auth/logout — Invalidate current session
pub async fn logout(
    session: AuthSession,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    storage::session::delete_session(&mut con, &session.token).await?;

    tracing::info!(action = "logout", user_id = %session.user_id, "User logged out");

    Ok(StatusCode::NO_CONTENT)
}
