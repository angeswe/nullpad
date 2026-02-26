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
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use std::net::SocketAddr;

/// POST /api/auth/challenge — Request challenge nonce
pub async fn request_challenge(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ChallengeRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate alias before rate limiting (cheap check first, avoids wasting rate limit slots)
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

    // Rate limit by IP
    // Get Redis connection (ConnectionManager handles auto-reconnection)
    let mut con = state.redis.clone();

    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let ip_hash = super::hash_ip(&*state.ip_hmac_salt, &ip);
    let rate_limit_key = format!("ratelimit:auth:challenge:{}", ip_hash);
    let rate_result = check_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_auth_per_min,
        60,
    )
    .await
    .map_err(|e| AppError::Internal(format!("Rate limit check failed: {}", e)))?;

    if !rate_result.allowed {
        tracing::warn!(action = "rate_limited", endpoint = "auth/challenge", ip_hash = %ip_hash, "Rate limit exceeded");
        return Err(AppError::RateLimited {
            retry_after: rate_result.retry_after,
        });
    }

    // Per-alias rate limit BEFORE storing challenge to prevent challenge overwrite DoS.
    // Check unconditionally (alias existence is checked atomically when storing).
    let alias_rate_key = format!("ratelimit:challenge_alias:{}", req.alias);
    let alias_rate_result = check_rate_limit(
        &mut con,
        &alias_rate_key,
        10, // max 10 challenges per alias per 30s window
        30,
    )
    .await
    .map_err(|e| AppError::Internal(format!("Rate limit check failed: {}", e)))?;

    if !alias_rate_result.allowed {
        return Err(AppError::RateLimited {
            retry_after: alias_rate_result.retry_after,
        });
    }

    // Generate nonce regardless of whether user exists to prevent alias enumeration
    let nonce = generate_challenge_nonce();

    let challenge = StoredChallenge {
        nonce: nonce.clone(),
        created_at: crate::util::now_secs(),
    };

    // Atomically check if user exists and store challenge.
    // This prevents race conditions between user lookup and challenge storage.
    // Non-existent users get a throwaway nonce (alias enumeration prevention).
    storage::session::store_challenge_if_user_exists(
        &mut con,
        &req.alias,
        &challenge,
        state.config.challenge_ttl_secs,
    )
    .await?;

    // Always return a challenge response (non-existent users get a throwaway nonce)
    Ok(Json(ChallengeResponse { nonce }))
}

/// POST /api/auth/verify — Verify signature and create session
pub async fn verify_challenge(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Get Redis connection (ConnectionManager handles auto-reconnection)
    let mut con = state.redis.clone();

    // Rate limit by IP
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let ip_hash = super::hash_ip(&*state.ip_hmac_salt, &ip);
    let rate_limit_key = format!("ratelimit:auth:verify:{}", ip_hash);
    let rate_result = check_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_auth_per_min,
        60,
    )
    .await
    .map_err(|e| AppError::Internal(format!("Rate limit check failed: {}", e)))?;

    if !rate_result.allowed {
        tracing::warn!(action = "rate_limited", endpoint = "auth/verify", ip_hash = %ip_hash, "Rate limit exceeded");
        return Err(AppError::RateLimited {
            retry_after: rate_result.retry_after,
        });
    }

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

    // Get and delete challenge (single-use)
    let challenge = storage::session::get_and_delete_challenge(&mut con, &req.alias)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Authentication failed".to_string()))?;

    // Look up user to get pubkey
    let user = storage::user::get_user_by_alias(&mut con, &req.alias)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Authentication failed".to_string()))?;

    // Verify signature (nonce is base64-encoded bytes)
    let nonce_bytes = general_purpose::STANDARD
        .decode(&challenge.nonce)
        .map_err(|e| AppError::Internal(format!("Invalid nonce encoding: {}", e)))?;

    let valid = verify_signature(&user.pubkey, &nonce_bytes, &req.signature)?;

    if !valid {
        tracing::warn!(action = "auth_failed", "Invalid signature");
        return Err(AppError::Unauthorized("Authentication failed".to_string()));
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
        user_id: user.id.clone(),
        role: role.as_str().to_string(),
        created_at: crate::util::now_secs(),
    };

    storage::session::store_session(
        &mut con,
        &token,
        &session,
        state.config.session_ttl_secs,
        state.config.max_sessions_per_user,
    )
    .await?;

    tracing::info!(action = "auth_success", user_id = %user.id, role = %role.as_str(), "User authenticated");

    Ok(Json(VerifyResponse {
        token,
        role: role.as_str().to_string(),
    }))
}

/// POST /api/register — Register with invite token
pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Get Redis connection (ConnectionManager handles auto-reconnection)
    let mut con = state.redis.clone();

    // Rate limit by IP
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let ip_hash = super::hash_ip(&*state.ip_hmac_salt, &ip);
    let rate_limit_key = format!("ratelimit:auth:register:{}", ip_hash);
    let rate_result = check_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_auth_per_min,
        60,
    )
    .await
    .map_err(|e| AppError::Internal(format!("Rate limit check failed: {}", e)))?;

    if !rate_result.allowed {
        tracing::warn!(action = "rate_limited", endpoint = "auth/register", ip_hash = %ip_hash, "Rate limit exceeded");
        return Err(AppError::RateLimited {
            retry_after: rate_result.retry_after,
        });
    }

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

    // Validate invite token format
    super::validate_id(&req.token, "invite token", 16)?;

    // Validate pubkey FIRST (before touching Redis): must be valid base64, 32 bytes, and a valid Ed25519 public key
    let pubkey_bytes = general_purpose::STANDARD
        .decode(&req.pubkey)
        .map_err(|_| AppError::BadRequest("Invalid public key: not valid base64".to_string()))?;
    if pubkey_bytes.len() != 32 {
        tracing::debug!(
            expected = 32,
            got = pubkey_bytes.len(),
            "Invalid pubkey length in registration"
        );
        return Err(AppError::BadRequest(
            "Invalid public key format".to_string(),
        ));
    }
    let key_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("Invalid public key format".to_string()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&key_array).map_err(|e| {
        tracing::debug!(error = %e, "Invalid Ed25519 public key in registration");
        AppError::BadRequest("Invalid public key format".to_string())
    })?;

    // Create user ID upfront (needed for Lua script)
    let user_id = nanoid::nanoid!(12);
    let user = StoredUser {
        id: user_id,
        alias: req.alias.clone(),
        pubkey: req.pubkey,
        role: Role::Trusted.as_str().to_string(),
        created_at: crate::util::now_secs(),
    };

    // Atomically: check alias availability, consume invite, create user.
    // Single Lua script prevents race where concurrent registrations both
    // consume invites but only one user is created (wasting an invite).
    let created = storage::user::consume_invite_and_create_user(
        &mut con,
        &req.token,
        &user,
        state.config.user_idle_ttl_secs,
    )
    .await?;

    match created {
        storage::user::RegisterResult::Success => {}
        storage::user::RegisterResult::AliasTaken => {
            return Err(AppError::BadRequest(format!(
                "Alias '{}' is already taken",
                req.alias
            )));
        }
        storage::user::RegisterResult::InviteNotFound => {
            return Err(AppError::NotFound(
                "Invite not found or expired".to_string(),
            ));
        }
    }

    tracing::info!(action = "user_registered", user_id = %user.id, "New user registered via invite");

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
    // Get Redis connection (ConnectionManager handles auto-reconnection)
    let mut con = state.redis.clone();

    storage::session::delete_session(&mut con, &session.token, &session.user_id).await?;

    tracing::info!(action = "logout", user_id = %session.user_id, "User logged out");

    Ok(StatusCode::NO_CONTENT)
}
