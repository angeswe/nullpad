//! Auth API endpoints.

use crate::auth::middleware::{AppState, AuthSession};
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

/// Compute the `Secure` cookie attribute fragment for the session cookie.
///
/// Returns `"; Secure"` when the transport is HTTPS and onion_mode is disabled.
/// In onion_mode, omit `Secure` unconditionally: Tor provides transport encryption,
/// and browsers silently discard `Secure` cookies over plain HTTP, which is how a
/// hidden service is reached from inside the Tor network. Do NOT use onion_mode
/// on clearnet deployments.
fn secure_cookie_attr(headers: &HeaderMap, config: &crate::config::Config) -> &'static str {
    if config.onion_mode {
        ""
    } else if is_https(headers, config.trusted_proxy_count) {
        "; Secure"
    } else {
        ""
    }
}

/// Check if the incoming request arrived over HTTPS.
///
/// Only trusts `X-Forwarded-Proto` / `Forwarded` headers when `trusted_proxy_count > 0`
/// (i.e. we know a reverse proxy is setting them). Without a trusted proxy, these headers
/// are client-spoofable and must be ignored.
///
/// Returns `false` for direct HTTP connections (no trusted proxy).
fn is_https(headers: &HeaderMap, trusted_proxy_count: usize) -> bool {
    if trusted_proxy_count == 0 {
        return false;
    }
    if let Some(proto) = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        return proto.eq_ignore_ascii_case("https");
    }
    if let Some(fwd) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        // RFC 7239: comma separates proxy entries, semicolon separates params within an entry.
        // Only check the first (client-facing) entry.
        if let Some(first_entry) = fwd.split(',').next() {
            return first_entry.split(';').any(|param| {
                let trimmed = param.trim();
                trimmed.eq_ignore_ascii_case("proto=https")
                    || trimmed.eq_ignore_ascii_case("proto=\"https\"")
            });
        }
    }
    false
}

/// POST /api/auth/challenge — Request challenge nonce
pub async fn request_challenge(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ChallengeRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate alias before rate limiting (cheap check first, avoids wasting rate limit slots)
    super::validate_alias(&req.alias)?;

    let mut con = state.redis.clone();

    // Rate limit by IP
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let ip_hash = super::hash_ip(&*state.ip_hmac_salt, &ip);
    let rate_limit_key = format!("ratelimit:auth:challenge:{}", ip_hash);
    super::enforce_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_auth_per_min,
        60,
        Some(("auth/challenge", &ip_hash)),
    )
    .await?;

    // Per-alias rate limit BEFORE storing challenge to prevent challenge overwrite DoS.
    // Check unconditionally (alias existence is checked atomically when storing).
    let alias_rate_key = format!("ratelimit:challenge_alias:{}", req.alias);
    super::enforce_rate_limit(&mut con, &alias_rate_key, 10, 30, None).await?;

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
    let mut con = state.redis.clone();

    // Rate limit by IP
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let ip_hash = super::hash_ip(&*state.ip_hmac_salt, &ip);
    let rate_limit_key = format!("ratelimit:auth:verify:{}", ip_hash);
    super::enforce_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_auth_per_min,
        60,
        Some(("auth/verify", &ip_hash)),
    )
    .await?;

    // Validate alias
    super::validate_alias(&req.alias)?;

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

    // Generate session token
    let token = generate_session_token();

    // Create session
    let session = StoredSession {
        user_id: user.id.clone(),
        role: user.role,
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

    tracing::info!(action = "auth_success", user_id = %user.id, role = %user.role, "User authenticated");

    // Set HttpOnly session cookie for browser navigation to protected pages.
    // The same token is returned in JSON for JS to store in sessionStorage (API calls).
    let role_str = user.role.to_string();
    let secure = secure_cookie_attr(&headers, &state.config);
    let cookie = format!(
        "np_session={}; HttpOnly; SameSite=Strict{}; Path=/; Max-Age={}",
        token, secure, state.config.session_ttl_secs
    );

    Ok((
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(VerifyResponse {
            token,
            role: role_str,
        }),
    ))
}

/// POST /api/register — Register with invite token
pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let mut con = state.redis.clone();

    // Rate limit by IP
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let ip_hash = super::hash_ip(&*state.ip_hmac_salt, &ip);
    let rate_limit_key = format!("ratelimit:auth:register:{}", ip_hash);
    super::enforce_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_auth_per_min,
        60,
        Some(("auth/register", &ip_hash)),
    )
    .await?;

    // Validate alias
    super::validate_alias(&req.alias)?;

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
        role: Role::Trusted,
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
        storage::user::RegisterResult::AliasTaken
        | storage::user::RegisterResult::InviteNotFound => {
            // Uniform error prevents alias enumeration (attacker can't distinguish
            // "alias taken" from "bad invite" without a valid invite token).
            return Err(AppError::BadRequest("Registration failed".to_string()));
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
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let mut con = state.redis.clone();

    storage::session::delete_session(&mut con, &session.token, &session.user_id).await?;

    tracing::info!(action = "logout", user_id = %session.user_id, "User logged out");

    // Clear the session cookie on logout.
    let secure = secure_cookie_attr(&headers, &state.config);
    let clear_cookie = format!(
        "np_session=; HttpOnly; SameSite=Strict{}; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        secure
    );

    Ok((
        StatusCode::NO_CONTENT,
        [(axum::http::header::SET_COOKIE, clear_cookie)],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_config(onion_mode: bool, trusted_proxy_count: usize) -> Config {
        Config {
            onion_mode,
            trusted_proxy_count,
            ..Config::test_default()
        }
    }

    fn https_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        h
    }

    #[test]
    fn secure_cookie_attr_https_no_onion_sets_secure() {
        let cfg = test_config(false, 1);
        assert_eq!(secure_cookie_attr(&https_headers(), &cfg), "; Secure");
    }

    #[test]
    fn secure_cookie_attr_http_no_onion_no_secure() {
        let cfg = test_config(false, 0);
        assert_eq!(secure_cookie_attr(&HeaderMap::new(), &cfg), "");
    }

    #[test]
    fn secure_cookie_attr_onion_mode_omits_secure_even_when_https() {
        let cfg = test_config(true, 1);
        // Even with X-Forwarded-Proto: https from a trusted proxy, onion_mode wins.
        assert_eq!(secure_cookie_attr(&https_headers(), &cfg), "");
    }

    #[test]
    fn secure_cookie_attr_onion_mode_omits_secure_on_http() {
        let cfg = test_config(true, 0);
        assert_eq!(secure_cookie_attr(&HeaderMap::new(), &cfg), "");
    }
}
