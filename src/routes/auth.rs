//! Auth API endpoints.

use crate::auth::middleware::{AppState, AuthSession};
use crate::auth::session::{
    generate_challenge_id, generate_challenge_nonce, generate_session_token, is_valid_challenge_id,
};
use crate::auth::verify::{parse_pubkey, verify_signature};
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

fn unauthorized() -> AppError {
    AppError::Unauthorized("Authentication failed".to_string())
}

fn auth_failed(log_message: &str) -> AppError {
    tracing::warn!(action = "auth_failed", "{log_message}");
    unauthorized()
}

fn signature_verdict(result: Result<bool, AppError>) -> Result<(), AppError> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(auth_failed("Invalid signature")),
        Err(AppError::BadRequest(_)) => Err(auth_failed("Signature verification rejected input")),
        Err(e) => {
            tracing::error!(action = "auth_failed", error = %e, "Signature verification error");
            Err(unauthorized())
        }
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
        let entries: Vec<&str> = proto.split(',').map(str::trim).collect();
        return entries[entries.len().saturating_sub(trusted_proxy_count)]
            .eq_ignore_ascii_case("https");
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

    // Keyed on alias and caller together, so one caller's requests never use up another
    // caller's allowance for the same alias.
    let alias_rate_key = format!("ratelimit:challenge_alias:{}:{}", req.alias, ip_hash);
    super::enforce_rate_limit(&mut con, &alias_rate_key, 10, 30, None).await?;

    // Generate ID and nonce regardless of whether user exists to prevent alias enumeration
    let challenge_id = generate_challenge_id();
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
        &challenge_id,
        &challenge,
        state.config.challenge_ttl_secs,
    )
    .await?;

    // Always return a challenge response (non-existent users get a throwaway nonce)
    Ok(Json(ChallengeResponse {
        challenge_id,
        nonce,
    }))
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

    let signature_well_formed = general_purpose::STANDARD
        .decode(&req.signature)
        .is_ok_and(|bytes| bytes.len() == 64);
    if !signature_well_formed {
        return Err(auth_failed("Malformed signature"));
    }
    if !is_valid_challenge_id(&req.challenge_id) {
        return Err(auth_failed("Malformed challenge id"));
    }

    // Get and delete challenge (single-use)
    let challenge =
        storage::session::get_and_delete_challenge(&mut con, &req.alias, &req.challenge_id)
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

    signature_verdict(verify_signature(&user.pubkey, &nonce_bytes, &req.signature))?;

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
    let secure = if is_https(&headers, state.config.trusted_proxy_count) {
        "; Secure"
    } else {
        ""
    };
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

    // Validate pubkey before touching Valkey
    parse_pubkey(&req.pubkey)?;

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
    let secure = if is_https(&headers, state.config.trusted_proxy_count) {
        "; Secure"
    } else {
        ""
    };
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
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
        let buffer = LogBuffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let result = tracing::subscriber::with_default(subscriber, f);
        let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        (result, logs)
    }

    #[test]
    fn test_signature_verdict_rejected_pubkey_returns_uniform_401() {
        let (result, logs) = capture_logs(|| {
            signature_verdict(Err(AppError::BadRequest(
                "Invalid public key format".to_string(),
            )))
        });
        assert!(
            matches!(result, Err(AppError::Unauthorized(msg)) if msg == "Authentication failed")
        );
        assert!(logs.contains("WARN"));
        assert!(logs.contains("auth_failed"));
        assert!(!logs.contains("Invalid public key format"));
    }

    #[test]
    fn test_signature_verdict_internal_error_returns_uniform_401() {
        let (result, logs) =
            capture_logs(|| signature_verdict(Err(AppError::Internal("boom".to_string()))));
        assert!(
            matches!(result, Err(AppError::Unauthorized(msg)) if msg == "Authentication failed")
        );
        assert!(logs.contains("ERROR"));
        assert!(logs.contains("boom"));
        assert!(logs.contains("auth_failed"));
    }

    #[test]
    fn test_signature_verdict_wrong_signature_returns_uniform_401() {
        let (result, logs) = capture_logs(|| signature_verdict(Ok(false)));
        assert!(
            matches!(result, Err(AppError::Unauthorized(msg)) if msg == "Authentication failed")
        );
        assert!(logs.contains("auth_failed"));
    }

    #[test]
    fn test_signature_verdict_valid_signature_is_ok() {
        assert!(signature_verdict(Ok(true)).is_ok());
    }

    fn proto_headers(proto: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", proto.parse().unwrap());
        headers
    }

    #[test]
    fn test_is_https_single_value() {
        assert!(is_https(&proto_headers("https"), 1));
        assert!(!is_https(&proto_headers("http"), 1));
        assert!(!is_https(&proto_headers("https"), 0));
    }

    #[test]
    fn test_is_https_comma_joined_two_proxies() {
        assert!(is_https(&proto_headers("https, https"), 2));
        assert!(is_https(&proto_headers("https,http"), 2));
        assert!(!is_https(&proto_headers("http, https"), 2));
    }

    #[test]
    fn test_is_https_fewer_entries_than_proxies_uses_leftmost() {
        assert!(is_https(&proto_headers("https"), 2));
        assert!(!is_https(&proto_headers("http"), 2));
    }

    #[test]
    fn test_is_https_spoofed_leftmost_entry_ignored() {
        assert!(!is_https(&proto_headers("https, http"), 1));
        assert!(is_https(&proto_headers("http, https"), 1));
        assert!(!is_https(&proto_headers("https, http, https"), 2));
    }
}
