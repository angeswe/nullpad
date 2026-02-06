//! API route handlers.

pub mod admin;
pub mod auth;
pub mod paste;

use crate::auth::middleware::AppState;
use crate::error::AppError;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    routing::post,
    Json, Router,
};
use std::net::{IpAddr, SocketAddr};

/// Validate that a string is a valid nanoid (alphanumeric, hyphens, underscores).
pub fn validate_id(id: &str, label: &str, expected_len: usize) -> Result<(), AppError> {
    if id.len() != expected_len
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest(format!("Invalid {} format", label)));
    }
    Ok(())
}

/// Extract client IP from X-Forwarded-For header, falling back to ConnectInfo.
///
/// When `trusted_proxy_count` > 0, reads the Nth-from-right IP in X-Forwarded-For
/// (e.g., with 1 trusted proxy, reads the 2nd-from-right, which is the real client).
/// When `trusted_proxy_count` == 0, falls back to direct connection IP (no proxy trust).
pub fn client_ip(headers: &HeaderMap, addr: &SocketAddr, trusted_proxy_count: usize) -> IpAddr {
    if trusted_proxy_count > 0 {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            let ips: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
            // With N trusted proxies, the real client IP is at position len - N - 1
            // (proxies append, so rightmost N entries are proxy IPs)
            let target_idx = ips.len().saturating_sub(trusted_proxy_count + 1);
            if let Ok(ip) = ips[target_idx].parse::<IpAddr>() {
                return ip;
            }
        }
    }
    // No proxy trust or no valid XFF: use direct connection IP
    addr.ip()
}

/// GET /healthz — Health check endpoint for liveness/readiness probes.
///
/// Pings Redis and returns 200 if healthy, 503 if Redis is unreachable.
async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    match state.redis.get_multiplexed_async_connection().await {
        Ok(mut con) => match redis::cmd("PING").query_async::<String>(&mut con).await {
            Ok(_) => (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))),
            Err(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"status": "error", "detail": "redis ping failed"})),
            ),
        },
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "error", "detail": "redis unreachable"})),
        ),
    }
}

/// Build the API router with all endpoints.
pub fn api_router() -> Router<AppState> {
    Router::new()
        // Health check
        .route("/healthz", get(healthz))
        // Paste endpoints
        .route("/api/paste", post(paste::create_paste))
        .route(
            "/api/paste/{id}",
            get(paste::get_paste).delete(paste::delete_paste),
        )
        // Auth endpoints
        .route("/api/auth/challenge", post(auth::request_challenge))
        .route("/api/auth/verify", post(auth::verify_challenge))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/register", post(auth::register))
        // Admin endpoints
        .route(
            "/api/invites",
            post(admin::create_invite).get(admin::list_invites),
        )
        .route(
            "/api/invites/{token}",
            axum::routing::delete(admin::revoke_invite),
        )
        .route("/api/users", get(admin::list_users))
        .route("/api/users/{id}", axum::routing::delete(admin::revoke_user))
}
