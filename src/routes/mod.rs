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
/// Trusts the first (leftmost) IP in X-Forwarded-For, which is the original client.
/// Falls back to the direct connection IP if no forwarded header is present.
pub fn client_ip(headers: &HeaderMap, addr: &SocketAddr) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
        })
        .unwrap_or_else(|| addr.ip())
}

/// GET /healthz — Health check endpoint for liveness/readiness probes.
///
/// Pings Redis and returns 200 if healthy, 503 if Redis is unreachable.
async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    match state.redis.get_multiplexed_async_connection().await {
        Ok(mut con) => match redis::cmd("PING")
            .query_async::<String>(&mut con)
            .await
        {
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
