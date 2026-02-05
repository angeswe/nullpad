//! Axum extractors for authentication and rate limiting.

use crate::config::Config;
use crate::error::AppError;
use crate::models::Role;
use crate::storage;
use axum::{extract::FromRequestParts, http::request::Parts};
use redis::AsyncCommands;
use std::sync::Arc;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub redis: redis::Client,
    pub config: Arc<Config>,
}

/// Authenticated session extractor.
///
/// Extracts session from `Authorization: Bearer {token}` header.
/// Returns 401 Unauthorized if missing or invalid.
pub struct AuthSession {
    pub user_id: String,
    pub role: Role,
    pub token: String,
}

impl FromRequestParts<AppState> for AuthSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract Authorization header
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("Missing authorization header".to_string()))?;

        // Parse Bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("Invalid authorization format".to_string()))?
            .to_string();

        // Get Redis connection
        let mut con = state
            .redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

        // Look up session
        let session = storage::session::get_session(&mut con, &token)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid or expired session".to_string()))?;

        // Parse role
        let role = session
            .role
            .parse::<Role>()
            .map_err(|e| AppError::Internal(format!("Invalid role in session: {}", e)))?;

        Ok(AuthSession {
            user_id: session.user_id,
            role,
            token,
        })
    }
}

/// Optional authenticated session extractor.
///
/// Returns Some(AuthSession) if valid auth header present, None otherwise.
/// Does not fail the request if auth is missing or invalid.
impl FromRequestParts<AppState> for Option<AuthSession> {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try to extract auth session, but don't fail if it's not present
        match AuthSession::from_request_parts(parts, state).await {
            Ok(session) => Ok(Some(session)),
            Err(_) => Ok(None),
        }
    }
}

/// Admin-only session extractor.
///
/// Extracts session and verifies role is Admin.
/// Returns 403 Forbidden if not admin.
pub struct AdminSession(pub AuthSession);

impl FromRequestParts<AppState> for AdminSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // First extract the auth session
        let session = AuthSession::from_request_parts(parts, state).await?;

        // Check if admin
        if session.role != Role::Admin {
            return Err(AppError::Forbidden("Admin access required".to_string()));
        }

        Ok(AdminSession(session))
    }
}

/// Check rate limit using Redis INCR with TTL.
///
/// # Arguments
/// * `con` - Redis connection
/// * `key` - Rate limit key (e.g., "ratelimit:ip:127.0.0.1")
/// * `max` - Maximum requests allowed in window
/// * `window_secs` - Time window in seconds
///
/// # Returns
/// * `Ok(true)` if under limit
/// * `Ok(false)` if limit exceeded
pub async fn check_rate_limit<C>(
    con: &mut C,
    key: &str,
    max: u32,
    window_secs: u64,
) -> Result<bool, redis::RedisError>
where
    C: AsyncCommands,
{
    // Increment counter
    let count: u32 = con.incr(key, 1).await?;

    // Set TTL on first request
    if count == 1 {
        con.expire::<_, ()>(key, window_secs as i64).await?;
    }

    Ok(count <= max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_rate_limit() {
        // Note: This test requires a running Redis instance
        // Skip if REDIS_URL is not set
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        let client = match redis::Client::open(redis_url) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Skipping test: Redis not available");
                return;
            }
        };

        let mut con = match client.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Skipping test: Redis connection failed");
                return;
            }
        };

        let test_key = "test:ratelimit:unit";

        // Clean up before test
        let _: Result<(), _> = con.del(test_key).await;

        // First request should succeed
        let result = check_rate_limit(&mut con, test_key, 3, 60).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Second request should succeed
        let result = check_rate_limit(&mut con, test_key, 3, 60).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Third request should succeed
        let result = check_rate_limit(&mut con, test_key, 3, 60).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Fourth request should fail (over limit)
        let result = check_rate_limit(&mut con, test_key, 3, 60).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Clean up
        let _: Result<(), _> = con.del(test_key).await;
    }
}
