//! API route handlers.

pub mod admin;
pub mod auth;
pub mod paste;

use crate::auth::middleware::{AdminSession, AppState, AuthSession};
use crate::error::AppError;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    routing::post,
    Json, Router,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};

/// Check a rate limit key and return a RateLimited error if exceeded.
///
/// Wraps `check_rate_limit` with standard error mapping. The optional `warn_context`
/// tuple `(endpoint, identity)` controls whether a tracing::warn is emitted on limit.
pub async fn enforce_rate_limit<C>(
    con: &mut C,
    key: &str,
    max: u32,
    window_secs: u64,
    warn_context: Option<(&str, &str)>,
) -> Result<(), AppError>
where
    C: redis::AsyncCommands,
{
    let result = crate::auth::middleware::check_rate_limit(con, key, max, window_secs)
        .await
        .map_err(|e| AppError::Internal(format!("Rate limit check failed: {}", e)))?;

    if !result.allowed {
        if let Some((endpoint, identity)) = warn_context {
            tracing::warn!(action = "rate_limited", endpoint = %endpoint, identity = %identity, "Rate limit exceeded");
        }
        return Err(AppError::RateLimited {
            retry_after: result.retry_after,
        });
    }
    Ok(())
}

/// Validate that an alias is 2-64 characters, alphanumeric plus hyphens and underscores.
pub fn validate_alias(alias: &str) -> Result<(), AppError> {
    if alias.len() < 2 || alias.len() > 64 {
        return Err(AppError::BadRequest(
            "Alias must be 2-64 characters".to_string(),
        ));
    }
    if !alias
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest(
            "Alias may only contain alphanumeric characters, hyphens, and underscores".to_string(),
        ));
    }
    Ok(())
}

/// Validate that a string is a valid nanoid (alphanumeric, hyphens, underscores).
///
/// Requires expected_len >= 2 to prevent accepting empty strings.
pub fn validate_id(id: &str, label: &str, expected_len: usize) -> Result<(), AppError> {
    if expected_len < 2 {
        return Err(AppError::BadRequest(format!("Invalid {} format", label)));
    }
    if id.len() != expected_len
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest(format!("Invalid {} format", label)));
    }
    Ok(())
}

/// Hash an IP address with HMAC-SHA256 for use in Redis keys and logs.
pub fn hash_ip(salt: &[u8], ip: &IpAddr) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key size");
    mac.update(ip.to_string().as_bytes());
    let result = mac.finalize();
    let bytes = result.into_bytes();
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    })
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
                return normalize_ip(ip);
            }
        }
    }
    // No proxy trust or no valid XFF: use direct connection IP
    normalize_ip(addr.ip())
}

/// Normalize IPv4-mapped IPv6 addresses to their IPv4 equivalent.
/// Prevents rate limit bypass via `::ffff:1.2.3.4` vs `1.2.3.4`.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

/// GET /healthz — Health check endpoint for liveness/readiness probes.
///
/// Pings Redis and returns 200 if healthy, 503 if Redis is unreachable.
async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    // ConnectionManager handles auto-reconnection; just try to PING
    let mut con = state.redis.clone();
    match redis::cmd("PING").query_async::<String>(&mut con).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "error", "detail": "redis ping failed"})),
        ),
    }
}

/// Serve a protected static JS file with correct Content-Type.
async fn serve_protected_js(path: &str) -> Result<impl IntoResponse, AppError> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|_| AppError::NotFound("Not found".to_string()))?;
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        content,
    ))
}

/// GET /js/admin.js — Admin JS (requires admin auth)
async fn protected_admin_js(AdminSession(_): AdminSession) -> Result<impl IntoResponse, AppError> {
    serve_protected_js("static/js/admin.js").await
}

/// GET /js/trusted.js — Trusted JS (requires auth)
async fn protected_trusted_js(_session: AuthSession) -> Result<impl IntoResponse, AppError> {
    serve_protected_js("static/js/trusted.js").await
}

/// Build the API router with all endpoints.
pub fn api_router() -> Router<AppState> {
    Router::new()
        // Health check
        .route("/healthz", get(healthz))
        // Protected JS files (matched before ServeDir fallback)
        .route("/js/admin.js", get(protected_admin_js))
        .route("/js/trusted.js", get(protected_trusted_js))
        // Paste endpoints
        .route("/api/paste", post(paste::create_paste))
        .route(
            "/api/paste/{id}",
            get(paste::get_paste)
                .post(paste::attempt_paste)
                .delete(paste::delete_paste),
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use std::net::{IpAddr, SocketAddr};

    // --- validate_id tests ---

    #[test]
    fn test_validate_id_valid() {
        // Exact length, valid chars
        assert!(validate_id("aB3-_dEf9012", "test", 12).is_ok());
    }

    #[test]
    fn test_validate_id_too_short() {
        assert!(validate_id("abc", "test", 12).is_err());
    }

    #[test]
    fn test_validate_id_too_long() {
        assert!(validate_id("abcdefghijklm", "test", 12).is_err());
    }

    #[test]
    fn test_validate_id_empty() {
        assert!(validate_id("", "test", 12).is_err());
    }

    #[test]
    fn test_validate_id_special_chars() {
        // 12 chars but with invalid characters
        assert!(validate_id("abcdef!@#$%^", "test", 12).is_err());
        assert!(validate_id("abcdef ghijk", "test", 12).is_err()); // space
        assert!(validate_id("abcdef/ghijk", "test", 12).is_err()); // slash
        assert!(validate_id("abcdef.ghijk", "test", 12).is_err()); // dot
    }

    #[test]
    fn test_validate_id_unicode() {
        // Unicode chars that are 12 chars but not ASCII alphanumeric
        assert!(validate_id("abcdefghijkü", "test", 12).is_err());
    }

    #[test]
    fn test_validate_id_all_valid_chars() {
        // All allowed character types
        assert!(validate_id("aZ09-_", "test", 6).is_ok());
    }

    #[test]
    fn test_validate_id_zero_length() {
        // Zero-length expected: rejected because expected_len < 2
        assert!(validate_id("", "test", 0).is_err());
    }

    #[test]
    fn test_validate_id_length_one() {
        // Length 1: rejected because expected_len < 2
        assert!(validate_id("a", "test", 1).is_err());
    }

    // --- client_ip tests ---

    fn make_addr(ip: &str) -> SocketAddr {
        format!("{}:1234", ip).parse().unwrap()
    }

    fn make_headers_with_xff(xff: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", xff.parse().unwrap());
        headers
    }

    #[test]
    fn test_client_ip_no_proxy_trust() {
        // trusted_proxy_count=0: always use direct IP, ignore XFF
        let headers = make_headers_with_xff("1.2.3.4, 5.6.7.8");
        let addr = make_addr("10.0.0.1");
        assert_eq!(
            client_ip(&headers, &addr, 0),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_client_ip_no_xff_header() {
        // trusted_proxy_count > 0 but no XFF header: use direct IP
        let headers = HeaderMap::new();
        let addr = make_addr("10.0.0.1");
        assert_eq!(
            client_ip(&headers, &addr, 1),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_client_ip_one_proxy() {
        // XFF: "client, proxy1" with 1 trusted proxy -> pick client (index 0)
        let headers = make_headers_with_xff("1.2.3.4, 5.6.7.8");
        let addr = make_addr("10.0.0.1");
        assert_eq!(
            client_ip(&headers, &addr, 1),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_client_ip_two_proxies() {
        // XFF: "client, proxy1, proxy2" with 2 trusted proxies -> pick client (index 0)
        let headers = make_headers_with_xff("1.1.1.1, 2.2.2.2, 3.3.3.3");
        let addr = make_addr("10.0.0.1");
        assert_eq!(
            client_ip(&headers, &addr, 2),
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_client_ip_single_ip_xff_one_proxy() {
        // XFF has only 1 IP but trusted_proxy_count=1
        // target_idx = 1.saturating_sub(1+1) = 1.saturating_sub(2) = 0
        let headers = make_headers_with_xff("1.2.3.4");
        let addr = make_addr("10.0.0.1");
        assert_eq!(
            client_ip(&headers, &addr, 1),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_client_ip_whitespace_in_xff() {
        // XFF entries have extra whitespace
        let headers = make_headers_with_xff("  1.2.3.4 ,  5.6.7.8 ");
        let addr = make_addr("10.0.0.1");
        assert_eq!(
            client_ip(&headers, &addr, 1),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_client_ip_unparseable_target() {
        // Target IP position is not a valid IP -> falls back to direct IP
        let headers = make_headers_with_xff("not-an-ip, 5.6.7.8");
        let addr = make_addr("10.0.0.1");
        assert_eq!(
            client_ip(&headers, &addr, 1),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_client_ip_ipv6() {
        let headers = make_headers_with_xff("::1, fe80::1");
        let addr = make_addr("10.0.0.1");
        assert_eq!(
            client_ip(&headers, &addr, 1),
            "::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_client_ip_proxy_count_exceeds_xff() {
        // trusted_proxy_count=5 but only 2 IPs in XFF
        // target_idx = 2.saturating_sub(5+1) = 2.saturating_sub(6) = 0
        let headers = make_headers_with_xff("1.2.3.4, 5.6.7.8");
        let addr = make_addr("10.0.0.1");
        assert_eq!(
            client_ip(&headers, &addr, 5),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }
}
