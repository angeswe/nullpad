//! Security headers middleware.
//!
//! Implements:
//! - nullpad-kry: Essential security headers (Referrer-Policy, X-Content-Type-Options, etc.)
//! - nullpad-2hm: Content Security Policy hardening

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};

/// Middleware that adds comprehensive security headers to all responses.
///
/// This middleware implements defense-in-depth security measures:
///
/// ## Critical Headers (nullpad-kry)
///
/// - **Referrer-Policy: no-referrer**
///   CRITICAL: Prevents URL fragments (containing decryption keys) from leaking
///   via the Referer header when users navigate away from the page.
///
/// - **X-Content-Type-Options: nosniff**
///   Prevents MIME type sniffing attacks by forcing browsers to respect
///   declared Content-Type headers.
///
/// - **X-Frame-Options: DENY**
///   Prevents clickjacking by disallowing the page from being embedded
///   in frames, iframes, or objects.
///
/// - **Strict-Transport-Security**
///   Forces HTTPS connections for 2 years (including subdomains) and
///   enables HSTS preloading to prevent downgrade attacks.
///
/// - **Permissions-Policy**
///   Disables sensitive browser features (camera, microphone, geolocation,
///   payment) to reduce attack surface.
///
/// ## Content Security Policy (nullpad-2hm)
///
/// Implements a strict CSP that:
/// - Allows resources only from same origin (`default-src 'self'`)
/// - Permits scripts only from same origin (no inline, no eval)
/// - Allows styles from same origin + Google Fonts
/// - Loads fonts from Google Fonts CDN
/// - Prevents framing (`frame-ancestors 'none'`)
/// - Restricts base URLs and form actions to same origin
///
/// # Usage
///
/// ```rust,no_run
/// use axum::Router;
/// use axum::middleware;
/// use nullpad::middleware::security_headers;
///
/// let app: Router = Router::new()
///     .layer(middleware::from_fn(security_headers));
/// ```
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // nullpad-kry: Essential security headers
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );

    // nullpad-2hm: Content Security Policy hardening
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'wasm-unsafe-eval'; \
             style-src 'self' fonts.googleapis.com; \
             font-src fonts.gstatic.com; \
             object-src 'none'; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action 'self'",
        ),
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        response::IntoResponse,
        Router,
    };
    use tower::ServiceExt;

    async fn test_handler() -> impl IntoResponse {
        (StatusCode::OK, "test response")
    }

    #[tokio::test]
    async fn test_security_headers_applied() {
        // Create a test router with the security headers middleware
        let app = Router::new()
            .route("/", axum::routing::get(test_handler))
            .layer(middleware::from_fn(security_headers));

        // Make a test request
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let headers = response.headers();

        // Verify cache control
        assert_eq!(
            headers.get("cache-control").unwrap(),
            "no-store",
            "Cache-Control must be no-store to prevent caching encrypted content"
        );

        // Verify nullpad-kry headers
        assert_eq!(
            headers.get("referrer-policy").unwrap(),
            "no-referrer",
            "Referrer-Policy must be no-referrer to prevent key leakage"
        );
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            headers.get("strict-transport-security").unwrap(),
            "max-age=63072000; includeSubDomains; preload"
        );
        assert_eq!(
            headers.get("permissions-policy").unwrap(),
            "camera=(), microphone=(), geolocation=(), payment=()"
        );

        // Verify nullpad-2hm CSP header
        let csp = headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self' 'wasm-unsafe-eval'"));
        assert!(csp.contains("style-src 'self' fonts.googleapis.com"));
        assert!(csp.contains("font-src fonts.gstatic.com"));
        assert!(csp.contains("object-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("base-uri 'self'"));
        assert!(csp.contains("form-action 'self'"));
    }

    #[tokio::test]
    async fn test_response_body_preserved() {
        let app = Router::new()
            .route("/", axum::routing::get(test_handler))
            .layer(middleware::from_fn(security_headers));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify body is preserved
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "test response");
    }
}
