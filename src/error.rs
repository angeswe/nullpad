//! Error types and Axum response conversions.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Application error types.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Rate limited")]
    RateLimited,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Internal(msg) => {
                // Log detailed error server-side, return generic message to client
                tracing::error!(error = %msg, "Internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded".to_string(),
            ),
        };

        let body = Json(json!({
            "error": message
        }));

        (status, body).into_response()
    }
}

// Convenience conversions from common error types
impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        AppError::Internal(format!("Redis error: {}", err))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Internal(format!("JSON error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    /// Extract status code and JSON body from an AppError response.
    async fn error_response(err: AppError) -> (StatusCode, serde_json::Value) {
        let response = err.into_response();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn test_internal_hides_details() {
        // CRITICAL: Internal error must NOT leak detailed message to client
        let (status, body) = error_response(AppError::Internal(
            "Redis connection refused at 10.0.0.5:6379".to_string(),
        ))
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "Internal server error");
        // Must NOT contain the actual error details
        assert!(!body["error"].as_str().unwrap().contains("Redis"));
        assert!(!body["error"].as_str().unwrap().contains("10.0.0.5"));
    }

    #[tokio::test]
    async fn test_bad_request() {
        let (status, body) =
            error_response(AppError::BadRequest("Invalid format".to_string())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "Invalid format");
    }

    #[tokio::test]
    async fn test_unauthorized() {
        let (status, body) =
            error_response(AppError::Unauthorized("Authentication failed".to_string())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "Authentication failed");
    }

    #[tokio::test]
    async fn test_forbidden() {
        let (status, body) =
            error_response(AppError::Forbidden("Admin access required".to_string())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "Admin access required");
    }

    #[tokio::test]
    async fn test_not_found() {
        let (status, body) =
            error_response(AppError::NotFound("Paste not found".to_string())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "Paste not found");
    }

    #[tokio::test]
    async fn test_rate_limited() {
        let (status, body) = error_response(AppError::RateLimited).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"], "Rate limit exceeded");
    }

    #[test]
    fn test_from_redis_error() {
        let redis_err = redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "test context",
            "connection refused".to_string(),
        ));
        let app_err = AppError::from(redis_err);
        match app_err {
            AppError::Internal(msg) => assert!(msg.contains("Redis error")),
            _ => panic!("Expected Internal variant"),
        }
    }

    #[test]
    fn test_from_serde_error() {
        let serde_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let app_err = AppError::from(serde_err);
        match app_err {
            AppError::Internal(msg) => assert!(msg.contains("JSON error")),
            _ => panic!("Expected Internal variant"),
        }
    }
}
