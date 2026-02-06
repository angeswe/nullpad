//! API route handlers.

pub mod admin;
pub mod auth;
pub mod paste;

use crate::auth::middleware::AppState;
use crate::error::AppError;
use axum::{routing::get, routing::post, Router};

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

/// Build the API router with all endpoints.
pub fn api_router() -> Router<AppState> {
    Router::new()
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
