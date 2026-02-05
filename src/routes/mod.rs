//! API route handlers.

pub mod admin;
pub mod auth;
pub mod paste;

use crate::auth::middleware::AppState;
use axum::{routing::get, routing::post, Router};

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
        .route("/api/register", post(auth::register))
        // Admin endpoints
        .route(
            "/api/invites",
            post(admin::create_invite).get(admin::list_invites),
        )
        .route("/api/invites/{token}", axum::routing::delete(admin::revoke_invite))
        .route("/api/users", get(admin::list_users))
        .route("/api/users/{id}", axum::routing::delete(admin::revoke_user))
}
