//! Admin API endpoints (all require AdminSession).

use crate::auth::middleware::{check_rate_limit, AdminSession, AppState};
use crate::error::AppError;
use crate::models::{CreateInviteResponse, InviteInfo, StoredInvite, UserInfo};
use crate::storage;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

/// Defense-in-depth rate limit for admin endpoints (per user_id).
const ADMIN_RATE_LIMIT_PER_MIN: u32 = 30;

/// Check admin rate limit by user_id.
async fn check_admin_rate_limit(
    con: &mut redis::aio::ConnectionManager,
    user_id: &str,
) -> Result<(), AppError> {
    let key = format!("ratelimit:admin:{}", user_id);
    let result = check_rate_limit(con, &key, ADMIN_RATE_LIMIT_PER_MIN, 60)
        .await
        .map_err(|e| AppError::Internal(format!("Rate limit check failed: {}", e)))?;

    if !result.allowed {
        tracing::warn!(action = "rate_limited", endpoint = "admin", user_id = %user_id, "Admin rate limit exceeded");
        return Err(AppError::RateLimited {
            retry_after: result.retry_after,
        });
    }
    Ok(())
}

/// POST /api/invites — Create invite
pub async fn create_invite(
    AdminSession(_session): AdminSession,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Get Redis connection (ConnectionManager handles auto-reconnection)
    let mut con = state.redis.clone();
    check_admin_rate_limit(&mut con, &_session.user_id).await?;

    // Generate invite token
    let token = nanoid::nanoid!(16);

    let invite = StoredInvite {
        token: token.clone(),
        created_at: crate::util::now_secs(),
    };

    // Store invite with TTL
    storage::user::store_invite(&mut con, &invite, state.config.invite_ttl_secs).await?;

    // Build invite URL
    let url = format!("/invite.html#{}", token);

    tracing::info!(action = "invite_created", token_prefix = %&token[..6], "Admin created invite");

    Ok(Json(CreateInviteResponse { token, url }))
}

/// GET /api/invites — List all invites
pub async fn list_invites(
    AdminSession(_session): AdminSession,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Get Redis connection (ConnectionManager handles auto-reconnection)
    let mut con = state.redis.clone();
    check_admin_rate_limit(&mut con, &_session.user_id).await?;

    let invites = storage::user::list_invites(&mut con).await?;

    // Convert to InviteInfo
    let invite_infos: Vec<InviteInfo> = invites
        .into_iter()
        .map(|inv| InviteInfo {
            token: inv.token,
            created_at: inv.created_at,
            expires_at: inv.created_at.saturating_add(state.config.invite_ttl_secs),
        })
        .collect();

    Ok(Json(invite_infos))
}

/// DELETE /api/invites/:token — Revoke invite
pub async fn revoke_invite(
    AdminSession(_session): AdminSession,
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    super::validate_id(&token, "invite token", 16)?;

    // Get Redis connection (ConnectionManager handles auto-reconnection)
    let mut con = state.redis.clone();
    check_admin_rate_limit(&mut con, &_session.user_id).await?;

    let deleted = storage::user::delete_invite(&mut con, &token).await?;

    if !deleted {
        return Err(AppError::NotFound("Invite not found".to_string()));
    }

    tracing::info!(action = "invite_revoked", token_prefix = %&token[..6], "Admin revoked invite");

    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/users — List all users
pub async fn list_users(
    AdminSession(_session): AdminSession,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Get Redis connection (ConnectionManager handles auto-reconnection)
    let mut con = state.redis.clone();
    check_admin_rate_limit(&mut con, &_session.user_id).await?;

    let users = storage::user::list_users(&mut con).await?;

    // Convert to UserInfo
    let user_infos: Vec<UserInfo> = users
        .into_iter()
        .map(|user| UserInfo {
            id: user.id,
            alias: user.alias,
            pubkey: user.pubkey,
            role: user.role,
            created_at: user.created_at,
        })
        .collect();

    Ok(Json(user_infos))
}

/// DELETE /api/users/:id — Revoke user
///
/// Deletes user, their pastes, and all their sessions.
pub async fn revoke_user(
    AdminSession(_session): AdminSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Don't allow deleting the admin user (check before validate_id
    // since admin ID is "admin" which doesn't match nanoid format)
    if id == "admin" {
        return Err(AppError::Forbidden("Cannot delete admin user".to_string()));
    }

    super::validate_id(&id, "user ID", 12)?;

    // Get Redis connection (ConnectionManager handles auto-reconnection)
    let mut con = state.redis.clone();
    check_admin_rate_limit(&mut con, &_session.user_id).await?;

    // Check if user exists
    let user = storage::user::get_user(&mut con, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Delete user's sessions first (prevents any in-flight auth from working)
    storage::session::delete_user_sessions(&mut con, &id).await?;

    // Delete user record (prevents new logins)
    storage::user::delete_user(&mut con, &id).await?;

    // Delete user's pastes last
    storage::paste::delete_user_pastes(&mut con, &state.config.paste_storage_path, &id).await?;

    tracing::warn!(action = "user_revoked", user_id = %id, alias = %user.alias, "Admin revoked user");

    Ok(StatusCode::NO_CONTENT)
}
