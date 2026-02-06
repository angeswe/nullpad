//! Admin API endpoints (all require AdminSession).

use crate::auth::middleware::{AdminSession, AppState};
use crate::error::AppError;
use crate::models::{CreateInviteResponse, InviteInfo, Role, StoredInvite, UserInfo};
use crate::storage;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

/// POST /api/invites — Create invite
pub async fn create_invite(
    AdminSession(_session): AdminSession,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    // Generate invite token
    let token = nanoid::nanoid!(16);

    let invite = StoredInvite {
        token: token.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Store invite with TTL
    storage::user::store_invite(&mut con, &invite, state.config.invite_ttl_secs).await?;

    // Build invite URL
    let url = format!("/invite.html?token={}", token);

    tracing::info!(action = "invite_created", token = %token, "Admin created invite");

    Ok(Json(CreateInviteResponse { token, url }))
}

/// GET /api/invites — List all invites
pub async fn list_invites(
    AdminSession(_session): AdminSession,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    let invites = storage::user::list_invites(&mut con).await?;

    // Convert to InviteInfo
    let invite_infos: Vec<InviteInfo> = invites
        .into_iter()
        .map(|inv| InviteInfo {
            token: inv.token,
            created_at: inv.created_at,
            expires_at: inv.created_at + state.config.invite_ttl_secs,
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

    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    let deleted = storage::user::delete_invite(&mut con, &token).await?;

    if !deleted {
        return Err(AppError::NotFound("Invite not found".to_string()));
    }

    tracing::info!(action = "invite_revoked", token = %token, "Admin revoked invite");

    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/users — List all users
pub async fn list_users(
    AdminSession(_session): AdminSession,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

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
    super::validate_id(&id, "user ID", 12)?;

    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    // Check if user exists
    let user = storage::user::get_user(&mut con, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Don't allow deleting the admin user
    if user.role.parse::<Role>() == Ok(Role::Admin) {
        return Err(AppError::Forbidden("Cannot delete admin user".to_string()));
    }

    // Delete user's pastes
    storage::paste::delete_user_pastes(&mut con, &id).await?;

    // Delete user's sessions
    storage::session::delete_user_sessions(&mut con, &id).await?;

    // Delete user
    storage::user::delete_user(&mut con, &id).await?;

    tracing::warn!(action = "user_revoked", user_id = %id, alias = %user.alias, "Admin revoked user");

    Ok(StatusCode::NO_CONTENT)
}
