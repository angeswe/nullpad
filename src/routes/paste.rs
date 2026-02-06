//! Paste API endpoints.

use crate::auth::middleware::{check_rate_limit, AdminSession, AppState, AuthSession};
use crate::error::AppError;
use crate::models::{CreatePasteResponse, GetPasteResponse, PasteMetadata, StoredPaste};
use crate::storage;
use axum::{
    extract::{ConnectInfo, Multipart, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;

/// POST /api/paste — Create paste
///
/// Accepts multipart form with:
/// - "metadata" field: JSON PasteMetadata
/// - "file" field: encrypted bytes
///
/// Public users: only .md/.txt extensions allowed
/// Authenticated users: any file type allowed
pub async fn create_paste(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    auth_session: Option<AuthSession>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    // Rate limit by IP (prefer X-Forwarded-For behind reverse proxy)
    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let rate_limit_key = format!("ratelimit:paste:{}", ip);
    let allowed = check_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_paste_per_min,
        60,
    )
    .await
    .map_err(|e| AppError::Internal(format!("Rate limit check failed: {}", e)))?;

    if !allowed {
        let mut hasher = std::hash::DefaultHasher::new();
        ip.hash(&mut hasher);
        let ip_hash = format!("{:x}", hasher.finish());
        tracing::warn!(action = "rate_limited", endpoint = "paste", ip_hash = %ip_hash, "Rate limit exceeded");
        return Err(AppError::RateLimited);
    }

    let mut metadata: Option<PasteMetadata> = None;
    let mut encrypted_content: Option<Vec<u8>> = None;

    // Parse multipart form
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Invalid multipart: {}", e)))?
    {
        let name = field
            .name()
            .ok_or_else(|| AppError::BadRequest("Field missing name".to_string()))?
            .to_string();

        match name.as_str() {
            "metadata" => {
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("Failed to read metadata: {}", e)))?;
                metadata =
                    Some(serde_json::from_slice(&data).map_err(|e| {
                        AppError::BadRequest(format!("Invalid metadata JSON: {}", e))
                    })?);
            }
            "file" => {
                encrypted_content = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("Failed to read file: {}", e)))?
                        .to_vec(),
                );
            }
            _ => {}
        }
    }

    let metadata = metadata.ok_or_else(|| AppError::BadRequest("Missing metadata".to_string()))?;
    let encrypted_content =
        encrypted_content.ok_or_else(|| AppError::BadRequest("Missing file".to_string()))?;

    // Validate filename: max 255 chars, no null bytes, no path separators
    if metadata.filename.len() > 255 {
        return Err(AppError::BadRequest(
            "Filename too long (max 255 characters)".to_string(),
        ));
    }
    if metadata.filename.contains('\0')
        || metadata.filename.contains('/')
        || metadata.filename.contains('\\')
    {
        return Err(AppError::BadRequest(
            "Filename contains invalid characters".to_string(),
        ));
    }
    if metadata.filename.is_empty() {
        return Err(AppError::BadRequest("Filename cannot be empty".to_string()));
    }

    // Validate content_type: max 127 chars, ASCII only, no null bytes
    if metadata.content_type.len() > 127 {
        return Err(AppError::BadRequest(
            "Content type too long (max 127 characters)".to_string(),
        ));
    }
    if !metadata.content_type.is_ascii() || metadata.content_type.contains('\0') {
        return Err(AppError::BadRequest(
            "Content type contains invalid characters".to_string(),
        ));
    }

    // Check file size
    if encrypted_content.len() > state.config.max_upload_bytes {
        return Err(AppError::BadRequest(format!(
            "File too large: {} bytes exceeds limit of {} bytes",
            encrypted_content.len(),
            state.config.max_upload_bytes
        )));
    }

    // Extract extension from filename (use rsplit_once to get only the final extension)
    let extension = metadata
        .filename
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_lowercase());

    // If no auth session, enforce public extension restrictions
    if auth_session.is_none() {
        match &extension {
            Some(ext) if state.config.public_allowed_extensions.contains(ext) => {}
            _ => {
                return Err(AppError::Forbidden(format!(
                    "File type not allowed for public uploads. Allowed: {}",
                    state.config.public_allowed_extensions.join(", ")
                )));
            }
        }
    }

    // Use config default if client omitted ttl_secs.
    // ttl_secs=0 means "forever" (no expiration) — trusted/admin users only.
    let requested_ttl = metadata.ttl_secs.unwrap_or(state.config.default_ttl_secs);
    let ttl_secs = if requested_ttl == 0 {
        match &auth_session {
            Some(s)
                if s.role == crate::models::Role::Trusted
                    || s.role == crate::models::Role::Admin =>
            {
                0
            }
            _ => {
                return Err(AppError::Forbidden(
                    "Forever pastes require a trusted account".to_string(),
                ))
            }
        }
    } else {
        requested_ttl.clamp(60, state.config.max_ttl_secs)
    };

    // Generate paste ID
    let paste_id = nanoid::nanoid!(12);

    // Create stored paste
    let paste = StoredPaste {
        id: paste_id.clone(),
        encrypted_content,
        filename: metadata.filename,
        content_type: metadata.content_type,
        burn_after_reading: metadata.burn_after_reading,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        owner_id: auth_session.as_ref().map(|s| s.user_id.clone()),
    };

    // Store paste
    storage::paste::store_paste(&mut con, &paste, ttl_secs, state.config.max_ttl_secs).await?;

    // On first upload, atomically update user TTL from idle to active.
    // Uses SCARD + TTL comparison to avoid race conditions between concurrent uploads.
    if let Some(ref session) = auth_session {
        storage::paste::activate_user_on_first_upload(
            &mut con,
            &session.user_id,
            state.config.user_idle_ttl_secs,
            state.config.user_active_ttl_secs,
        )
        .await?;
    }

    tracing::info!(
        action = "paste_created",
        paste_id = %paste_id,
        burn = paste.burn_after_reading,
        ttl = ttl_secs,
        "Paste created"
    );

    // Build response URL (paste ID in query param, frontend appends #key fragment)
    let url = format!("/view.html?id={}", paste_id);

    Ok(Json(CreatePasteResponse { id: paste_id, url }))
}

/// GET /api/paste/:id — Get paste
///
/// Fetches encrypted paste. If burn_after_reading, deletes atomically.
pub async fn get_paste(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    super::validate_id(&id, "paste ID", 12)?;

    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    // Rate limit paste reads to prevent burn-after-reading abuse
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let rate_limit_key = format!("ratelimit:paste_read:{}", ip);
    let allowed = check_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_paste_per_min * 5, // 5x write limit for reads
        60,
    )
    .await
    .map_err(|e| AppError::Internal(format!("Rate limit check failed: {}", e)))?;

    if !allowed {
        return Err(AppError::RateLimited);
    }

    // Atomic get-and-delete-if-burn: single Lua script prevents race conditions.
    // Returns the paste and deletes it only if burn_after_reading is true.
    let paste = storage::paste::get_paste_atomic(&mut con, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("Paste not found".to_string()))?;

    Ok(Json(GetPasteResponse {
        encrypted_content: general_purpose::STANDARD.encode(&paste.encrypted_content),
        filename: paste.filename,
        content_type: paste.content_type,
        burn_after_reading: paste.burn_after_reading,
        created_at: paste.created_at,
    }))
}

/// DELETE /api/paste/:id — Delete paste (admin only)
pub async fn delete_paste(
    AdminSession(_session): AdminSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    super::validate_id(&id, "paste ID", 12)?;

    let mut con = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    let deleted = storage::paste::delete_paste(&mut con, &id).await?;

    if !deleted {
        return Err(AppError::NotFound("Paste not found".to_string()));
    }

    tracing::info!(action = "paste_deleted", paste_id = %id, "Admin deleted paste");

    Ok(StatusCode::NO_CONTENT)
}
