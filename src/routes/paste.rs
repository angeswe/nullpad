//! Paste API endpoints.

use crate::auth::middleware::{AdminSession, AppState, AuthSession};
use crate::error::AppError;
use crate::models::{
    CreatePasteResponse, GetPasteResponse, PasteMetadata, StoredPaste, StoredPasteMeta,
};
use crate::storage;
use axum::{
    extract::{ConnectInfo, Multipart, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use std::net::SocketAddr;

/// POST /api/paste — Create paste
///
/// Accepts multipart form with:
/// - "metadata" field: JSON PasteMetadata (paste_id, encrypted_metadata, paste_type, ttl_secs, burn_after_reading)
/// - "file" field: encrypted bytes
///
/// Public users: text paste type only
/// Authenticated users: text and file paste types
pub async fn create_paste(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    auth_session: Option<AuthSession>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let mut con = state.redis.clone();

    // Rate limit by IP
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let ip_hash = super::hash_ip(&*state.ip_hmac_salt, &ip);
    let rate_limit_key = format!("ratelimit:paste:{}", ip_hash);
    super::enforce_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_paste_per_min,
        60,
        Some(("paste", &ip_hash)),
    )
    .await?;

    let mut metadata: Option<PasteMetadata> = None;
    let mut encrypted_content: Option<Vec<u8>> = None;
    let mut field_count: u32 = 0;
    const MAX_MULTIPART_FIELDS: u32 = 4;

    // Parse multipart form (capped at MAX_MULTIPART_FIELDS to prevent DoS)
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Invalid multipart: {}", e)))?
    {
        field_count += 1;
        if field_count > MAX_MULTIPART_FIELDS {
            return Err(AppError::BadRequest(
                "Too many multipart fields".to_string(),
            ));
        }
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

    // Validate client-generated paste ID
    super::validate_id(&metadata.paste_id, "paste ID", 12)?;

    // Validate encrypted_metadata: non-empty, valid base64, max 4096 bytes decoded
    if metadata.encrypted_metadata.is_empty() {
        return Err(AppError::BadRequest(
            "Missing encrypted_metadata".to_string(),
        ));
    }
    let decoded_meta = general_purpose::STANDARD
        .decode(&metadata.encrypted_metadata)
        .map_err(|_| AppError::BadRequest("Invalid encrypted_metadata encoding".to_string()))?;
    if decoded_meta.len() > 4096 {
        return Err(AppError::BadRequest(
            "encrypted_metadata too large (max 4096 bytes)".to_string(),
        ));
    }

    // Validate paste_type: must be "text" or "file"
    if metadata.paste_type != "text" && metadata.paste_type != "file" {
        return Err(AppError::BadRequest(
            "paste_type must be \"text\" or \"file\"".to_string(),
        ));
    }

    // Public users can only create text pastes
    if auth_session.is_none() && metadata.paste_type == "file" {
        return Err(AppError::Forbidden(
            "File uploads require authentication".to_string(),
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

    // Enforce per-user paste count limit (0 = unlimited)
    if let Some(ref session) = auth_session {
        if state.config.max_pastes_per_user > 0 {
            let paste_ids = storage::paste::get_user_paste_ids(&mut con, &session.user_id).await?;
            if paste_ids.len() >= state.config.max_pastes_per_user {
                return Err(AppError::BadRequest(format!(
                    "Paste limit reached ({} max)",
                    state.config.max_pastes_per_user
                )));
            }
        }
    }

    // Use client-generated paste ID (validated above)
    let paste_id = metadata.paste_id;

    // Create stored paste (metadata + content)
    let paste = StoredPaste {
        meta: StoredPasteMeta {
            id: paste_id.clone(),
            encrypted_metadata: metadata.encrypted_metadata,
            paste_type: metadata.paste_type,
            filename: None,
            content_type: None,
            burn_after_reading: metadata.burn_after_reading,
            created_at: crate::util::now_secs(),
            owner_id: auth_session.as_ref().map(|s| s.user_id.clone()),
            has_pin: metadata.has_pin,
        },
        encrypted_content,
    };

    // Store paste (metadata to Redis via SETNX, then content to disk)
    storage::paste::store_paste(
        &mut con,
        &state.config.paste_storage_path,
        &paste,
        ttl_secs,
        state.config.max_ttl_secs,
    )
    .await
    .map_err(|e| {
        // store_paste returns UnexpectedReturnType with detail "conflict"
        // when the paste ID already exists (SETNX failed).
        if e.kind() == redis::ErrorKind::UnexpectedReturnType && e.detail() == Some("conflict") {
            AppError::Conflict("Paste ID already exists".to_string())
        } else {
            AppError::from(e)
        }
    })?;

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
        burn = paste.meta.burn_after_reading,
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

    let mut con = state.redis.clone();

    // Rate limit paste reads to prevent burn-after-reading abuse
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let ip_hash = super::hash_ip(&*state.ip_hmac_salt, &ip);
    let rate_limit_key = format!("ratelimit:paste_read:{}", ip_hash);
    super::enforce_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_paste_per_min * 5, // 5x write limit for reads
        60,
        None,
    )
    .await?;

    // Check if paste is PIN-gated (metadata only, no blob read, no burn)
    let meta = storage::paste::get_paste_meta(&mut con, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("Paste not found".to_string()))?;

    if meta.has_pin {
        // PIN-gated: return probe response without content
        return Ok(Json(GetPasteResponse {
            encrypted_content: None,
            encrypted_metadata: None,
            filename: None,
            content_type: None,
            burn_after_reading: meta.burn_after_reading,
            created_at: None,
            needs_pin: Some(true),
        }));
    }

    // Atomic get-and-delete-if-burn: single Lua script prevents race conditions.
    // Returns the paste and deletes it only if burn_after_reading is true.
    let paste = storage::paste::get_paste_atomic(
        &mut con,
        &state.config.paste_storage_path,
        &id,
        state.config.max_upload_bytes as u64,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Paste not found".to_string()))?;

    // Return encrypted_metadata for new pastes, legacy fields for old pastes
    let encrypted_metadata = if paste.meta.encrypted_metadata.is_empty() {
        None
    } else {
        Some(paste.meta.encrypted_metadata)
    };

    Ok(Json(GetPasteResponse {
        encrypted_content: Some(general_purpose::STANDARD.encode(&paste.encrypted_content)),
        encrypted_metadata,
        filename: paste.meta.filename,
        content_type: paste.meta.content_type,
        burn_after_reading: paste.meta.burn_after_reading,
        created_at: Some(paste.meta.created_at),
        needs_pin: None,
    }))
}

/// POST /api/paste/:id — Attempt to retrieve a PIN-gated paste
///
/// Rate limited per IP per paste. Returns full content for PIN-gated pastes.
/// Returns 404 if paste doesn't exist or isn't PIN-gated.
/// Burns paste on first attempt if burn_after_reading is true.
pub async fn attempt_paste(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    super::validate_id(&id, "paste ID", 12)?;

    let mut con = state.redis.clone();

    // Rate limit per IP per paste
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let ip_hash = super::hash_ip(&*state.ip_hmac_salt, &ip);
    let rate_limit_key = format!("ratelimit:pin_attempt:{}:{}", ip_hash, id);
    super::enforce_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_pin_attempt,
        60,
        Some(("pin_attempt", &ip_hash)),
    )
    .await?;

    // Verify paste exists and is PIN-gated
    let meta = storage::paste::get_paste_meta(&mut con, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("Paste not found".to_string()))?;

    if !meta.has_pin {
        return Err(AppError::NotFound("Paste not found".to_string()));
    }

    // Fetch full paste (triggers burn if applicable)
    let paste = storage::paste::get_paste_atomic(
        &mut con,
        &state.config.paste_storage_path,
        &id,
        state.config.max_upload_bytes as u64,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Paste not found".to_string()))?;

    let encrypted_metadata = if paste.meta.encrypted_metadata.is_empty() {
        None
    } else {
        Some(paste.meta.encrypted_metadata)
    };

    Ok(Json(GetPasteResponse {
        encrypted_content: Some(general_purpose::STANDARD.encode(&paste.encrypted_content)),
        encrypted_metadata,
        filename: paste.meta.filename,
        content_type: paste.meta.content_type,
        burn_after_reading: paste.meta.burn_after_reading,
        created_at: Some(paste.meta.created_at),
        needs_pin: None,
    }))
}

/// DELETE /api/paste/:id — Delete paste (admin only)
pub async fn delete_paste(
    AdminSession(_session): AdminSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    super::validate_id(&id, "paste ID", 12)?;

    let mut con = state.redis.clone();

    let deleted =
        storage::paste::delete_paste(&mut con, &state.config.paste_storage_path, &id).await?;

    if !deleted {
        return Err(AppError::NotFound("Paste not found".to_string()));
    }

    tracing::info!(action = "paste_deleted", paste_id = %id, "Admin deleted paste");

    Ok(StatusCode::NO_CONTENT)
}
