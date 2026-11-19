//! Paste API endpoints.

use crate::auth::middleware::{AdminSession, AppState, AuthSession, BlobReadsPerIp};
use crate::error::AppError;
use crate::models::{
    CreatePasteResponse, GetPasteResponse, PasteMetadata, ReservePasteResponse, StoredPasteMeta,
};
use crate::storage;
use crate::storage::blob::{BlobReadGuard, OpenedBlob};
use crate::storage::paste::StorePasteError;
use axum::{
    body::Body,
    extract::{multipart::MultipartError, ConnectInfo, Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::io::ReaderStream;

/// Paste bodies one client IP may have streaming at once. A read over it gets 429.
pub const MAX_BLOB_READS_PER_IP: usize = 4;

/// A paste body that is still streaming after
/// `BLOB_TRANSFER_BASE_SECS + size / BLOB_TRANSFER_MIN_BYTES_PER_SEC` seconds
/// is cut off, so a client that reads slowly cannot hold its read slots forever.
const BLOB_TRANSFER_BASE_SECS: u64 = 30;
const BLOB_TRANSFER_MIN_BYTES_PER_SEC: u64 = 64 * 1024;

fn transfer_deadline(len: u64) -> Duration {
    Duration::from_secs(BLOB_TRANSFER_BASE_SECS + len / BLOB_TRANSFER_MIN_BYTES_PER_SEC)
}

/// Read size for streaming a paste frame to the client.
const FRAME_STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Request body for PIN-gated paste retrieval.
#[derive(Debug, serde::Deserialize)]
pub struct PinAttemptRequest {
    /// HMAC-SHA256(derived_key, paste_id) — proves knowledge of PIN + key.
    pub pin_verifier: Option<String>,
}

/// POST /api/paste/reserve — Issue a paste ID
///
/// No auth and no request body. `create_paste` stores a paste only under an ID
/// issued here, and only once. The ID is not logged.
pub async fn reserve_paste(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<ReservePasteResponse>, AppError> {
    let mut con = state.redis.clone();

    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let ip_hash = super::hash_ip(&*state.ip_hmac_salt, &ip);
    super::enforce_rate_limit(
        &mut con,
        &format!("ratelimit:paste_reserve:{}", ip_hash),
        state.config.rate_limit_paste_per_min,
        60,
        Some(("paste_reserve", &ip_hash)),
    )
    .await?;

    let id = storage::paste::reserve_paste_id(&mut con).await?;
    Ok(Json(ReservePasteResponse { id }))
}

/// POST /api/paste — Create paste
///
/// Accepts multipart form with:
/// - "metadata" field: JSON PasteMetadata (paste_id, encrypted_metadata, paste_type, ttl_secs, burn_after_reading)
/// - "file" field: encrypted bytes
///
/// `paste_id` must be an ID from `reserve_paste` that no create request has
/// used yet. Any other ID gets 409.
///
/// Anonymous users: blobs up to `anon_max_bytes`, and a daily per-IP paste quota.
/// Authenticated users: blobs up to `max_upload_bytes`.
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
    if auth_session.is_none() {
        super::enforce_rate_limit(
            &mut con,
            &format!("ratelimit:anon_paste_day:{}", ip_hash),
            state.config.anon_max_pastes_per_ip_per_day,
            86400,
            Some(("anon_paste_day", &ip_hash)),
        )
        .await?;
    }
    let max_blob_bytes = if auth_session.is_some() {
        state.config.max_upload_bytes
    } else {
        state.config.anon_max_bytes
    };

    let mut metadata: Option<PasteMetadata> = None;
    let mut upload: Option<storage::blob::BlobUpload> = None;
    let mut field_count: u32 = 0;
    const MAX_MULTIPART_FIELDS: u32 = 4;
    // Legitimate metadata JSON is under ~6 KB (encrypted_metadata is capped at
    // 4096 decoded bytes). The cap is checked while reading, so an oversized
    // field is never fully buffered.
    const MAX_METADATA_FIELD_BYTES: usize = 16 * 1024;

    let too_large = || {
        AppError::PayloadTooLarge(format!(
            "File too large: exceeds limit of {} bytes",
            max_blob_bytes
        ))
    };
    let multipart_error = |context: &str, e: MultipartError| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            too_large()
        } else {
            AppError::BadRequest(format!("{}: {}", context, e))
        }
    };

    // Parse multipart form (capped at MAX_MULTIPART_FIELDS to prevent DoS)
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| multipart_error("Invalid multipart", e))?
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
                let mut data = Vec::new();
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| multipart_error("Failed to read metadata", e))?
                {
                    if data.len() + chunk.len() > MAX_METADATA_FIELD_BYTES {
                        return Err(AppError::BadRequest(format!(
                            "metadata too large (max {} bytes)",
                            MAX_METADATA_FIELD_BYTES
                        )));
                    }
                    data.extend_from_slice(&chunk);
                }
                metadata =
                    Some(serde_json::from_slice(&data).map_err(|e| {
                        AppError::BadRequest(format!("Invalid metadata JSON: {}", e))
                    })?);
            }
            "file" => {
                let mut file = storage::blob::BlobUpload::create(&state.config.paste_storage_path)
                    .await
                    .map_err(|e| AppError::Internal(format!("Failed to create upload: {}", e)))?;
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| multipart_error("Failed to read file", e))?
                {
                    if file.bytes_written() + chunk.len() as u64 > max_blob_bytes as u64 {
                        return Err(too_large());
                    }
                    file.write(&chunk).await.map_err(|e| {
                        AppError::Internal(format!("Failed to write upload: {}", e))
                    })?;
                }
                upload = Some(file);
            }
            _ => {}
        }
    }

    let metadata = metadata.ok_or_else(|| AppError::BadRequest("Missing metadata".to_string()))?;
    let upload = upload.ok_or_else(|| AppError::BadRequest("Missing file".to_string()))?;

    // Format check only. store_paste refuses an ID that was not reserved.
    super::validate_id(&metadata.paste_id, "paste ID", 12)?;

    // Require pin_verifier when has_pin is true; reject it when has_pin is false,
    // so an unchecked value can never be stored.
    if metadata.has_pin {
        let verifier = metadata.pin_verifier.as_deref().unwrap_or("");
        if verifier.is_empty() {
            return Err(AppError::BadRequest(
                "pin_verifier required when has_pin is true".to_string(),
            ));
        }
        // Validate it's valid base64 and 32 bytes (HMAC-SHA256 output)
        let decoded = general_purpose::STANDARD
            .decode(verifier)
            .map_err(|_| AppError::BadRequest("Invalid pin_verifier encoding".to_string()))?;
        if decoded.len() != 32 {
            return Err(AppError::BadRequest(
                "pin_verifier must be 32 bytes (HMAC-SHA256)".to_string(),
            ));
        }
    } else if metadata
        .pin_verifier
        .as_deref()
        .is_some_and(|v| !v.is_empty())
    {
        return Err(AppError::BadRequest(
            "pin_verifier not allowed when has_pin is false".to_string(),
        ));
    }

    // Validate encrypted_metadata: non-empty, valid base64, max 4096 decoded bytes.
    //
    // Headroom math (worst case):
    //   - 255-char multibyte filename → ~600 bytes JSON
    //   - Padded to next multiple of 512 → 1024 bytes plaintext
    //   - AES-256-GCM overhead: 12 (IV) + 1024 (padded plaintext) + 16 (tag) = 1052 bytes
    //   - 1052 << 4096, so the cap has ~3× headroom.
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

    // Use config default if client omitted ttl_secs.
    // ttl_secs=0 means "forever" (no expiration) — admin only to prevent Valkey memory exhaustion.
    let requested_ttl = metadata.ttl_secs.unwrap_or(state.config.default_ttl_secs);
    let ttl_secs = if requested_ttl == 0 {
        match &auth_session {
            Some(s) if s.role == crate::models::Role::Admin => 0,
            _ => {
                return Err(AppError::Forbidden(
                    "Forever pastes require an admin account".to_string(),
                ))
            }
        }
    } else {
        requested_ttl.clamp(60, state.config.max_ttl_secs)
    };

    let paste_id = metadata.paste_id;

    let meta = StoredPasteMeta {
        id: paste_id.clone(),
        encrypted_metadata: metadata.encrypted_metadata,
        paste_type: metadata.paste_type,
        filename: None,
        content_type: None,
        burn_after_reading: metadata.burn_after_reading,
        created_at: crate::util::now_secs(),
        owner_id: auth_session.as_ref().map(|s| s.user_id.clone()),
        has_pin: Some(metadata.has_pin),
        // Only store a verifier that passed the has_pin checks above.
        pin_verifier: if metadata.has_pin {
            metadata.pin_verifier
        } else {
            None
        },
        // store_paste computes and records the blob hash.
        content_sha256: None,
    };

    // A request timeout or client disconnect drops this handler. The store runs
    // in its own task so it is never cut off between the SETNX and user_pastes.
    let config = state.config.clone();
    let task_meta = meta.clone();
    tokio::spawn(async move {
        let result = async {
            // Store paste (use up the reservation, metadata to Valkey via SETNX,
            // then content to disk)
            storage::paste::store_paste(
                &mut con,
                &config.paste_storage_path,
                &task_meta,
                upload,
                ttl_secs,
                config.max_ttl_secs,
                config.max_pastes_per_user,
            )
            .await?;

            // On first upload, atomically update user TTL from idle to active.
            // Uses SCARD + TTL comparison to avoid race conditions between concurrent uploads.
            if let Some(ref user_id) = task_meta.owner_id {
                storage::paste::activate_user_on_first_upload(
                    &mut con,
                    user_id,
                    config.user_idle_ttl_secs,
                    config.user_active_ttl_secs,
                )
                .await?;
            }
            Ok::<(), StorePasteError>(())
        }
        .await;
        result.map_err(|e| match e {
            StorePasteError::Conflict => {
                tracing::debug!("Paste store rejected: ID not reserved or already used");
                AppError::Conflict(
                    "Paste ID is not reserved or was already used. \
                     Reload the page and try again."
                        .to_string(),
                )
            }
            StorePasteError::QuotaExceeded => {
                tracing::debug!("Paste store rejected: paste limit reached");
                AppError::BadRequest(format!(
                    "Paste limit reached ({} max)",
                    config.max_pastes_per_user
                ))
            }
            StorePasteError::Redis(e) => {
                tracing::error!(error = %e, "Paste store failed");
                AppError::from(e)
            }
        })
    })
    .await
    .map_err(|e| {
        tracing::error!(is_panic = e.is_panic(), "Paste store task failed");
        AppError::Internal("Paste store task failed".to_string())
    })??;

    tracing::info!(
        action = "paste_created",
        burn = meta.burn_after_reading,
        ttl = ttl_secs,
        "Paste created"
    );

    // Build response URL (paste ID in query param, frontend appends #key fragment)
    let url = format!("/view.html?id={}", paste_id);

    Ok(Json(CreatePasteResponse { id: paste_id, url }))
}

/// Encode the part of a paste frame that comes before the content:
/// a big-endian `u32` length `N`, then `N` bytes of JSON metadata.
pub fn encode_frame_prefix(meta: &GetPasteResponse) -> Result<Vec<u8>, AppError> {
    let json = serde_json::to_vec(meta).map_err(|e| {
        tracing::error!(error = %e, "Failed to serialize paste metadata");
        AppError::Internal("Failed to encode response".to_string())
    })?;
    let json_len = u32::try_from(json.len()).map_err(|_| {
        tracing::error!("Paste metadata too large to frame");
        AppError::Internal("Failed to encode response".to_string())
    })?;
    let mut prefix = Vec::with_capacity(4 + json.len());
    prefix.extend_from_slice(&json_len.to_be_bytes());
    prefix.extend_from_slice(&json);
    Ok(prefix)
}

/// An `AsyncRead` that holds a blob read permit and the blob's read guard for
/// as long as it lives.
///
/// Both are released when the response body is dropped: after the last byte
/// is sent, when the connection fails or times out, or when `deadline` passes.
/// Until then, a delete of the blob does not overwrite the bytes being streamed.
struct PermitReader<R> {
    inner: R,
    _permit: BlobReadPermit,
    _blob_guard: BlobReadGuard,
    deadline: tokio::time::Instant,
}

impl<R: AsyncRead + Unpin> AsyncRead for PermitReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if tokio::time::Instant::now() >= self.deadline {
            tracing::warn!("Paste body transfer passed its deadline, closing the connection");
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "paste body transfer deadline passed",
            )));
        }
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        // The status line and headers are already sent, so the client only
        // sees a cut-off body. Log the cause here.
        if let Poll::Ready(Err(e)) = &poll {
            tracing::error!(error = %e, "Failed to read blob while streaming paste body");
        }
        poll
    }
}

/// Build the 200 response for a paste GET or PIN attempt.
///
/// Wire format (`application/octet-stream`): a big-endian `u32` length `N`,
/// then `N` bytes of JSON metadata, then the raw ciphertext. With no blob
/// (the `needs_pin` probe) the frame has zero content bytes.
///
/// The blob is streamed from its open file handle in fixed-size chunks, so
/// memory use does not depend on the paste size. `permit` is held until the
/// body is dropped.
pub fn paste_frame_response(
    meta: &GetPasteResponse,
    blob: Option<(OpenedBlob, BlobReadPermit)>,
) -> Result<Response, AppError> {
    let prefix = encode_frame_prefix(meta)?;
    let content_len = blob.as_ref().map_or(0, |(opened, _)| opened.len);
    let total_len = prefix.len() as u64 + content_len;

    let body = match blob {
        Some((opened, permit)) => {
            let reader = PermitReader {
                inner: Cursor::new(prefix).chain(opened.file.take(opened.len)),
                _permit: permit,
                _blob_guard: opened.guard,
                deadline: tokio::time::Instant::now() + transfer_deadline(total_len),
            };
            Body::from_stream(ReaderStream::with_capacity(
                reader,
                FRAME_STREAM_CHUNK_BYTES,
            ))
        }
        None => Body::from(prefix),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, total_len)
        .body(body)
        .map_err(|e| AppError::Internal(format!("Failed to build paste response: {}", e)))
}

/// Metadata part of the frame for a paste that is served with its content.
fn served_paste_meta(meta: StoredPasteMeta) -> GetPasteResponse {
    // Return encrypted_metadata for new pastes, legacy fields for old pastes
    let encrypted_metadata = if meta.encrypted_metadata.is_empty() {
        None
    } else {
        Some(meta.encrypted_metadata)
    };
    GetPasteResponse {
        encrypted_metadata,
        filename: meta.filename,
        content_type: meta.content_type,
        burn_after_reading: meta.burn_after_reading,
        created_at: Some(meta.created_at),
        needs_pin: None,
    }
}

/// One of the [`MAX_BLOB_READS_PER_IP`] read slots of a client IP.
/// Dropping it frees the slot.
struct IpReadSlot {
    ip: IpAddr,
    reads_per_ip: BlobReadsPerIp,
}

impl Drop for IpReadSlot {
    fn drop(&mut self) {
        let mut reads = self.reads_per_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = reads.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                reads.remove(&self.ip);
            }
        }
    }
}

/// A client IP's read slot and a global blob read permit, held together by
/// a streaming paste body.
pub struct BlobReadPermit {
    _slot: IpReadSlot,
    _permit: OwnedSemaphorePermit,
}

/// Take a read slot of `ip` and a blob read permit without waiting.
///
/// Returns 429 when `ip` already has [`MAX_BLOB_READS_PER_IP`] reads
/// streaming, and 503 when every permit is in use. Both travel with the
/// response body and are released when the body is dropped.
pub fn acquire_blob_read_permit(
    permits: &Arc<Semaphore>,
    reads_per_ip: &BlobReadsPerIp,
    ip: IpAddr,
) -> Result<BlobReadPermit, AppError> {
    let slot = {
        let mut reads = reads_per_ip.lock().unwrap_or_else(|e| e.into_inner());
        let count = reads.entry(ip).or_insert(0);
        if *count >= MAX_BLOB_READS_PER_IP {
            return Err(AppError::RateLimited { retry_after: None });
        }
        *count += 1;
        IpReadSlot {
            ip,
            reads_per_ip: reads_per_ip.clone(),
        }
    };
    let permit = permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::ServiceUnavailable("No blob read permit free".to_string()))?;
    Ok(BlobReadPermit {
        _slot: slot,
        _permit: permit,
    })
}

/// GET /api/paste/:id — Get paste
///
/// Fetches encrypted paste. If burn_after_reading, deletes atomically.
/// A 200 body is a paste frame (see [`paste_frame_response`]).
pub async fn get_paste(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
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

    match meta.has_pin {
        Some(true) => {
            // PIN-gated: probe frame without content. No blob is read, so no
            // permit is taken.
            let probe = GetPasteResponse {
                encrypted_metadata: None,
                filename: None,
                content_type: None,
                burn_after_reading: meta.burn_after_reading,
                created_at: None,
                needs_pin: Some(true),
            };
            return paste_frame_response(&probe, None);
        }
        Some(false) => {}
        // Written before server-side PIN gating: it may be a PIN paste whose
        // ciphertext the server cannot gate, so it is never served.
        None => {
            tracing::warn!(
                action = "legacy_paste_refused",
                "Paste record has no has_pin field"
            );
            return Err(AppError::NotFound("Paste not found".to_string()));
        }
    }

    let permit = acquire_blob_read_permit(&state.blob_read_permits, &state.blob_reads_per_ip, ip)?;

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

    paste_frame_response(&served_paste_meta(paste.meta), Some((paste.blob, permit)))
}

/// POST /api/paste/:id — Attempt to retrieve a PIN-gated paste
///
/// Rate limited per IP per paste. Returns full content for PIN-gated pastes.
/// Returns 404 if paste doesn't exist or isn't PIN-gated.
/// Burns paste on first attempt if burn_after_reading is true.
/// A 200 body is a paste frame (see [`paste_frame_response`]).
pub async fn attempt_paste(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PinAttemptRequest>,
) -> Result<Response, AppError> {
    super::validate_id(&id, "paste ID", 12)?;

    // Take the blob read permit before any PIN attempt counter is touched, so
    // a busy server (503) or a full per-IP cap (429) never uses up a caller's
    // PIN attempts.
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxy_count);
    let permit = acquire_blob_read_permit(&state.blob_read_permits, &state.blob_reads_per_ip, ip)?;

    let mut con = state.redis.clone();

    // Rate limit globally per paste (distributed brute-force protection).
    // Check global first so an exhausted paste doesn't leak per-IP budget.
    let global_key = format!("ratelimit:pin_attempt_global:{}", id);
    super::enforce_rate_limit(
        &mut con,
        &global_key,
        state.config.rate_limit_pin_attempt_global,
        3600,
        Some(("pin_attempt_global", "per_paste")),
    )
    .await?;

    // Rate limit per IP per paste
    let ip_hash = super::hash_ip(&*state.ip_hmac_salt, &ip);
    let rate_limit_key = format!("ratelimit:pin_attempt:{}:{}", ip_hash, id);
    super::enforce_rate_limit(
        &mut con,
        &rate_limit_key,
        state.config.rate_limit_pin_attempt,
        60,
        Some(("pin_attempt_per_ip", &ip_hash)),
    )
    .await?;

    // Verify paste exists and is PIN-gated
    let meta = storage::paste::get_paste_meta(&mut con, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("Paste not found".to_string()))?;

    match meta.has_pin {
        Some(true) => {}
        Some(false) => return Err(AppError::NotFound("Paste not found".to_string())),
        None => {
            tracing::warn!(
                action = "legacy_paste_refused",
                "Paste record has no has_pin field"
            );
            return Err(AppError::NotFound("Paste not found".to_string()));
        }
    }

    // Verify PIN: constant-time compare submitted verifier against stored verifier
    let stored_verifier = meta.pin_verifier.as_deref().unwrap_or("");
    let submitted_verifier = body.pin_verifier.as_deref().unwrap_or("");

    if stored_verifier.is_empty() {
        tracing::warn!(
            action = "pin_verifier_missing",
            "PIN-gated paste has no stored verifier (data integrity issue)"
        );
        return Err(AppError::Forbidden("Invalid PIN".to_string()));
    }
    if submitted_verifier.is_empty() {
        return Err(AppError::Forbidden("Invalid PIN".to_string()));
    }

    let stored_bytes = general_purpose::STANDARD
        .decode(stored_verifier)
        .map_err(|_| {
            tracing::error!(
                action = "pin_verifier_corrupt",
                "Stored PIN verifier has invalid base64 encoding"
            );
            AppError::Internal("PIN verification error".to_string())
        })?;
    let submitted_bytes = general_purpose::STANDARD
        .decode(submitted_verifier)
        .map_err(|_| AppError::Forbidden("Invalid PIN".to_string()))?;

    if stored_bytes.len() != submitted_bytes.len()
        || stored_bytes.ct_eq(&submitted_bytes).unwrap_u8() != 1
    {
        return Err(AppError::Forbidden("Invalid PIN".to_string()));
    }

    // PIN verified — fetch full paste (triggers burn if applicable)
    let paste = storage::paste::get_paste_atomic(
        &mut con,
        &state.config.paste_storage_path,
        &id,
        state.config.max_upload_bytes as u64,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Paste not found".to_string()))?;

    paste_frame_response(&served_paste_meta(paste.meta), Some((paste.blob, permit)))
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

    tracing::info!(action = "paste_deleted", "Admin deleted paste");

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn frame_prefix_layout() {
        let meta = GetPasteResponse {
            encrypted_metadata: Some("bWV0YQ==".to_string()),
            filename: None,
            content_type: None,
            burn_after_reading: true,
            created_at: Some(1_700_000_000),
            needs_pin: None,
        };

        let prefix = encode_frame_prefix(&meta).unwrap();

        let json_len = u32::from_be_bytes(prefix[..4].try_into().unwrap()) as usize;
        assert_eq!(json_len, prefix.len() - 4);
        let json: serde_json::Value = serde_json::from_slice(&prefix[4..]).unwrap();
        assert!(json.get("burn_after_reading").is_some());
        assert!(json.get("encrypted_content").is_none());
    }

    #[test]
    fn transfer_deadline_scales_with_size() {
        assert_eq!(transfer_deadline(0), Duration::from_secs(30));
        assert_eq!(
            transfer_deadline(50 * 1024 * 1024),
            Duration::from_secs(30 + 800)
        );
    }

    #[tokio::test]
    async fn read_past_deadline_times_out_and_frees_read_slots() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        storage::blob::init_storage(storage_path).await.unwrap();
        storage::blob::write_blob(storage_path, "ab123456789012", b"content")
            .await
            .unwrap();
        let opened = storage::blob::open_blob(storage_path, "ab123456789012", 1024)
            .await
            .unwrap()
            .unwrap();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let reads_per_ip: BlobReadsPerIp = Arc::new(Mutex::new(HashMap::from([(ip, 1)])));
        let mut reader = PermitReader {
            inner: opened.file,
            _permit: BlobReadPermit {
                _slot: IpReadSlot {
                    ip,
                    reads_per_ip: reads_per_ip.clone(),
                },
                _permit: permits.clone().try_acquire_owned().unwrap(),
            },
            _blob_guard: opened.guard,
            deadline: tokio::time::Instant::now(),
        };

        let err = reader.read(&mut [0u8; 16]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        drop(reader);
        assert_eq!(permits.available_permits(), 1);
        assert!(reads_per_ip.lock().unwrap().is_empty());
    }
}
