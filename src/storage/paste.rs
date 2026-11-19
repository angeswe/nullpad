//! Paste storage operations.
//!
//! Valkey key patterns:
//! - `paste:{nanoid}` — paste metadata (JSON, no content)
//! - `user_pastes:{user_id}` — SET of paste IDs owned by user
//!
//! Filesystem:
//! - `{storage_path}/{id[0..2]}/{id}` — encrypted content

use crate::models::StoredPasteMeta;
use crate::storage::blob::{self, BlobUpload, OpenedBlob};
use redis::{AsyncCommands, FromRedisValue};
use std::path::Path;

/// A paste whose record was read (and, for burn-after-reading, consumed) and
/// whose blob is open for streaming.
#[derive(Debug)]
pub struct OpenedPaste {
    pub meta: StoredPasteMeta,
    pub blob: OpenedBlob,
}

/// Why `store_paste` did not store a paste.
#[derive(Debug, thiserror::Error)]
pub enum StorePasteError {
    #[error("Paste ID already exists")]
    Conflict,
    #[error("Paste limit reached")]
    QuotaExceeded,
    #[error(transparent)]
    Redis(#[from] redis::RedisError),
}

/// Store a paste: claim ID in Valkey first (SETNX), then write content to disk.
///
/// Uses SET NX (set-if-not-exists) to atomically claim the paste ID, preventing
/// overwrites of existing pastes. If the ID already exists, returns
/// `StorePasteError::Conflict`.
///
/// The stored metadata always records the SHA-256 of the uploaded content
/// (`content_sha256`), whatever `meta.content_sha256` holds.
///
/// If the paste has an owner_id, one Lua script checks the owner's paste count
/// against `max_pastes_per_user` (0 = unlimited), claims the ID, and adds it to
/// the owner's paste set. At the limit it returns `StorePasteError::QuotaExceeded`.
/// `max_ttl_secs` is used for the user_pastes SET expiry (from config.max_ttl_secs).
///
/// If the blob commit fails, the record and the user_pastes entry are removed.
pub async fn store_paste<C>(
    con: &mut C,
    storage_path: &Path,
    meta: &StoredPasteMeta,
    upload: BlobUpload,
    ttl_secs: u64,
    max_ttl_secs: u64,
    max_pastes_per_user: usize,
) -> Result<(), StorePasteError>
where
    C: AsyncCommands,
{
    let key = format!("paste:{}", meta.id);
    // Tie the record to this blob. A blob left on disk by an expired paste
    // with the same ID then fails the check in get_paste_atomic.
    let stored_meta = StoredPasteMeta {
        content_sha256: Some(upload.sha256_hex()),
        ..meta.clone()
    };
    let json = serde_json::to_string(&stored_meta).map_err(super::json_serialize_err)?;
    let user_pastes_key = meta
        .owner_id
        .as_ref()
        .map(|owner_id| format!("user_pastes:{}", owner_id));

    match &user_pastes_key {
        Some(user_pastes_key) => {
            // KEYS[1] = paste key, KEYS[2] = user_pastes key
            // ARGV[1] = json, ARGV[2] = ttl (0 = forever), ARGV[3] = max pastes
            // (0 = unlimited), ARGV[4] = paste id, ARGV[5] = max_ttl_secs
            let script = redis::Script::new(
                r"
                local max = tonumber(ARGV[3])
                if max > 0 and redis.call('SCARD', KEYS[2]) >= max then
                    return 'quota'
                end
                local ttl = tonumber(ARGV[2])
                local claimed
                if ttl > 0 then
                    claimed = redis.call('SET', KEYS[1], ARGV[1], 'EX', ttl, 'NX')
                else
                    claimed = redis.call('SET', KEYS[1], ARGV[1], 'NX')
                end
                if not claimed then
                    return 'conflict'
                end
                redis.call('SADD', KEYS[2], ARGV[4])
                if ttl == 0 then
                    redis.call('PERSIST', KEYS[2])
                elseif redis.call('TTL', KEYS[2]) ~= -1 then
                    redis.call('EXPIRE', KEYS[2], ARGV[5])
                end
                return 'ok'
                ",
            );
            let outcome: String = script
                .key(&key)
                .key(user_pastes_key)
                .arg(&json)
                .arg(ttl_secs)
                .arg(max_pastes_per_user)
                .arg(&meta.id)
                .arg(max_ttl_secs)
                .invoke_async(con)
                .await?;
            match outcome.as_str() {
                "ok" => {}
                "conflict" => return Err(StorePasteError::Conflict),
                "quota" => return Err(StorePasteError::QuotaExceeded),
                other => {
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::UnexpectedReturnType,
                        "Unexpected store_paste script result",
                        other.to_string(),
                    ))
                    .into())
                }
            }
        }
        None => {
            let mut cmd = redis::cmd("SET");
            cmd.arg(&key).arg(&json);
            if ttl_secs > 0 {
                cmd.arg("EX").arg(ttl_secs);
            }
            cmd.arg("NX");
            // "OK" on success, nil when the key exists.
            let result: Option<String> = cmd.query_async(con).await?;
            if result.is_none() {
                return Err(StorePasteError::Conflict);
            }
        }
    }

    // Write content to disk (only after Valkey confirms the ID is ours).
    if let Err(e) = upload.commit(storage_path, &meta.id).await {
        let mut cleanup = redis::pipe();
        cleanup.atomic().del(&key).ignore();
        if let Some(user_pastes_key) = &user_pastes_key {
            cleanup.srem(user_pastes_key, &meta.id).ignore();
        }
        if let Err(cleanup_err) = cleanup.query_async::<()>(con).await {
            tracing::error!(
                error = %cleanup_err,
                "Failed to clean up Valkey keys after blob write failure"
            );
        }
        return Err(redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "Blob write failed",
            e.to_string(),
        ))
        .into());
    }

    Ok(())
}

/// Get paste metadata only (Valkey GET, no blob read, no burn side effects).
///
/// Used by PIN gating probe to check `has_pin` without consuming burn pastes.
pub async fn get_paste_meta<C>(
    con: &mut C,
    id: &str,
) -> Result<Option<StoredPasteMeta>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("paste:{}", id);
    let json: Option<String> = con.get(&key).await?;

    match json {
        Some(data) => {
            let meta: StoredPasteMeta =
                serde_json::from_str(&data).map_err(super::json_deserialize_err)?;
            Ok(Some(meta))
        }
        None => Ok(None),
    }
}

/// Get a paste atomically, deleting if burn-after-reading.
///
/// Reads the blob from disk FIRST to ensure content is available before
/// touching metadata. For burn-after-reading pastes, metadata is only
/// deleted after confirming the blob can be read, preventing data loss.
/// `max_blob_bytes` limits the blob size to prevent OOM.
///
/// NOTE: If Valkey AOF persistence is enabled, burn-after-reading metadata may
/// be retained in the AOF log even after deletion. The Lua DEL command is
/// recorded in the AOF. On AOF rewrite, the key won't appear (since it's
/// already deleted), but between rewrites the original SET + DEL are both
/// present. Consider periodic AOF rewrite (BGREWRITEAOF) or disabling AOF
/// if metadata retention is a concern.
/// Turn a blob read failure into the right outcome for `get_paste_atomic`.
///
/// `BlobError::InvalidId` means the sanitizer rejected the ID — it cannot be a
/// real paste, so this is logged at warn and treated the same as "not found"
/// (`Ok(None)`, which the route maps to 404).
///
/// Every other variant (`Io`, `TooLarge`, and any future non-ID variant) is an
/// infrastructure or data-integrity failure: the paste may well exist, but its
/// content could not be read. These are logged at error and propagated as an
/// error, which the route maps to 500 — never silently reported as "missing".
///
/// Deliberately matches every variant instead of using a wildcard `_` arm, so
/// a new `BlobError` variant fails to compile here until someone decides
/// which bucket it belongs in.
fn classify_blob_read_error(
    err: blob::BlobError,
) -> Result<Option<OpenedPaste>, redis::RedisError> {
    match err {
        blob::BlobError::InvalidId(_) => {
            tracing::warn!(
                error = %err,
                "Blob ID rejected by sanitizer; treating paste as not found"
            );
            Ok(None)
        }
        blob::BlobError::Io(_) | blob::BlobError::TooLarge(_) => {
            tracing::error!(error = %err, "Failed to read blob");
            Err(redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "Blob read failed",
                err.to_string(),
            )))
        }
    }
}

pub async fn get_paste_atomic<C>(
    con: &mut C,
    storage_path: &Path,
    id: &str,
    max_blob_bytes: u64,
) -> Result<Option<OpenedPaste>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("paste:{}", id);

    // Step 1: Open and hash the blob BEFORE touching metadata.
    // This ensures content is available before we atomically delete
    // metadata for burn-after-reading pastes. The open file handle is what
    // gets streamed, so the bytes sent are the bytes hashed here.
    let opened = match blob::open_blob(storage_path, id, max_blob_bytes).await {
        Ok(Some(opened)) => opened,
        Ok(None) => {
            let exists: bool = redis::cmd("EXISTS").arg(&key).query_async(con).await?;
            if exists {
                tracing::warn!("Paste metadata exists but blob missing on disk");
            }
            return Ok(None);
        }
        Err(e) => return classify_blob_read_error(e),
    };

    // Step 2: Lua script — GET metadata, check the blob hash, then DEL if
    // burn + SREM from user_pastes.
    //
    // The blob must be the one the record was stored with. Paste IDs are
    // client-chosen: after a paste expires, a new paste can claim its ID
    // before its blob replaces the old one on disk. Serving the old blob under
    // the new record would skip the old paste's PIN check. The check runs
    // before any DEL, so a mismatched read never consumes a burn paste.
    //
    // A record with no content_sha256 field was written before the field
    // existed and is not checked. Any other value that is not the blob's hash
    // is a mismatch, including JSON null (cjson.null is not nil).
    //
    // Replies: nil = no record; integer 0 = mismatch, nothing deleted;
    // string = the record JSON.
    let script = redis::Script::new(
        r#"
        local val = redis.call('GET', KEYS[1])
        if not val then
            return nil
        end
        local obj = cjson.decode(val)
        local h = obj.content_sha256
        if h ~= nil and h ~= ARGV[3] then
            return 0
        end
        if obj.burn_after_reading == true then
            redis.call('DEL', KEYS[1])
            if type(obj.owner_id) == 'string' then
                redis.call('SREM', ARGV[2] .. obj.owner_id, ARGV[1])
            end
        end
        return val
        "#,
    );

    let reply: redis::Value = script
        .key(&key)
        .arg(id)
        .arg("user_pastes:")
        .arg(&opened.sha256_hex)
        .invoke_async(con)
        .await?;

    let data = match reply {
        redis::Value::Nil => return Ok(None),
        redis::Value::Int(0) => {
            // The paste ID is deliberately not logged for this event.
            tracing::warn!(
                "Blob does not match paste metadata hash; record left in place, \
                 treating paste as not found"
            );
            return Ok(None);
        }
        other => String::from_redis_value(other)?,
    };

    let meta: StoredPasteMeta = serde_json::from_str(&data).map_err(super::json_deserialize_err)?;

    // Step 3: For burn-after-reading, delete the blob now. The read guard in
    // `opened` is registered, so the path is unlinked now and the content is
    // overwritten only after the response has finished streaming it.
    if meta.burn_after_reading {
        if let Err(e) = blob::delete_blob(storage_path, id).await {
            tracing::error!(error = %e, "Failed to delete burn blob");
        }
    }

    Ok(Some(OpenedPaste { meta, blob: opened }))
}

/// Delete a paste from Valkey and disk, cleaning up the owner's user_pastes SET.
///
/// Uses a Lua script to atomically fetch the metadata (for owner_id), delete it,
/// and SREM from the owner's user_pastes SET. Then deletes the blob from disk.
///
/// Returns true if the paste was deleted, false if it didn't exist.
pub async fn delete_paste<C>(
    con: &mut C,
    storage_path: &Path,
    id: &str,
) -> Result<bool, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("paste:{}", id);

    // Key prefixes passed as ARGV to avoid hardcoding in Lua
    let script = redis::Script::new(
        r#"
        local val = redis.call('GET', KEYS[1])
        if not val then
            return 0
        end
        redis.call('DEL', KEYS[1])
        local obj = cjson.decode(val)
        if type(obj.owner_id) == 'string' then
            redis.call('SREM', ARGV[2] .. obj.owner_id, ARGV[1])
        end
        return 1
        "#,
    );

    let deleted: i32 = script
        .key(&key)
        .arg(id)
        .arg("user_pastes:")
        .invoke_async(con)
        .await?;

    if deleted > 0 {
        // Delete blob from disk
        if let Err(e) = blob::delete_blob(storage_path, id).await {
            tracing::warn!(error = %e, "Failed to delete blob (may not exist)");
            // Continue anyway - metadata is already deleted
        }
    }

    Ok(deleted > 0)
}

/// Outcome of [`reserve_pin_attempt`].
#[derive(Debug, PartialEq, Eq)]
pub enum PinReservation {
    /// No paste record, or the paste has no PIN.
    NotFound,
    /// One failure was counted against the paste and the requester.
    Reserved { failures: u32 },
    /// The requester has used up its share of the paste's failures.
    IpShareUsed { retry_after_secs: u64 },
    /// The paste has used up its lifetime failure budget.
    Exhausted,
}

/// Count one PIN failure against the paste (`pin_failures` in its record) and
/// against the requester (`ip_key`) before the verifier is compared, so
/// concurrent wrong attempts can never exceed `max_failures`. A correct PIN
/// takes the failure back with [`refund_pin_attempt`].
///
/// `ip_key` expires with the paste, or after `ip_key_ttl_secs` when the paste
/// has no TTL.
///
/// The record is rewritten through cjson. StoredPasteMeta has no arrays,
/// keeps nulls as cjson.null, and its numbers are integers below 2^53, so the
/// rewritten JSON reads back the same through serde.
pub async fn reserve_pin_attempt<C>(
    con: &mut C,
    id: &str,
    ip_key: &str,
    max_failures: u32,
    max_failures_per_ip: u32,
    ip_key_ttl_secs: u64,
) -> Result<PinReservation, redis::RedisError>
where
    C: AsyncCommands,
{
    // Replies: {0} not found, {1, failures} reserved, {2, ttl} requester share
    // used, {3} exhausted.
    let script = redis::Script::new(
        r#"
        local val = redis.call('GET', KEYS[1])
        if not val then
            return {0}
        end
        local obj = cjson.decode(val)
        if obj.has_pin ~= true then
            return {0}
        end
        local ip_used = tonumber(redis.call('GET', KEYS[2]) or '0')
        if ip_used >= tonumber(ARGV[2]) then
            local ttl = redis.call('TTL', KEYS[2])
            if ttl < 1 then
                ttl = 1
            end
            return {2, ttl}
        end
        local failures = tonumber(obj.pin_failures or 0)
        if failures >= tonumber(ARGV[1]) then
            return {3}
        end
        obj.pin_failures = failures + 1
        redis.call('SET', KEYS[1], cjson.encode(obj), 'KEEPTTL')
        if redis.call('INCR', KEYS[2]) == 1 then
            local pttl = redis.call('PTTL', KEYS[1])
            if pttl > 0 then
                redis.call('PEXPIRE', KEYS[2], pttl)
            else
                redis.call('EXPIRE', KEYS[2], ARGV[3])
            end
        end
        return {1, failures + 1}
        "#,
    );

    let reply: Vec<u64> = script
        .key(format!("paste:{}", id))
        .key(ip_key)
        .arg(max_failures)
        .arg(max_failures_per_ip)
        .arg(ip_key_ttl_secs)
        .invoke_async(con)
        .await?;

    match reply.as_slice() {
        [0] => Ok(PinReservation::NotFound),
        [1, failures] => Ok(PinReservation::Reserved {
            failures: *failures as u32,
        }),
        [2, ttl] => Ok(PinReservation::IpShareUsed {
            retry_after_secs: *ttl,
        }),
        [3] => Ok(PinReservation::Exhausted),
        other => Err(redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "Unexpected reserve_pin_attempt script result",
            format!("{:?}", other),
        ))),
    }
}

/// Take back a failure counted by [`reserve_pin_attempt`]. A missing record
/// or `ip_key` is skipped: a burn paste may already be gone.
pub async fn refund_pin_attempt<C>(
    con: &mut C,
    id: &str,
    ip_key: &str,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let script = redis::Script::new(
        r#"
        local val = redis.call('GET', KEYS[1])
        if val then
            local obj = cjson.decode(val)
            local failures = tonumber(obj.pin_failures or 0)
            if failures > 0 then
                obj.pin_failures = failures - 1
                redis.call('SET', KEYS[1], cjson.encode(obj), 'KEEPTTL')
            end
        end
        if tonumber(redis.call('GET', KEYS[2]) or '0') > 0 then
            redis.call('DECR', KEYS[2])
        end
        return 1
        "#,
    );

    let _: i64 = script
        .key(format!("paste:{}", id))
        .key(ip_key)
        .invoke_async(con)
        .await?;
    Ok(())
}

/// Atomically activate a user's TTL on their first upload.
///
/// Uses a Lua script to check if the user_pastes set has exactly 1 member
/// and the user key TTL is still at the idle value. Only updates if both
/// conditions are true, preventing race conditions between concurrent uploads.
pub async fn activate_user_on_first_upload<C>(
    con: &mut C,
    user_id: &str,
    idle_ttl_secs: u64,
    active_ttl_secs: u64,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let user_pastes_key = format!("user_pastes:{}", user_id);
    let user_key = format!("user:{}", user_id);
    let alias_key_prefix = "alias:";

    let script = redis::Script::new(
        r#"
        local count = redis.call('SCARD', KEYS[1])
        if count ~= 1 then
            return 0
        end
        local ttl = redis.call('TTL', KEYS[2])
        local idle_ttl = tonumber(ARGV[1])
        local active_ttl = tonumber(ARGV[2])
        -- Only update if TTL is close to idle value (within 60s tolerance)
        if ttl > 0 and ttl > (idle_ttl - 60) then
            redis.call('EXPIRE', KEYS[2], active_ttl)
            -- Also update alias key TTL
            local user_json = redis.call('GET', KEYS[2])
            if user_json then
                local user = cjson.decode(user_json)
                if type(user.alias) == 'string' then
                    redis.call('EXPIRE', ARGV[3] .. user.alias, active_ttl)
                end
            end
            return 1
        end
        return 0
        "#,
    );

    let _: i32 = script
        .key(&user_pastes_key)
        .key(&user_key)
        .arg(idle_ttl_secs)
        .arg(active_ttl_secs)
        .arg(alias_key_prefix)
        .invoke_async(con)
        .await?;

    Ok(())
}

/// Delete all pastes owned by a user (Valkey metadata + disk blobs).
///
/// First fetches paste IDs, then deletes Valkey metadata via Lua script,
/// then deletes blobs from disk. Blob deletion failures are logged but
/// don't fail the operation (orphaned blobs are cleaned up by cleanup job).
pub async fn delete_user_pastes<C>(
    con: &mut C,
    storage_path: &Path,
    user_id: &str,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let user_pastes_key = format!("user_pastes:{}", user_id);

    // First get the list of paste IDs (for blob deletion)
    let paste_ids: Vec<String> = con.smembers(&user_pastes_key).await?;

    if paste_ids.is_empty() {
        // Clean up empty set if it exists
        con.del::<_, ()>(&user_pastes_key).await?;
        return Ok(());
    }

    // Delete Valkey metadata via Lua script
    let script = redis::Script::new(
        r#"
        local user_pastes_key = KEYS[1]
        local paste_prefix = ARGV[1]

        local paste_ids = redis.call('SMEMBERS', user_pastes_key)
        if #paste_ids == 0 then
            redis.call('DEL', user_pastes_key)
            return {0, 0}
        end

        local deleted = {}
        local failed = 0

        for i, paste_id in ipairs(paste_ids) do
            local paste_key = paste_prefix .. paste_id
            local ok = pcall(function()
                redis.call('DEL', paste_key)
            end)
            if ok then
                table.insert(deleted, paste_id)
            else
                failed = failed + 1
            end
        end

        if failed == 0 then
            redis.call('DEL', user_pastes_key)
        elseif #deleted > 0 then
            redis.call('SREM', user_pastes_key, unpack(deleted))
        end

        return {#deleted, #paste_ids}
        "#,
    );

    let result: Vec<i32> = script
        .key(&user_pastes_key)
        .arg("paste:")
        .invoke_async(con)
        .await?;

    if result.len() >= 2 && result[0] < result[1] {
        tracing::warn!(
            action = "paste_cleanup_partial",
            deleted = result[0],
            total = result[1],
            "Partial paste deletion during user cleanup"
        );
    }

    // Delete blobs from disk (best effort - failures logged but don't fail operation)
    for paste_id in paste_ids {
        if let Err(e) = blob::delete_blob(storage_path, &paste_id).await {
            tracing::warn!(error = %e, "Failed to delete user paste blob");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An I/O failure (disk full, unmounted volume, EACCES, corruption, etc.)
    /// must not present as "paste does not exist" — it must propagate as an
    /// error so the route returns 500, not 404.
    #[test]
    fn test_classify_blob_read_error_io_propagates_as_err() {
        let io_err = std::io::Error::other("simulated unreadable blob");
        let result = classify_blob_read_error(blob::BlobError::Io(io_err));
        assert!(
            result.is_err(),
            "expected an I/O blob read failure to propagate as Err, got {:?}",
            result
        );
    }

    /// A blob exceeding the configured size limit is an infrastructure/data
    /// condition, not evidence the ID is bogus — it must also propagate as an
    /// error (500), not be swallowed into Ok(None) (404).
    #[test]
    fn test_classify_blob_read_error_too_large_propagates_as_err() {
        let result =
            classify_blob_read_error(blob::BlobError::TooLarge("blob too large".to_string()));
        assert!(
            result.is_err(),
            "expected an oversized blob to propagate as Err, got {:?}",
            result
        );
    }

    /// A sanitizer rejection means the ID could never map to a real paste —
    /// this is the one case that should still present as "not found" (404).
    #[test]
    fn test_classify_blob_read_error_invalid_id_yields_ok_none() {
        let result =
            classify_blob_read_error(blob::BlobError::InvalidId("invalid characters".to_string()));
        assert!(
            matches!(result, Ok(None)),
            "expected an InvalidId blob read failure to yield Ok(None), got {:?}",
            result
        );
    }

    /// FIPS 180-2 test vector: SHA-256("abc").
    #[test]
    fn content_sha256_hex_matches_known_vector() {
        assert_eq!(
            blob::content_sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
