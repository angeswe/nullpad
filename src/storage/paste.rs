//! Paste storage operations.
//!
//! Redis key patterns:
//! - `paste:{nanoid}` — paste metadata (JSON, no content)
//! - `user_pastes:{user_id}` — SET of paste IDs owned by user
//!
//! Filesystem:
//! - `{storage_path}/{id[0..2]}/{id}` — encrypted content

use crate::models::{StoredPaste, StoredPasteMeta};
use crate::storage::blob;
use redis::AsyncCommands;
use std::path::Path;

/// Store a paste: content on disk, metadata in Redis.
///
/// If the paste has an owner_id, also add the paste ID to the user's paste set.
/// `max_ttl_secs` is used for the user_pastes SET expiry (from config.max_ttl_secs).
pub async fn store_paste<C>(
    con: &mut C,
    storage_path: &Path,
    paste: &StoredPaste,
    ttl_secs: u64,
    max_ttl_secs: u64,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    // Write content to disk first (so we don't have orphan metadata)
    blob::write_blob(storage_path, &paste.meta.id, &paste.encrypted_content)
        .await
        .map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "Blob write failed",
                e.to_string(),
            ))
        })?;

    let key = format!("paste:{}", paste.meta.id);
    let json = serde_json::to_string(&paste.meta).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "JSON serialize",
            e.to_string(),
        ))
    })?;

    // Store metadata: ttl_secs=0 means forever (no expiration)
    if ttl_secs == 0 {
        con.set::<_, _, ()>(&key, json).await?;
    } else {
        con.set_ex::<_, _, ()>(&key, json, ttl_secs).await?;
    }

    // If paste has an owner, add to user's paste set
    if let Some(ref owner_id) = paste.meta.owner_id {
        let user_pastes_key = format!("user_pastes:{}", owner_id);
        con.sadd::<_, _, ()>(&user_pastes_key, &paste.meta.id)
            .await?;
        if ttl_secs == 0 {
            // Forever paste: persist the user_pastes set (remove any TTL)
            con.persist::<_, ()>(&user_pastes_key).await?;
        } else {
            // Only set TTL if the key isn't already persistent (TTL != -1)
            // This prevents overwriting persistent state from forever pastes
            let current_ttl: i64 = redis::cmd("TTL")
                .arg(&user_pastes_key)
                .query_async(con)
                .await?;
            if current_ttl != -1 {
                con.expire::<_, ()>(&user_pastes_key, max_ttl_secs as i64)
                    .await?;
            }
        }
    }

    Ok(())
}

/// Get a paste atomically, deleting if burn-after-reading.
///
/// Single Lua script avoids the check-then-act race condition where two
/// concurrent requests could both see burn_after_reading=true before either
/// deletes the metadata. Uses cjson.decode for reliable JSON parsing and
/// cleans up user_pastes SET on burn deletion.
///
/// Content is read from disk after Redis operation succeeds.
/// For burn-after-reading, deletes blob BEFORE returning (atomic burn).
pub async fn get_paste_atomic<C>(
    con: &mut C,
    storage_path: &Path,
    id: &str,
) -> Result<Option<StoredPaste>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("paste:{}", id);

    // Lua script: GET metadata, parse JSON for burn flag, DEL if burn + SREM from user_pastes
    // Now fast since metadata is small (~200 bytes vs 10MB+ content)
    let script = redis::Script::new(
        r#"
        local val = redis.call('GET', KEYS[1])
        if not val then
            return nil
        end
        local obj = cjson.decode(val)
        if obj.burn_after_reading == true then
            redis.call('DEL', KEYS[1])
            if type(obj.owner_id) == 'string' then
                redis.call('SREM', ARGV[2] .. obj.owner_id, ARGV[1])
            end
        end
        return val
        "#,
    );

    let json: Option<String> = script
        .key(&key)
        .arg(id)
        .arg("user_pastes:")
        .invoke_async(con)
        .await?;

    match json {
        Some(data) => {
            let meta: StoredPasteMeta = serde_json::from_str(&data).map_err(|e| {
                redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "JSON deserialize",
                    e.to_string(),
                ))
            })?;

            // Read content from disk
            // Treat blob errors as "not found" to gracefully handle orphaned metadata
            // (e.g., pastes created before blob migration, or disk issues)
            let encrypted_content = match blob::read_blob(storage_path, id).await {
                Ok(Some(content)) => content,
                Ok(None) => {
                    // Blob missing - orphaned metadata, treat as not found
                    tracing::warn!(paste_id = %id, "Paste metadata exists but blob missing");
                    return Ok(None);
                }
                Err(e) => {
                    // Blob read error - treat as not found, log for debugging
                    tracing::warn!(paste_id = %id, error = %e, "Blob read error, treating as not found");
                    return Ok(None);
                }
            };

            // For burn-after-reading, delete the blob now (metadata already deleted by Lua)
            if meta.burn_after_reading {
                if let Err(e) = blob::delete_blob(storage_path, id).await {
                    tracing::error!(paste_id = %id, error = %e, "Failed to delete burn blob");
                    // Continue anyway - content was already read
                }
            }

            Ok(Some(StoredPaste {
                meta,
                encrypted_content,
            }))
        }
        None => Ok(None),
    }
}

/// Delete a paste from Redis and disk, cleaning up the owner's user_pastes SET.
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
            tracing::warn!(paste_id = %id, error = %e, "Failed to delete blob (may not exist)");
            // Continue anyway - metadata is already deleted
        }
    }

    Ok(deleted > 0)
}

/// Get all paste IDs owned by a user.
pub async fn get_user_paste_ids<C>(
    con: &mut C,
    user_id: &str,
) -> Result<Vec<String>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("user_pastes:{}", user_id);
    let ids: Vec<String> = con.smembers(&key).await?;
    Ok(ids)
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

/// Delete all pastes owned by a user (Redis metadata + disk blobs).
///
/// First fetches paste IDs, then deletes Redis metadata via Lua script,
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

    // Delete Redis metadata via Lua script
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
            tracing::warn!(paste_id = %paste_id, error = %e, "Failed to delete user paste blob");
        }
    }

    Ok(())
}
