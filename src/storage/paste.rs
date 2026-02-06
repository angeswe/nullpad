//! Paste Redis operations.
//!
//! Redis key patterns:
//! - `paste:{nanoid}` — individual paste data (JSON)
//! - `user_pastes:{user_id}` — SET of paste IDs owned by user

use crate::models::StoredPaste;
use redis::AsyncCommands;

/// Store a paste in Redis with TTL.
///
/// If the paste has an owner_id, also add the paste ID to the user's paste set.
/// `max_ttl_secs` is used for the user_pastes SET expiry (from config.max_ttl_secs).
pub async fn store_paste<C>(
    con: &mut C,
    paste: &StoredPaste,
    ttl_secs: u64,
    max_ttl_secs: u64,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("paste:{}", paste.id);
    let json = serde_json::to_string(paste).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "JSON serialize",
            e.to_string(),
        ))
    })?;

    // Store paste: ttl_secs=0 means forever (no expiration)
    if ttl_secs == 0 {
        con.set::<_, _, ()>(&key, json).await?;
    } else {
        con.set_ex::<_, _, ()>(&key, json, ttl_secs).await?;
    }

    // If paste has an owner, add to user's paste set
    if let Some(ref owner_id) = paste.owner_id {
        let user_pastes_key = format!("user_pastes:{}", owner_id);
        con.sadd::<_, _, ()>(&user_pastes_key, &paste.id).await?;
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
/// deletes the paste. Uses cjson.decode for reliable JSON parsing and
/// cleans up user_pastes SET on burn deletion.
pub async fn get_paste_atomic<C>(
    con: &mut C,
    id: &str,
) -> Result<Option<StoredPaste>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("paste:{}", id);

    // Lua script: GET paste, parse JSON for burn flag, DEL if burn + SREM from user_pastes
    // Key prefixes passed as ARGV to avoid hardcoding in Lua
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
            let paste = serde_json::from_str(&data).map_err(|e| {
                redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "JSON deserialize",
                    e.to_string(),
                ))
            })?;
            Ok(Some(paste))
        }
        None => Ok(None),
    }
}

/// Delete a paste from Redis, cleaning up the owner's user_pastes SET.
///
/// Uses a Lua script to atomically fetch the paste (for owner_id), delete it,
/// and SREM from the owner's user_pastes SET.
///
/// Returns true if the paste was deleted, false if it didn't exist.
pub async fn delete_paste<C>(con: &mut C, id: &str) -> Result<bool, redis::RedisError>
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

/// Delete all pastes owned by a user.
///
/// Also deletes the user_pastes set.
pub async fn delete_user_pastes<C>(con: &mut C, user_id: &str) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let paste_ids = get_user_paste_ids(con, user_id).await?;

    // Delete each paste
    for paste_id in paste_ids {
        let _ = delete_paste(con, &paste_id).await;
    }

    // Delete the user_pastes set
    let user_pastes_key = format!("user_pastes:{}", user_id);
    con.del::<_, ()>(&user_pastes_key).await?;

    Ok(())
}
