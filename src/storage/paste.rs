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
pub async fn store_paste<C>(
    con: &mut C,
    paste: &StoredPaste,
    ttl_secs: u64,
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

    // Store paste with TTL
    con.set_ex::<_, _, ()>(&key, json, ttl_secs).await?;

    // If paste has an owner, add to user's paste set
    if let Some(ref owner_id) = paste.owner_id {
        let user_pastes_key = format!("user_pastes:{}", owner_id);
        con.sadd::<_, _, ()>(&user_pastes_key, &paste.id).await?;
        // Set 7 day TTL on the user_pastes set (604800 seconds)
        con.expire::<_, ()>(&user_pastes_key, 604800).await?;
    }

    Ok(())
}

/// Get a paste from Redis.
pub async fn get_paste<C>(con: &mut C, id: &str) -> Result<Option<StoredPaste>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("paste:{}", id);
    let json: Option<String> = con.get(&key).await?;

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

/// Get and delete a paste atomically (burn-after-reading).
///
/// Uses a Lua script to prevent race conditions.
pub async fn get_and_delete_paste<C>(
    con: &mut C,
    id: &str,
) -> Result<Option<StoredPaste>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("paste:{}", id);

    // Lua script for atomic GET + DEL
    let script = redis::Script::new(
        r"
        local val = redis.call('GET', KEYS[1])
        if val then
            redis.call('DEL', KEYS[1])
        end
        return val
        ",
    );

    let json: Option<String> = script.key(&key).invoke_async(con).await?;

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

/// Get a paste atomically, deleting if burn-after-reading.
///
/// Single Lua script avoids the check-then-act race condition where two
/// concurrent requests could both see burn_after_reading=true before either
/// deletes the paste.
pub async fn get_paste_atomic<C>(
    con: &mut C,
    id: &str,
) -> Result<Option<StoredPaste>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("paste:{}", id);

    // Lua script: GET paste, check burn flag, DEL if burn, return data
    let script = redis::Script::new(
        r#"
        local val = redis.call('GET', KEYS[1])
        if not val then
            return nil
        end
        -- Check if burn_after_reading is true in the JSON
        if string.find(val, '"burn_after_reading":true') then
            redis.call('DEL', KEYS[1])
        end
        return val
        "#,
    );

    let json: Option<String> = script.key(&key).invoke_async(con).await?;

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

/// Delete a paste from Redis.
///
/// Returns true if the paste was deleted, false if it didn't exist.
pub async fn delete_paste<C>(con: &mut C, id: &str) -> Result<bool, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("paste:{}", id);
    let deleted: i32 = con.del(&key).await?;
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
