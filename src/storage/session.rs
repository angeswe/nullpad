//! Session and challenge Redis operations.
//!
//! Redis key patterns:
//! - `session:{token}` — session data (JSON)
//! - `challenge:{alias}` — challenge nonce (JSON)

use crate::models::{StoredChallenge, StoredSession};
use redis::AsyncCommands;

/// Store a challenge in Redis with TTL (default 30s).
///
/// Challenges are single-use nonces for authentication.
pub async fn store_challenge<C>(
    con: &mut C,
    alias: &str,
    challenge: &StoredChallenge,
    ttl_secs: u64,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("challenge:{}", alias);
    let json = serde_json::to_string(challenge)
        .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "JSON serialize", e.to_string())))?;

    con.set_ex::<_, _, ()>(&key, json, ttl_secs).await?;
    Ok(())
}

/// Get and delete a challenge atomically (single-use nonce).
///
/// Uses a Lua script to prevent race conditions.
pub async fn get_and_delete_challenge<C>(
    con: &mut C,
    alias: &str,
) -> Result<Option<StoredChallenge>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("challenge:{}", alias);

    // Lua script for atomic GET + DEL
    let script = redis::Script::new(
        r"
        local val = redis.call('GET', KEYS[1])
        if val then
            redis.call('DEL', KEYS[1])
        end
        return val
        "
    );

    let json: Option<String> = script.key(&key).invoke_async(con).await?;

    match json {
        Some(data) => {
            let challenge = serde_json::from_str(&data)
                .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "JSON deserialize", e.to_string())))?;
            Ok(Some(challenge))
        }
        None => Ok(None),
    }
}

/// Store a session in Redis with TTL (default 15min).
pub async fn store_session<C>(
    con: &mut C,
    session: &StoredSession,
    ttl_secs: u64,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("session:{}", session.token);
    let json = serde_json::to_string(session)
        .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "JSON serialize", e.to_string())))?;

    con.set_ex::<_, _, ()>(&key, json, ttl_secs).await?;
    Ok(())
}

/// Get a session by token.
pub async fn get_session<C>(
    con: &mut C,
    token: &str,
) -> Result<Option<StoredSession>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("session:{}", token);
    let json: Option<String> = con.get(&key).await?;

    match json {
        Some(data) => {
            let session = serde_json::from_str(&data)
                .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "JSON deserialize", e.to_string())))?;
            Ok(Some(session))
        }
        None => Ok(None),
    }
}

/// Delete a session from Redis.
///
/// Returns true if the session was deleted, false if it didn't exist.
pub async fn delete_session<C>(
    con: &mut C,
    token: &str,
) -> Result<bool, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("session:{}", token);
    let deleted: i32 = con.del(&key).await?;
    Ok(deleted > 0)
}

/// Delete all sessions for a user.
///
/// Scans for all session keys and deletes those matching the user_id.
pub async fn delete_user_sessions<C>(
    con: &mut C,
    user_id: &str,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    // Get all session keys
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("session:*")
        .query_async(con)
        .await?;

    // Check each session and delete if it matches the user_id
    for key in keys {
        let json: Option<String> = con.get(&key).await?;
        if let Some(data) = json {
            if let Ok(session) = serde_json::from_str::<StoredSession>(&data) {
                if session.user_id == user_id {
                    con.del::<_, ()>(&key).await?;
                }
            }
        }
    }

    Ok(())
}
