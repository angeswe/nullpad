//! Session and challenge Redis operations.
//!
//! Redis key patterns:
//! - `session:{token}` — session data (JSON)
//! - `challenge:{alias}` — challenge nonce (JSON)
//!
//! ## Security: Zeroizing Sensitive Data
//!
//! This module uses the `zeroize` crate to securely clear sensitive data from memory
//! after use. Specifically:
//! - Challenge nonces are zeroized after verification
//! - Session tokens are zeroized after consumption
//!
//! **Limitations**: Redis stores data in its own memory space, so zeroize only protects
//! the Rust application's memory. This is defense-in-depth for the application layer.
//! Additionally, since we're working with String types that come from JSON deserialization,
//! intermediate copies may exist. We zeroize what we can control directly.

use crate::models::{StoredChallenge, StoredSession};
use redis::AsyncCommands;
use zeroize::Zeroizing;

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
    let json = serde_json::to_string(challenge).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "JSON serialize",
            e.to_string(),
        ))
    })?;

    con.set_ex::<_, _, ()>(&key, json, ttl_secs).await?;
    Ok(())
}

/// Get and delete a challenge atomically (single-use nonce).
///
/// Uses a Lua script to prevent race conditions.
/// The retrieved nonce is zeroized after deserialization.
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
        ",
    );

    let json: Option<String> = script.key(&key).invoke_async(con).await?;

    match json {
        Some(data) => {
            // Wrap the JSON string in Zeroizing to clear it after use
            let zeroizing_data = Zeroizing::new(data);
            let challenge = serde_json::from_str(&zeroizing_data).map_err(|e| {
                redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "JSON deserialize",
                    e.to_string(),
                ))
            })?;
            // zeroizing_data is automatically zeroized when dropped here
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
    let json = serde_json::to_string(session).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "JSON serialize",
            e.to_string(),
        ))
    })?;

    con.set_ex::<_, _, ()>(&key, json, ttl_secs).await?;
    Ok(())
}

/// Get a session by token.
///
/// The session JSON is zeroized after deserialization.
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
            // Wrap the JSON string in Zeroizing to clear it after use
            let zeroizing_data = Zeroizing::new(data);
            let session = serde_json::from_str(&zeroizing_data).map_err(|e| {
                redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "JSON deserialize",
                    e.to_string(),
                ))
            })?;
            // zeroizing_data is automatically zeroized when dropped here
            Ok(Some(session))
        }
        None => Ok(None),
    }
}

/// Delete a session from Redis.
///
/// Returns true if the session was deleted, false if it didn't exist.
pub async fn delete_session<C>(con: &mut C, token: &str) -> Result<bool, redis::RedisError>
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
/// Session data is zeroized after checking.
pub async fn delete_user_sessions<C>(con: &mut C, user_id: &str) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    // Scan for all session keys (non-blocking)
    let keys = super::scan_keys(con, "session:*").await?;

    // Check each session and delete if it matches the user_id
    for key in keys {
        let json: Option<String> = con.get(&key).await?;
        if let Some(data) = json {
            // Wrap session JSON in Zeroizing
            let zeroizing_data = Zeroizing::new(data);
            if let Ok(session) = serde_json::from_str::<StoredSession>(&zeroizing_data) {
                if session.user_id == user_id {
                    con.del::<_, ()>(&key).await?;
                }
            }
            // zeroizing_data is automatically zeroized when dropped here
        }
    }

    Ok(())
}
