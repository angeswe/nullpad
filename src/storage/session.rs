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
///
/// Also adds the session token to the user's session tracking set
/// (`user_sessions:{user_id}`) for efficient cleanup on user revocation.
pub async fn store_session<C>(
    con: &mut C,
    session: &StoredSession,
    ttl_secs: u64,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let session_key = format!("session:{}", session.token);
    let user_sessions_key = format!("user_sessions:{}", session.user_id);

    let json = serde_json::to_string(session).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "JSON serialize",
            e.to_string(),
        ))
    })?;

    // Store session with TTL
    con.set_ex::<_, _, ()>(&session_key, json, ttl_secs).await?;

    // Track session token in user's session set
    con.sadd::<_, _, ()>(&user_sessions_key, &session.token)
        .await?;
    // Keep the set alive at least as long as the session
    con.expire::<_, ()>(&user_sessions_key, ttl_secs as i64)
        .await?;

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
/// Also removes the token from the user's session tracking set.
/// Returns true if the session was deleted, false if it didn't exist.
pub async fn delete_session<C>(
    con: &mut C,
    token: &str,
    user_id: &str,
) -> Result<bool, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("session:{}", token);
    let deleted: i32 = con.del(&key).await?;

    // Remove from user's session tracking set
    let user_sessions_key = format!("user_sessions:{}", user_id);
    con.srem::<_, _, ()>(&user_sessions_key, token).await?;

    Ok(deleted > 0)
}

/// Delete all sessions for a user.
///
/// Uses the `user_sessions:{user_id}` tracking set for O(1) lookup
/// instead of scanning all session keys.
pub async fn delete_user_sessions<C>(con: &mut C, user_id: &str) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let user_sessions_key = format!("user_sessions:{}", user_id);

    // Get all session tokens for this user
    let tokens: Vec<String> = con.smembers(&user_sessions_key).await?;

    // Delete each session key
    for token in &tokens {
        let session_key = format!("session:{}", token);
        con.del::<_, ()>(&session_key).await?;
    }

    // Delete the tracking set itself
    con.del::<_, ()>(&user_sessions_key).await?;

    Ok(())
}
