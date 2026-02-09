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

/// Store a challenge only if user exists, atomically.
///
/// Uses a Lua script to prevent race conditions between checking user
/// existence and storing the challenge. Returns true if stored (user exists),
/// false if user doesn't exist.
pub async fn store_challenge_if_user_exists<C>(
    con: &mut C,
    alias: &str,
    challenge: &StoredChallenge,
    ttl_secs: u64,
) -> Result<bool, redis::RedisError>
where
    C: AsyncCommands,
{
    let alias_key = format!("alias:{}", alias);
    let challenge_key = format!("challenge:{}", alias);
    let json = serde_json::to_string(challenge).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "JSON serialize",
            e.to_string(),
        ))
    })?;

    // Lua script: check if user exists, store challenge atomically
    let script = redis::Script::new(
        r"
        if redis.call('EXISTS', KEYS[1]) == 1 then
            redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
            return 1
        end
        return 0
        ",
    );

    let stored: i32 = script
        .key(&alias_key)
        .key(&challenge_key)
        .arg(&json)
        .arg(ttl_secs)
        .invoke_async(con)
        .await?;

    Ok(stored == 1)
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
///
/// If the user already has `max_sessions` sessions, the oldest sessions
/// (by TTL) are deleted before creating the new one. This prevents
/// unbounded session growth across many IPs.
pub async fn store_session<C>(
    con: &mut C,
    token: &str,
    session: &StoredSession,
    ttl_secs: u64,
    max_sessions: usize,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let session_key = format!("session:{}", token);
    let user_sessions_key = format!("user_sessions:{}", session.user_id);

    let json = serde_json::to_string(session).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "JSON serialize",
            e.to_string(),
        ))
    })?;

    // Lua script to atomically:
    // 1. Check session count
    // 2. If at/above limit, delete oldest sessions (lowest TTL)
    // 3. Return deleted tokens for logging
    //
    // KEYS[1]: user_sessions:{user_id}
    // ARGV[1]: max_sessions (usize as string)
    // ARGV[2]: session_key_prefix ("session:")
    //
    // Returns: array of deleted session tokens
    let cleanup_script = redis::Script::new(
        r"
        local user_sessions_key = KEYS[1]
        local max_sessions = tonumber(ARGV[1])
        local session_key_prefix = ARGV[2]

        local tokens = redis.call('SMEMBERS', user_sessions_key)
        local count = #tokens

        local deleted = {}

        if count >= max_sessions then
            -- Build table of {token, ttl} pairs
            local token_ttls = {}
            for _, token in ipairs(tokens) do
                local session_key = session_key_prefix .. token
                local ttl = redis.call('TTL', session_key)
                -- TTL returns -2 if key doesn't exist, -1 if no expiry
                -- Only consider valid sessions (ttl >= 0)
                if ttl >= 0 then
                    table.insert(token_ttls, {token = token, ttl = ttl})
                else
                    -- Session expired but token still in set, clean it up
                    redis.call('SREM', user_sessions_key, token)
                end
            end

            -- Sort by TTL ascending (oldest first)
            table.sort(token_ttls, function(a, b) return a.ttl < b.ttl end)

            -- Delete oldest sessions until we're below the limit
            local to_delete = count - max_sessions + 1
            for i = 1, math.min(to_delete, #token_ttls) do
                local token = token_ttls[i].token
                local session_key = session_key_prefix .. token
                redis.call('DEL', session_key)
                redis.call('SREM', user_sessions_key, token)
                table.insert(deleted, token)
            end
        end

        return deleted
        ",
    );

    // Run cleanup script
    let deleted_tokens: Vec<String> = cleanup_script
        .key(&user_sessions_key)
        .arg(max_sessions)
        .arg("session:")
        .invoke_async(con)
        .await?;

    if !deleted_tokens.is_empty() {
        tracing::debug!(
            user_id = %session.user_id,
            deleted_count = deleted_tokens.len(),
            "Deleted oldest sessions to enforce limit"
        );
    }

    // Store session with TTL
    con.set_ex::<_, _, ()>(&session_key, json, ttl_secs).await?;

    // Track session token in user's session set
    con.sadd::<_, _, ()>(&user_sessions_key, token).await?;
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
