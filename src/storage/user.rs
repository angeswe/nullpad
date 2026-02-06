//! User and invite Redis operations.
//!
//! Redis key patterns:
//! - `user:{nanoid}` — individual user data (JSON)
//! - `alias:{alias}` — alias lookup to user_id (STRING)
//! - `invite:{token}` — invite data (JSON)
//!
//! ## Security: Zeroizing Sensitive Data
//!
//! This module uses the `zeroize` crate to securely clear sensitive data from memory
//! after use, specifically for invite tokens and user data containing public keys.

use crate::models::{StoredInvite, StoredUser};
use redis::AsyncCommands;
use zeroize::Zeroizing;

/// Store a user in Redis with TTL.
///
/// Also creates an alias lookup key with the same TTL.
pub async fn store_user<C>(
    con: &mut C,
    user: &StoredUser,
    ttl_secs: u64,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let user_key = format!("user:{}", user.id);
    let alias_key = format!("alias:{}", user.alias);

    let json = serde_json::to_string(user).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "JSON serialize",
            e.to_string(),
        ))
    })?;

    // Store user with TTL
    con.set_ex::<_, _, ()>(&user_key, json, ttl_secs).await?;

    // Store alias lookup with same TTL
    con.set_ex::<_, _, ()>(&alias_key, &user.id, ttl_secs)
        .await?;

    Ok(())
}

/// Get a user by ID.
///
/// The user JSON is zeroized after deserialization.
pub async fn get_user<C>(con: &mut C, id: &str) -> Result<Option<StoredUser>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("user:{}", id);
    let json: Option<String> = con.get(&key).await?;

    match json {
        Some(data) => {
            // Wrap the JSON string in Zeroizing to clear it after use
            let zeroizing_data = Zeroizing::new(data);
            let user = serde_json::from_str(&zeroizing_data).map_err(|e| {
                redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "JSON deserialize",
                    e.to_string(),
                ))
            })?;
            // zeroizing_data is automatically zeroized when dropped here
            Ok(Some(user))
        }
        None => Ok(None),
    }
}

/// Get a user by alias.
///
/// Performs a two-step lookup: alias -> user_id -> user data.
pub async fn get_user_by_alias<C>(
    con: &mut C,
    alias: &str,
) -> Result<Option<StoredUser>, redis::RedisError>
where
    C: AsyncCommands,
{
    let alias_key = format!("alias:{}", alias);
    let user_id: Option<String> = con.get(&alias_key).await?;

    match user_id {
        Some(id) => get_user(con, &id).await,
        None => Ok(None),
    }
}

/// Delete a user from Redis.
///
/// Also deletes the alias lookup key.
pub async fn delete_user<C>(con: &mut C, id: &str) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    // Get user first to find alias
    let user = get_user(con, id).await?;

    // Delete user key
    let user_key = format!("user:{}", id);
    con.del::<_, ()>(&user_key).await?;

    // Delete alias key if user was found
    if let Some(user) = user {
        let alias_key = format!("alias:{}", user.alias);
        con.del::<_, ()>(&alias_key).await?;
    }

    Ok(())
}

/// Upsert the admin user (permanent, no TTL).
///
/// Creates or updates `user:admin` with the provided pubkey and alias.
pub async fn upsert_admin<C>(
    con: &mut C,
    pubkey: &str,
    alias: &str,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let user = StoredUser {
        id: "admin".to_string(),
        alias: alias.to_string(),
        pubkey: pubkey.to_string(),
        role: "admin".to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let user_key = "user:admin";
    let alias_key = format!("alias:{}", alias);

    let json = serde_json::to_string(&user).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "JSON serialize",
            e.to_string(),
        ))
    })?;

    // Store user without TTL (permanent)
    con.set::<_, _, ()>(&user_key, json).await?;

    // Store alias lookup without TTL (permanent)
    con.set::<_, _, ()>(&alias_key, "admin").await?;

    Ok(())
}

/// Update a user's TTL.
pub async fn update_user_ttl<C>(
    con: &mut C,
    id: &str,
    ttl_secs: u64,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("user:{}", id);
    con.expire::<_, ()>(&key, ttl_secs as i64).await?;
    Ok(())
}

/// List all users in Redis.
///
/// Scans for keys matching `user:*` and deserializes each.
/// User JSON data is zeroized after deserialization.
pub async fn list_users<C>(con: &mut C) -> Result<Vec<StoredUser>, redis::RedisError>
where
    C: AsyncCommands,
{
    let mut users = Vec::new();
    let keys = super::scan_keys(con, "user:*").await?;

    for key in keys {
        let json: Option<String> = con.get(&key).await?;
        if let Some(data) = json {
            // Wrap user JSON in Zeroizing
            let zeroizing_data = Zeroizing::new(data);
            if let Ok(user) = serde_json::from_str::<StoredUser>(&zeroizing_data) {
                users.push(user);
            }
            // zeroizing_data is automatically zeroized when dropped here
        }
    }

    Ok(users)
}

/// Store an invite in Redis with TTL.
pub async fn store_invite<C>(
    con: &mut C,
    invite: &StoredInvite,
    ttl_secs: u64,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("invite:{}", invite.token);
    let json = serde_json::to_string(invite).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "JSON serialize",
            e.to_string(),
        ))
    })?;

    con.set_ex::<_, _, ()>(&key, json, ttl_secs).await?;
    Ok(())
}

/// Get an invite by token.
///
/// The invite JSON is zeroized after deserialization.
pub async fn get_invite<C>(
    con: &mut C,
    token: &str,
) -> Result<Option<StoredInvite>, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("invite:{}", token);
    let json: Option<String> = con.get(&key).await?;

    match json {
        Some(data) => {
            // Wrap the JSON string in Zeroizing to clear it after use
            let zeroizing_data = Zeroizing::new(data);
            let invite = serde_json::from_str(&zeroizing_data).map_err(|e| {
                redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "JSON deserialize",
                    e.to_string(),
                ))
            })?;
            // zeroizing_data is automatically zeroized when dropped here
            Ok(Some(invite))
        }
        None => Ok(None),
    }
}

/// Delete an invite from Redis.
///
/// Returns true if the invite was deleted, false if it didn't exist.
pub async fn delete_invite<C>(con: &mut C, token: &str) -> Result<bool, redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("invite:{}", token);
    let deleted: i32 = con.del(&key).await?;
    Ok(deleted > 0)
}

/// List all invites in Redis.
///
/// Scans for keys matching `invite:*` and deserializes each.
/// Invite JSON data is zeroized after deserialization.
pub async fn list_invites<C>(con: &mut C) -> Result<Vec<StoredInvite>, redis::RedisError>
where
    C: AsyncCommands,
{
    let mut invites = Vec::new();
    let keys = super::scan_keys(con, "invite:*").await?;

    for key in keys {
        let json: Option<String> = con.get(&key).await?;
        if let Some(data) = json {
            // Wrap invite JSON in Zeroizing
            let zeroizing_data = Zeroizing::new(data);
            if let Ok(invite) = serde_json::from_str::<StoredInvite>(&zeroizing_data) {
                invites.push(invite);
            }
            // zeroizing_data is automatically zeroized when dropped here
        }
    }

    Ok(invites)
}
