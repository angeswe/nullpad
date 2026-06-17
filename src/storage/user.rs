//! User and invite Valkey operations.
//!
//! Valkey key patterns:
//! - `user:{nanoid}` — individual user data (JSON)
//! - `alias:{alias}` — alias lookup to user_id (STRING)
//! - `invite:{token}` — invite data (JSON)
//!
//! ## Security: Zeroizing Sensitive Data
//!
//! This module uses the `zeroize` crate to securely clear sensitive data from memory
//! after use, specifically for invite tokens and user data containing public keys.

use crate::models::{Role, StoredInvite, StoredUser};
use redis::AsyncCommands;
use zeroize::Zeroizing;

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
            let user =
                serde_json::from_str(&zeroizing_data).map_err(super::json_deserialize_err)?;
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

/// Soft-delete a user atomically: delete alias key and user key in one Lua script.
///
/// This prevents new logins (alias gone) and new session lookups (user gone).
/// Callers should delete sessions and pastes after this returns.
///
/// Returns `true` if the user was deleted, `false` if they didn't exist.
pub async fn delete_user<C>(con: &mut C, id: &str) -> Result<bool, redis::RedisError>
where
    C: AsyncCommands,
{
    let user_key = format!("user:{}", id);

    // Atomic: read user to get alias, delete both user and alias keys
    // KEYS[1] = user:{id}
    // ARGV[1] = alias key prefix ("alias:")
    let script = redis::Script::new(
        r#"
        local user_json = redis.call('GET', KEYS[1])
        if not user_json then
            return 0
        end
        redis.call('DEL', KEYS[1])
        local user = cjson.decode(user_json)
        if type(user.alias) == 'string' then
            redis.call('DEL', ARGV[1] .. user.alias)
        end
        return 1
        "#,
    );

    let result: i32 = script
        .key(&user_key)
        .arg("alias:")
        .invoke_async(con)
        .await?;

    Ok(result == 1)
}

/// Upsert the admin user (permanent, no TTL).
///
/// Creates or updates `user:admin` with the provided pubkey and alias.
/// Uses a Lua script to atomically clean up stale alias keys if the alias
/// has changed between deploys, preventing multi-pod startup races.
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
        role: Role::Admin,
        created_at: crate::util::now_secs(),
    };

    let user_key = "user:admin";
    let new_alias_key = format!("alias:{}", alias);

    let json = serde_json::to_string(&user).map_err(super::json_serialize_err)?;

    // Atomic upsert: read old admin, delete stale alias, write new admin + alias
    // Alias key prefix passed as ARGV[3] to avoid hardcoding in Lua
    let script = redis::Script::new(
        r#"
        local old_json = redis.call('GET', KEYS[1])
        local result = 0
        if old_json then
            result = 1
            local old_user = cjson.decode(old_json)
            if type(old_user.alias) == 'string' and old_user.alias ~= ARGV[2] then
                redis.call('DEL', ARGV[3] .. old_user.alias)
                result = 2
            end
        end
        redis.call('SET', KEYS[1], ARGV[1])
        redis.call('SET', KEYS[2], 'admin')
        return result
        "#,
    );

    script
        .key(user_key)
        .key(&new_alias_key)
        .arg(&json)
        .arg(alias)
        .arg("alias:")
        .invoke_async::<i32>(con)
        .await?;

    Ok(())
}

/// List all users in Valkey.
///
/// Scans for keys matching `user:*` and deserializes each.
/// User JSON data is zeroized after deserialization.
pub async fn list_users<C>(con: &mut C) -> Result<Vec<StoredUser>, redis::RedisError>
where
    C: AsyncCommands,
{
    let mut users = Vec::new();
    // Use negation pattern to exclude user_pastes:* and user_sessions:* keys
    let keys = super::scan_keys(con, "user:*").await?;

    for key in keys {
        // Skip non-user keys that match the broad pattern
        if key.starts_with("user_pastes:") || key.starts_with("user_sessions:") {
            continue;
        }
        let json: Option<String> = con.get(&key).await?;
        if let Some(data) = json {
            // Wrap user JSON in Zeroizing
            let zeroizing_data = Zeroizing::new(data);
            match serde_json::from_str::<StoredUser>(&zeroizing_data) {
                Ok(user) => users.push(user),
                Err(e) => tracing::warn!(key = %key, error = %e, "Failed to deserialize user"),
            }
            // zeroizing_data is automatically zeroized when dropped here
        }
    }

    Ok(users)
}

/// Result of an atomic invite consumption + user creation.
pub enum RegisterResult {
    /// User created successfully, invite consumed.
    Success,
    /// Alias was already taken; invite NOT consumed.
    AliasTaken,
    /// Invite not found or expired; no changes made.
    InviteNotFound,
}

/// Atomically consume an invite and create a user.
///
/// Uses a single Lua script to prevent race conditions where concurrent
/// registrations both consume invites but only one user is created.
/// If the alias is taken or the invite doesn't exist, no changes are made.
pub async fn consume_invite_and_create_user<C>(
    con: &mut C,
    invite_token: &str,
    user: &StoredUser,
    user_ttl_secs: u64,
) -> Result<RegisterResult, redis::RedisError>
where
    C: AsyncCommands,
{
    let invite_key = format!("invite:{}", invite_token);
    let alias_key = format!("alias:{}", user.alias);
    let user_key = format!("user:{}", user.id);

    let user_json = serde_json::to_string(user).map_err(super::json_serialize_err)?;

    // Lua script: atomically check alias, check invite, consume invite, create user.
    // Returns:
    //   1 = success
    //   0 = alias taken
    //  -1 = invite not found
    //
    // KEYS[1] = alias:{alias}
    // KEYS[2] = invite:{token}
    // KEYS[3] = user:{id}
    // ARGV[1] = user JSON
    // ARGV[2] = user ID (for alias lookup value)
    // ARGV[3] = TTL in seconds
    let script = redis::Script::new(
        r#"
        if redis.call('EXISTS', KEYS[1]) == 1 then
            return 0
        end
        if redis.call('EXISTS', KEYS[2]) == 0 then
            return -1
        end
        redis.call('DEL', KEYS[2])
        redis.call('SETEX', KEYS[3], ARGV[3], ARGV[1])
        redis.call('SETEX', KEYS[1], ARGV[3], ARGV[2])
        return 1
        "#,
    );

    let result: i32 = script
        .key(&alias_key)
        .key(&invite_key)
        .key(&user_key)
        .arg(&user_json)
        .arg(&user.id)
        .arg(user_ttl_secs as i64)
        .invoke_async(con)
        .await?;

    match result {
        1 => Ok(RegisterResult::Success),
        0 => Ok(RegisterResult::AliasTaken),
        -1 => Ok(RegisterResult::InviteNotFound),
        other => {
            tracing::warn!(
                lua_return = other,
                "Unexpected return value from consume_invite_and_create_user Lua script"
            );
            Ok(RegisterResult::InviteNotFound)
        }
    }
}

/// Store an invite in Valkey with TTL.
pub async fn store_invite<C>(
    con: &mut C,
    invite: &StoredInvite,
    ttl_secs: u64,
) -> Result<(), redis::RedisError>
where
    C: AsyncCommands,
{
    let key = format!("invite:{}", invite.token);
    let json = serde_json::to_string(invite).map_err(super::json_serialize_err)?;

    con.set_ex::<_, _, ()>(&key, json, ttl_secs).await?;
    Ok(())
}

/// Delete an invite from Valkey.
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

/// List all invites in Valkey.
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
            match serde_json::from_str::<StoredInvite>(&zeroizing_data) {
                Ok(invite) => invites.push(invite),
                Err(e) => tracing::warn!(key = %key, error = %e, "Failed to deserialize invite"),
            }
            // zeroizing_data is automatically zeroized when dropped here
        }
    }

    Ok(invites)
}
