//! Redis storage layer for pastes, users, sessions, and challenges.
//!
//! All functions are async and use redis::AsyncCommands.
//! Data is serialized to JSON for storage in Redis.

pub mod paste;
pub mod session;
pub mod user;

use redis::AsyncCommands;

/// Maximum number of keys returned by scan_keys to prevent unbounded memory allocation.
const SCAN_MAX_KEYS: usize = 10_000;

/// Scan for Redis keys matching a pattern using SCAN (non-blocking).
///
/// Unlike KEYS, SCAN does not block the Redis server during iteration.
/// Capped at SCAN_MAX_KEYS results to prevent unbounded memory growth.
pub async fn scan_keys<C>(con: &mut C, pattern: &str) -> Result<Vec<String>, redis::RedisError>
where
    C: AsyncCommands,
{
    let mut all_keys = Vec::new();
    let mut cursor: u64 = 0;
    loop {
        let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(100)
            .query_async(con)
            .await?;
        all_keys.extend(keys);
        if all_keys.len() >= SCAN_MAX_KEYS {
            all_keys.truncate(SCAN_MAX_KEYS);
            break;
        }
        cursor = new_cursor;
        if cursor == 0 {
            break;
        }
    }
    Ok(all_keys)
}
