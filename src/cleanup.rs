//! Background cleanup job for orphaned paste files.
//!
//! When Redis expires paste metadata (via TTL), the corresponding file
//! on disk becomes orphaned. This job periodically scans the storage
//! directory and deletes files whose metadata no longer exists in Redis.

use redis::AsyncCommands;
use std::path::Path;
use std::time::Duration;
use tokio::fs;

/// Run the cleanup loop.
///
/// Scans the paste storage directory every `interval` and deletes
/// orphaned files (those without corresponding Redis metadata).
pub async fn run_cleanup_loop<C>(mut redis: C, storage_path: &Path, interval: Duration)
where
    C: AsyncCommands + Clone + Send + 'static,
{
    let storage_path = storage_path.to_path_buf();

    loop {
        tokio::time::sleep(interval).await;

        if let Err(e) = cleanup_orphaned_files(&mut redis, &storage_path).await {
            tracing::error!(error = %e, "Cleanup job failed");
        }
    }
}

/// Scan storage directory and delete orphaned files.
async fn cleanup_orphaned_files<C>(redis: &mut C, storage_path: &Path) -> Result<(), CleanupError>
where
    C: AsyncCommands,
{
    let mut deleted_count = 0;
    let mut checked_count = 0;

    // Iterate through shard directories (e.g., /data/pastes/ab/, /data/pastes/cd/)
    let mut shard_dirs = fs::read_dir(storage_path).await?;

    while let Some(shard_entry) = shard_dirs.next_entry().await? {
        let shard_path = shard_entry.path();
        if !shard_path.is_dir() {
            continue;
        }

        // Iterate through files in this shard
        let mut files = fs::read_dir(&shard_path).await?;

        while let Some(file_entry) = files.next_entry().await? {
            let file_path = file_entry.path();
            if !file_path.is_file() {
                continue;
            }

            // Skip temp files
            if file_path.extension().map_or(false, |ext| ext == "tmp") {
                continue;
            }

            // Get paste ID from filename
            let paste_id = match file_path.file_name().and_then(|n| n.to_str()) {
                Some(id) => id.to_string(),
                None => continue,
            };

            checked_count += 1;

            // Check if metadata exists in Redis
            let redis_key = format!("paste:{}", paste_id);
            let exists: bool = redis.exists(&redis_key).await.unwrap_or(true);

            if !exists {
                // Orphaned file - delete it
                if let Err(e) = fs::remove_file(&file_path).await {
                    tracing::warn!(
                        paste_id = %paste_id,
                        error = %e,
                        "Failed to delete orphaned file"
                    );
                } else {
                    deleted_count += 1;
                }
            }
        }
    }

    if deleted_count > 0 {
        tracing::info!(
            deleted = deleted_count,
            checked = checked_count,
            "Cleanup job completed"
        );
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum CleanupError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
}
