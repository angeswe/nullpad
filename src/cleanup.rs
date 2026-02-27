//! Background cleanup job for orphaned paste files.
//!
//! When Redis expires paste metadata (via TTL), the corresponding file
//! on disk becomes orphaned. This job periodically scans the storage
//! directory and deletes files whose metadata no longer exists in Redis.

use crate::util::now_secs;
use redis::AsyncCommands;
use std::path::Path;
use std::time::Duration;
use tokio::fs;

/// Maximum files to process per cleanup cycle to bound Redis load.
const CLEANUP_BATCH_SIZE: usize = 50;
const CLEANUP_MAX_FILES_PER_CYCLE: usize = 1000;

/// Stale .tmp files older than this are deleted (1 hour).
const STALE_TMP_SECS: u64 = 3600;

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

/// Validate that a filename is a valid paste ID (alphanumeric, hyphens, underscores, min 2 chars).
fn is_valid_paste_id(id: &str) -> bool {
    id.len() >= 2
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Scan storage directory and delete orphaned files.
async fn cleanup_orphaned_files<C>(redis: &mut C, storage_path: &Path) -> Result<(), CleanupError>
where
    C: AsyncCommands,
{
    let mut deleted_count: u64 = 0;
    let mut checked_count: u64 = 0;
    let mut tmp_deleted_count: u64 = 0;
    let mut total_files: usize = 0;

    let now = now_secs();

    // Collect files to check in batches
    let mut pending_files: Vec<(String, std::path::PathBuf)> = Vec::new();

    // Iterate through shard directories (e.g., /data/pastes/ab/, /data/pastes/cd/)
    let mut shard_dirs = fs::read_dir(storage_path).await?;

    'outer: while let Some(shard_entry) = shard_dirs.next_entry().await? {
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

            // Handle .tmp files: delete if stale (older than 1 hour)
            if file_path.extension().is_some_and(|ext| ext == "tmp") {
                if let Ok(metadata) = fs::metadata(&file_path).await {
                    if let Ok(modified) = metadata.modified() {
                        let modified_secs = modified
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        if now.saturating_sub(modified_secs) > STALE_TMP_SECS {
                            if let Err(e) = fs::remove_file(&file_path).await {
                                tracing::warn!(
                                    path = %file_path.display(),
                                    error = %e,
                                    "Failed to delete stale tmp file"
                                );
                            } else {
                                tmp_deleted_count += 1;
                            }
                        }
                    }
                }
                continue;
            }

            // Get paste ID from filename
            let paste_id = match file_path.file_name().and_then(|n| n.to_str()) {
                Some(id) => id.to_string(),
                None => continue,
            };

            // Validate paste ID before using in Redis key
            if !is_valid_paste_id(&paste_id) {
                tracing::warn!(
                    filename = %paste_id,
                    "Cleanup: skipping file with invalid paste ID"
                );
                continue;
            }

            // Check per-cycle cap
            total_files += 1;
            if total_files > CLEANUP_MAX_FILES_PER_CYCLE {
                tracing::info!(
                    cap = CLEANUP_MAX_FILES_PER_CYCLE,
                    "Cleanup: per-cycle cap reached, deferring remaining files"
                );
                break 'outer;
            }

            pending_files.push((paste_id, file_path));

            // Process batch when full
            if pending_files.len() >= CLEANUP_BATCH_SIZE {
                let (batch_checked, batch_deleted) =
                    process_batch(redis, &mut pending_files).await?;
                checked_count += batch_checked;
                deleted_count += batch_deleted;

                // Yield between batches to avoid starving other tasks
                tokio::task::yield_now().await;
            }
        }
    }

    // Process remaining files
    if !pending_files.is_empty() {
        let (batch_checked, batch_deleted) = process_batch(redis, &mut pending_files).await?;
        checked_count += batch_checked;
        deleted_count += batch_deleted;
    }

    if deleted_count > 0 || tmp_deleted_count > 0 {
        tracing::info!(
            deleted = deleted_count,
            tmp_deleted = tmp_deleted_count,
            checked = checked_count,
            "Cleanup job completed"
        );
    }

    Ok(())
}

/// Process a batch of files: pipeline Redis EXISTS queries, then delete orphans.
async fn process_batch<C>(
    redis: &mut C,
    files: &mut Vec<(String, std::path::PathBuf)>,
) -> Result<(u64, u64), CleanupError>
where
    C: AsyncCommands,
{
    let mut checked: u64 = 0;
    let mut deleted: u64 = 0;

    // Build Redis pipeline for batched EXISTS queries
    let mut pipe = redis::pipe();
    for (paste_id, _) in files.iter() {
        let redis_key = format!("paste:{}", paste_id);
        pipe.exists(redis_key);
    }

    let results: Vec<bool> = match pipe.query_async(redis).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, batch_size = files.len(), "Cleanup: Redis pipeline failed, skipping batch");
            files.clear();
            return Ok((0, 0));
        }
    };

    for (i, (paste_id, file_path)) in files.drain(..).enumerate() {
        checked += 1;

        // Default to true (keep file) if result is missing
        let exists = results.get(i).copied().unwrap_or(true);

        if !exists {
            if let Err(e) = fs::remove_file(&file_path).await {
                tracing::warn!(
                    paste_id = %paste_id,
                    error = %e,
                    "Failed to delete orphaned file"
                );
            } else {
                deleted += 1;
            }
        }
    }

    Ok((checked, deleted))
}

#[derive(Debug, thiserror::Error)]
pub enum CleanupError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
}
