//! Blob storage for paste content on filesystem.
//!
//! File structure:
//! - `{storage_path}/{id[0..2]}/{id}` — encrypted paste content
//!
//! Uses directory sharding (first 2 chars of ID) to avoid too many files in one directory.

use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Error type for blob operations.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid paste ID: {0}")]
    InvalidId(String),
}

/// Get the path for a blob file.
///
/// Uses directory sharding: `{storage_path}/{id[0..2]}/{id}`
fn blob_path(storage_path: &Path, id: &str) -> Result<PathBuf, BlobError> {
    if id.len() < 2 {
        return Err(BlobError::InvalidId(
            "ID must be at least 2 characters".to_string(),
        ));
    }

    // Use first 2 characters for directory sharding
    let shard = &id[..2];
    Ok(storage_path.join(shard).join(id))
}

/// Initialize the storage directory.
///
/// Creates the storage directory if it doesn't exist.
pub async fn init_storage(storage_path: &Path) -> Result<(), BlobError> {
    fs::create_dir_all(storage_path).await?;
    Ok(())
}

/// Write a blob to disk.
///
/// Uses atomic write (write to temp file, then rename) to prevent partial reads.
pub async fn write_blob(storage_path: &Path, id: &str, content: &[u8]) -> Result<(), BlobError> {
    let path = blob_path(storage_path, id)?;

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }

    // Write to temp file first (atomic)
    let temp_path = path.with_extension("tmp");
    let mut file = fs::File::create(&temp_path).await?;
    file.write_all(content).await?;
    file.sync_all().await?;

    // Rename to final path (atomic on most filesystems)
    fs::rename(&temp_path, &path).await?;

    Ok(())
}

/// Read a blob from disk.
///
/// Returns None if the blob doesn't exist.
pub async fn read_blob(storage_path: &Path, id: &str) -> Result<Option<Vec<u8>>, BlobError> {
    let path = blob_path(storage_path, id)?;

    match fs::File::open(&path).await {
        Ok(mut file) => {
            let mut content = Vec::new();
            file.read_to_end(&mut content).await?;
            Ok(Some(content))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(BlobError::Io(e)),
    }
}

/// Delete a blob from disk.
///
/// Returns true if the blob was deleted, false if it didn't exist.
pub async fn delete_blob(storage_path: &Path, id: &str) -> Result<bool, BlobError> {
    let path = blob_path(storage_path, id)?;

    match fs::remove_file(&path).await {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(BlobError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_write_read_delete() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();

        init_storage(storage_path).await.unwrap();

        let id = "ab123456789012";
        let content = b"test content";

        // Write
        write_blob(storage_path, id, content).await.unwrap();

        // Read
        let read_content = read_blob(storage_path, id).await.unwrap();
        assert_eq!(read_content, Some(content.to_vec()));

        // Delete
        let deleted = delete_blob(storage_path, id).await.unwrap();
        assert!(deleted);

        // Read after delete
        let read_content = read_blob(storage_path, id).await.unwrap();
        assert_eq!(read_content, None);

        // Delete again (should return false)
        let deleted = delete_blob(storage_path, id).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn test_directory_sharding() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();

        init_storage(storage_path).await.unwrap();

        let id = "xy987654321012";
        let content = b"sharded content";

        write_blob(storage_path, id, content).await.unwrap();

        // Check file exists at sharded path
        let expected_path = storage_path.join("xy").join(id);
        assert!(expected_path.exists());
    }

    #[tokio::test]
    async fn test_invalid_id() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();

        // ID too short
        let result = write_blob(storage_path, "a", b"content").await;
        assert!(matches!(result, Err(BlobError::InvalidId(_))));
    }
}
