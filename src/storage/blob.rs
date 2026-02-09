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

/// Validate paste ID to prevent path traversal attacks.
///
/// Rejects IDs containing path separators or parent directory references.
/// This provides defense-in-depth even though route handlers also validate IDs.
fn validate_blob_id(id: &str) -> Result<(), BlobError> {
    if id.len() < 2 {
        return Err(BlobError::InvalidId(
            "ID must be at least 2 characters".to_string(),
        ));
    }

    // Reject path traversal attempts
    if id.contains("..") || id.contains('/') || id.contains('\\') {
        return Err(BlobError::InvalidId(
            "ID contains invalid characters".to_string(),
        ));
    }

    // Only allow alphanumeric, hyphen, underscore (nanoid charset)
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(BlobError::InvalidId(
            "ID contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Normalize and validate the storage base path.
///
/// - Prefer a canonicalized absolute path when the directory exists.
/// - If it doesn't exist yet, require that the provided path is absolute and use it as-is.
fn normalize_storage_base(storage_path: &Path) -> Result<PathBuf, BlobError> {
    match storage_path.canonicalize() {
        Ok(p) => Ok(p),
        Err(_) => {
            // Directory may not exist yet; use the provided path but ensure it is absolute.
            if !storage_path.is_absolute() {
                return Err(BlobError::InvalidId(
                    "Storage path must be absolute".to_string(),
                ));
            }
            Ok(storage_path.to_path_buf())
        }
    }
}
/// Get the path for a blob file.
///
/// Uses directory sharding: `{storage_path}/{id[0..2]}/{id}`
/// Validates ID to prevent path traversal attacks and ensures the
/// resulting path stays within the storage directory.
fn blob_path(storage_path: &Path, id: &str) -> Result<PathBuf, BlobError> {
    validate_blob_id(id)?;

    // Normalize the storage base to an absolute path.
    let canonical_storage = normalize_storage_base(storage_path)?;


    // Use first 2 characters for directory sharding
    let shard = &id[..2];
    let path = canonical_storage.join(shard).join(id);

    // Defense-in-depth: verify that the blob's parent directory is within storage directory.
    if let Some(parent) = path.parent() {
        if let Ok(parent_canonical) = parent.canonicalize() {
            if !parent_canonical.starts_with(&canonical_storage) {
                return Err(BlobError::InvalidId(
                    "Path escapes storage directory".to_string(),
                ));
            }
        }
    }

    Ok(path)
}

/// Initialize the storage directory.
///
/// Creates the storage directory if it doesn't exist.
pub async fn init_storage(storage_path: &Path) -> Result<(), BlobError> {
    // Normalize storage path in the same way as blob_path: prefer the canonical
    // absolute path, but ensure that we never operate on a relative base path.
    let base = normalize_storage_base(storage_path)?;

    fs::create_dir_all(&base).await?;
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
