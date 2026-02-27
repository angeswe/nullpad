//! Blob storage for paste content on filesystem.
//!
//! Security: All paths are validated and canonicalized to prevent:
//! - Path traversal attacks (../, etc.)
//! - Symlink attacks (symlinks pointing outside storage)
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

/// Sanitize paste ID by validating it contains only safe characters.
///
/// Returns a validated ID string that is safe to use in paths.
/// This is the security barrier that prevents path traversal attacks.
///
/// Allowed characters: `[A-Za-z0-9_-]` (nanoid charset)
/// Minimum length: 2 characters (for sharding)
fn sanitize_blob_id(id: &str) -> Result<&str, BlobError> {
    // Reject IDs that are too short for sharding
    if id.len() < 2 {
        return Err(BlobError::InvalidId(
            "ID must be at least 2 characters".to_string(),
        ));
    }

    // Validate every character is in the safe set [A-Za-z0-9_-]
    // This prevents path traversal since '.' , '/' , '\' are not allowed
    for c in id.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return Err(BlobError::InvalidId(
                "ID contains invalid characters".to_string(),
            ));
        }
    }

    // Return the validated ID - it's now safe to use in paths
    Ok(id)
}

/// Initialize the storage directory.
///
/// Creates the storage directory if it doesn't exist.
/// Requires an absolute path to prevent ambiguity.
pub async fn init_storage(storage_path: &Path) -> Result<(), BlobError> {
    if !storage_path.is_absolute() {
        return Err(BlobError::InvalidId(
            "Storage path must be absolute".to_string(),
        ));
    }

    fs::create_dir_all(storage_path).await?;
    Ok(())
}

/// Canonicalize and validate the storage root path.
///
/// This function establishes the trust boundary for all blob operations.
/// After this point, the returned `PathBuf` is treated as a trusted,
/// absolute, canonical root directory — not derived from user input.
fn canonicalize_storage_root(storage_path: &Path) -> Result<PathBuf, BlobError> {
    if !storage_path.is_absolute() {
        return Err(BlobError::InvalidId(
            "Storage path must be absolute".to_string(),
        ));
    }
    Ok(storage_path.canonicalize()?)
}

/// Resolve and verify a blob path from a user-provided ID.
///
/// Security: `canonical_storage` must come from `canonicalize_storage_root`,
/// which establishes it as a trusted root. This function sanitizes the user
/// ID, canonicalizes the constructed path, verifies it stays within storage
/// via `strip_prefix`, and reconstructs from the trusted root + verified
/// relative suffix.
///
/// Returns `Ok(None)` if the blob doesn't exist on disk.
fn resolve_blob_path(canonical_storage: &Path, id: &str) -> Result<Option<PathBuf>, BlobError> {
    let safe_id = sanitize_blob_id(id)?;
    let shard_name = &safe_id[..2];
    let constructed_path = canonical_storage.join(shard_name).join(safe_id);

    let canonical_path = match constructed_path.canonicalize() {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(BlobError::Io(e)),
    };

    // Verify path is within storage; strip_prefix returns the relative suffix
    let relative = canonical_path
        .strip_prefix(canonical_storage)
        .map_err(|_| BlobError::InvalidId("Path escapes storage directory".to_string()))?;

    // Reconstruct from trusted root + verified relative path.
    // This creates a new PathBuf derived from the storage root, not from user input.
    Ok(Some(canonical_storage.join(relative)))
}

/// Write a blob to disk.
///
/// Uses atomic write (write to temp file, then rename) to prevent partial reads.
pub async fn write_blob(storage_path: &Path, id: &str, content: &[u8]) -> Result<(), BlobError> {
    let safe_id = sanitize_blob_id(id)?;
    let canonical_storage = canonicalize_storage_root(storage_path)?;

    // Build and create shard directory
    let shard_name = &safe_id[..2];
    let shard_dir = canonical_storage.join(shard_name);
    fs::create_dir_all(&shard_dir).await?;

    // Verify shard directory is within storage; reconstruct from trusted root
    let canonical_shard = shard_dir.canonicalize()?;
    let shard_relative = canonical_shard
        .strip_prefix(&canonical_storage)
        .map_err(|_| BlobError::InvalidId("Path escapes storage directory".to_string()))?;
    let verified_shard = canonical_storage.join(shard_relative);

    // Build final paths from verified shard
    let blob_path = verified_shard.join(safe_id);
    let temp_path = blob_path.with_extension("tmp");

    // Belt-and-suspenders: verify blob path is also within storage
    blob_path
        .strip_prefix(&canonical_storage)
        .map_err(|_| BlobError::InvalidId("Path escapes storage directory".to_string()))?;

    // Write atomically: temp file (exclusive create) -> sync -> rename.
    // If a stale temp file exists from a previous crash, remove it first.
    let open_result = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .await;
    let mut file = match open_result {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temp_path).await?;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .await?
        }
        Err(e) => return Err(e.into()),
    };
    file.write_all(content).await?;
    file.sync_all().await?;
    fs::rename(&temp_path, &blob_path).await?;

    Ok(())
}

/// Read a blob from disk with a size limit.
///
/// Returns None if the blob doesn't exist.
/// `max_bytes` caps how large a blob we'll read (prevents OOM from corrupt files).
pub async fn read_blob(
    storage_path: &Path,
    id: &str,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, BlobError> {
    let canonical_storage = canonicalize_storage_root(storage_path)?;
    let verified_path = match resolve_blob_path(&canonical_storage, id)? {
        Some(p) => p,
        None => return Ok(None),
    };

    let file = fs::File::open(&verified_path).await?;
    let metadata = file.metadata().await?;
    let file_size = metadata.len();

    if file_size > max_bytes {
        return Err(BlobError::InvalidId(format!(
            "Blob too large: {} bytes exceeds {}",
            file_size, max_bytes
        )));
    }

    let mut content = Vec::with_capacity(file_size as usize);
    let mut reader = file;
    reader.read_to_end(&mut content).await?;
    Ok(Some(content))
}

/// Delete a blob from disk.
///
/// Returns true if the blob was deleted, false if it didn't exist.
pub async fn delete_blob(storage_path: &Path, id: &str) -> Result<bool, BlobError> {
    let canonical_storage = canonicalize_storage_root(storage_path)?;
    let verified_path = match resolve_blob_path(&canonical_storage, id)? {
        Some(p) => p,
        None => return Ok(false),
    };

    fs::remove_file(&verified_path).await?;
    Ok(true)
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
        let read_content = read_blob(storage_path, id, 1024 * 1024).await.unwrap();
        assert_eq!(read_content, Some(content.to_vec()));

        // Delete
        let deleted = delete_blob(storage_path, id).await.unwrap();
        assert!(deleted);

        // Read after delete
        let read_content = read_blob(storage_path, id, 1024 * 1024).await.unwrap();
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
    async fn test_id_too_short() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        let result = write_blob(storage_path, "a", b"content").await;
        assert!(matches!(result, Err(BlobError::InvalidId(_))));
    }

    #[tokio::test]
    async fn test_path_traversal_dotdot() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        // Various ../ attempts
        let attacks = [
            "../etc/passwd",
            "..%2fetc%2fpasswd",
            "ab/../../../etc/passwd",
            "ab..cd..ef",
            "..",
            "ab..",
            "..ab",
        ];

        for id in attacks {
            let result = write_blob(storage_path, id, b"malicious").await;
            assert!(
                matches!(result, Err(BlobError::InvalidId(_))),
                "Expected InvalidId for '{}', got {:?}",
                id,
                result
            );
        }
    }

    #[tokio::test]
    async fn test_path_traversal_slash() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        let attacks = [
            "ab/cd",
            "/etc/passwd",
            "ab/../../etc/passwd",
            "valid_start/bad",
        ];

        for id in attacks {
            let result = write_blob(storage_path, id, b"malicious").await;
            assert!(
                matches!(result, Err(BlobError::InvalidId(_))),
                "Expected InvalidId for '{}', got {:?}",
                id,
                result
            );
        }
    }

    #[tokio::test]
    async fn test_path_traversal_backslash() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        let attacks = ["ab\\cd", "ab\\..\\..\\etc\\passwd", "valid\\bad"];

        for id in attacks {
            let result = write_blob(storage_path, id, b"malicious").await;
            assert!(
                matches!(result, Err(BlobError::InvalidId(_))),
                "Expected InvalidId for '{}', got {:?}",
                id,
                result
            );
        }
    }

    #[tokio::test]
    async fn test_invalid_characters() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        // Characters outside [A-Za-z0-9_-]
        let invalid = [
            "ab.txt",   // dot
            "ab cd",    // space
            "ab\0cd",   // null byte
            "ab\ncd",   // newline
            "ab:cd",    // colon (Windows drive separator)
            "ab<cd",    // angle bracket
            "ab>cd",    // angle bracket
            "ab|cd",    // pipe
            "ab\"cd",   // quote
            "ab*cd",    // wildcard
            "ab?cd",    // wildcard
            "ab%00cd",  // URL-encoded null
            "ab\tcd",   // tab
            "ab;cd",    // semicolon
            "ab&cd",    // ampersand
            "ab$cd",    // dollar
            "ab`cd",    // backtick
            "ab'cd",    // single quote
            "ab=cd",    // equals
            "ab+cd",    // plus (not in nanoid default charset)
            "ab@cd",    // at sign
            "ab#cd",    // hash
            "ab!cd",    // exclamation
            "ab(cd",    // parenthesis
            "ab)cd",    // parenthesis
            "ab[cd",    // bracket
            "ab]cd",    // bracket
            "ab{cd",    // brace
            "ab}cd",    // brace
            "ab~cd",    // tilde
            "ab\x7fcd", // DEL character
            "ab\x00cd", // NUL character
            "café12",   // non-ASCII
            "ab中文cd", // unicode
            "ab🎉cd",   // emoji
        ];

        for id in invalid {
            let result = write_blob(storage_path, id, b"content").await;
            assert!(
                matches!(result, Err(BlobError::InvalidId(_))),
                "Expected InvalidId for {:?}, got {:?}",
                id,
                result
            );
        }
    }

    #[tokio::test]
    async fn test_valid_nanoid_charset() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        // Valid nanoid characters: A-Z, a-z, 0-9, _, -
        let valid = [
            "abcdefghijkl",
            "ABCDEFGHIJKL",
            "0123456789ab",
            "ab_cd_ef_gh_",
            "ab-cd-ef-gh-",
            "aB3_xY9-zZ0a",
            "____________",
            "------------",
        ];

        for id in valid {
            let result = write_blob(storage_path, id, b"content").await;
            assert!(
                result.is_ok(),
                "Expected success for '{}', got {:?}",
                id,
                result
            );
            // Clean up
            delete_blob(storage_path, id).await.unwrap();
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_symlink_attack_read() {
        use std::os::unix::fs::symlink;

        // Use two separate temp directories - one for storage, one for "attacker" files
        let storage_temp = TempDir::new().unwrap();
        let attacker_temp = TempDir::new().unwrap();

        let storage_path = storage_temp.path();
        init_storage(storage_path).await.unwrap();

        // Create a shard directory
        let shard_dir = storage_path.join("sy");
        fs::create_dir_all(&shard_dir).await.unwrap();

        // Create a target file truly outside storage (in different temp dir)
        let outside_file = attacker_temp.path().join("secret.txt");
        std::fs::write(&outside_file, b"secret data").unwrap();

        // Create a symlink inside storage pointing outside
        let symlink_path = shard_dir.join("symlink_attack");
        symlink(&outside_file, &symlink_path).unwrap();

        // Attempt to read via the symlink - should fail because resolved path
        // is outside storage directory
        let result = read_blob(storage_path, "symlink_attack", 1024 * 1024).await;
        assert!(
            matches!(result, Err(BlobError::InvalidId(_))),
            "Expected InvalidId for symlink attack, got {:?}",
            result
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_symlink_attack_delete() {
        use std::os::unix::fs::symlink;

        // Use two separate temp directories
        let storage_temp = TempDir::new().unwrap();
        let attacker_temp = TempDir::new().unwrap();

        let storage_path = storage_temp.path();
        init_storage(storage_path).await.unwrap();

        // Create a shard directory
        let shard_dir = storage_path.join("sy");
        fs::create_dir_all(&shard_dir).await.unwrap();

        // Create a target file truly outside storage that we don't want deleted
        let outside_file = attacker_temp.path().join("important.txt");
        std::fs::write(&outside_file, b"important data").unwrap();

        // Create a symlink inside storage pointing outside
        let symlink_path = shard_dir.join("symlink_del_atk");
        symlink(&outside_file, &symlink_path).unwrap();

        // Attempt to delete via the symlink - should fail
        let result = delete_blob(storage_path, "symlink_del_atk").await;
        assert!(
            matches!(result, Err(BlobError::InvalidId(_))),
            "Expected InvalidId for symlink delete attack, got {:?}",
            result
        );

        // Verify the outside file still exists
        assert!(
            outside_file.exists(),
            "Outside file should not have been deleted"
        );
    }

    #[tokio::test]
    async fn test_relative_storage_path_rejected() {
        let result = init_storage(Path::new("relative/path")).await;
        assert!(
            matches!(result, Err(BlobError::InvalidId(_))),
            "Expected InvalidId for relative path, got {:?}",
            result
        );
    }
}
