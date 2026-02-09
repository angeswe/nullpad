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

use std::path::Path;
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

/// Write a blob to disk.
///
/// Uses atomic write (write to temp file, then rename) to prevent partial reads.
/// Path safety is ensured by:
/// 1. Sanitizing the ID to only allow safe characters
/// 2. Building the path from canonical storage base
/// 3. Verifying the final path is within storage after creation
pub async fn write_blob(storage_path: &Path, id: &str, content: &[u8]) -> Result<(), BlobError> {
    // Sanitize ID first - this is the security barrier
    let safe_id = sanitize_blob_id(id)?;

    // Get canonical storage path
    let canonical_storage = storage_path.canonicalize()?;

    // Build path using only the safe ID
    let shard_name = &safe_id[..2];
    let shard_dir = canonical_storage.join(shard_name);

    // Create shard directory
    fs::create_dir_all(&shard_dir).await?;

    // Verify shard directory is within storage (defense in depth)
    let canonical_shard = shard_dir.canonicalize()?;
    if !canonical_shard.starts_with(&canonical_storage) {
        return Err(BlobError::InvalidId(
            "Path escapes storage directory".to_string(),
        ));
    }

    // Build final path within verified shard directory
    let blob_path = canonical_shard.join(safe_id);
    let temp_path = blob_path.with_extension("tmp");

    // Write atomically: temp file -> sync -> rename
    let mut file = fs::File::create(&temp_path).await?;
    file.write_all(content).await?;
    file.sync_all().await?;
    fs::rename(&temp_path, &blob_path).await?;

    Ok(())
}

/// Read a blob from disk.
///
/// Returns None if the blob doesn't exist.
/// Path safety is ensured by:
/// 1. Sanitizing the ID to only allow safe characters
/// 2. Canonicalizing the path to resolve symlinks
/// 3. Verifying the canonical path is within storage
pub async fn read_blob(storage_path: &Path, id: &str) -> Result<Option<Vec<u8>>, BlobError> {
    // Sanitize ID first - this is the security barrier
    let safe_id = sanitize_blob_id(id)?;

    // Get canonical storage path
    let canonical_storage = storage_path.canonicalize()?;

    // Build path using only the safe ID
    let shard_name = &safe_id[..2];
    let constructed_path = canonical_storage.join(shard_name).join(safe_id);

    // Canonicalize to resolve any symlinks
    let canonical_path = match constructed_path.canonicalize() {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(BlobError::Io(e)),
    };

    // Verify canonical path is within storage (catches symlink attacks)
    if !canonical_path.starts_with(&canonical_storage) {
        return Err(BlobError::InvalidId(
            "Path escapes storage directory".to_string(),
        ));
    }

    // Safe to read - path is verified
    let mut file = fs::File::open(&canonical_path).await?;
    let mut content = Vec::new();
    file.read_to_end(&mut content).await?;
    Ok(Some(content))
}

/// Delete a blob from disk.
///
/// Returns true if the blob was deleted, false if it didn't exist.
/// Path safety is ensured by:
/// 1. Sanitizing the ID to only allow safe characters
/// 2. Canonicalizing the path to resolve symlinks
/// 3. Verifying the canonical path is within storage
pub async fn delete_blob(storage_path: &Path, id: &str) -> Result<bool, BlobError> {
    // Sanitize ID first - this is the security barrier
    let safe_id = sanitize_blob_id(id)?;

    // Get canonical storage path
    let canonical_storage = storage_path.canonicalize()?;

    // Build path using only the safe ID
    let shard_name = &safe_id[..2];
    let constructed_path = canonical_storage.join(shard_name).join(safe_id);

    // Canonicalize to resolve any symlinks
    let canonical_path = match constructed_path.canonicalize() {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(BlobError::Io(e)),
    };

    // Verify canonical path is within storage (catches symlink attacks)
    if !canonical_path.starts_with(&canonical_storage) {
        return Err(BlobError::InvalidId(
            "Path escapes storage directory".to_string(),
        ));
    }

    // Safe to delete - path is verified
    fs::remove_file(&canonical_path).await?;
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
        let result = read_blob(storage_path, "symlink_attack").await;
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
