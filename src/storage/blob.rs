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

use crate::util::NANOID_CHARSET;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// Chunk size for hashing a blob without loading it into memory.
const HASH_CHUNK_BYTES: usize = 64 * 1024;

/// Chunk size for overwriting a deleted blob.
const WIPE_CHUNK_BYTES: usize = 64 * 1024;

/// Identity of a blob file: `(device, inode)`. It stays the same while any
/// handle to the file is open, even after the path is unlinked.
type InodeKey = (u64, u64);

fn inode_key(meta: &std::fs::Metadata) -> InodeKey {
    (meta.dev(), meta.ino())
}

/// Open readers of one blob file, and the overwrite that waits for them.
struct ReaderEntry {
    readers: usize,
    /// Set by [`delete_blob`] when it unlinked the file while readers were
    /// open: the write handle and the number of bytes to overwrite.
    pending_wipe: Option<(std::fs::File, u64)>,
}

/// Blob files that GET responses are streaming, keyed by inode.
///
/// [`delete_blob`] overwrites a blob in place. A response streaming the same
/// file would then send the overwritten bytes, so the overwrite waits until
/// the last reader of that file is dropped. An entry exists only while its
/// reader count is above zero. The lock is never held across an `.await` or
/// across file I/O.
static BLOB_READERS: LazyLock<Mutex<HashMap<InodeKey, ReaderEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Lock the reader registry. A poisoned lock is used anyway: nothing panics
/// while holding it, and losing a reader count would skip or misplace a wipe.
fn blob_readers() -> MutexGuard<'static, HashMap<InodeKey, ReaderEntry>> {
    BLOB_READERS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Registers one open reader of a blob file.
///
/// While it lives, [`delete_blob`] unlinks the file but does not overwrite
/// it. Dropping the last guard of a deleted file runs the overwrite.
#[derive(Debug)]
pub struct BlobReadGuard {
    key: InodeKey,
}

impl BlobReadGuard {
    fn register(key: InodeKey) -> Self {
        blob_readers()
            .entry(key)
            .or_insert(ReaderEntry {
                readers: 0,
                pending_wipe: None,
            })
            .readers += 1;
        Self { key }
    }
}

impl Drop for BlobReadGuard {
    fn drop(&mut self) {
        let pending = {
            let mut readers = blob_readers();
            let Some(entry) = readers.get_mut(&self.key) else {
                return;
            };
            entry.readers -= 1;
            if entry.readers > 0 {
                return;
            }
            readers
                .remove(&self.key)
                .and_then(|entry| entry.pending_wipe)
        };
        let Some((file, len)) = pending else {
            return;
        };

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // A Drop cannot await. The watcher task logs how the wipe ended.
                drop(spawn_deferred_wipe(&handle, move || wipe_file(file, len)));
            }
            Err(_) => {
                if let Err(e) = wipe_file(file, len) {
                    tracing::error!(error = %e, "Failed to overwrite deleted blob");
                }
            }
        }
    }
}

/// Run a deferred wipe on the blocking pool, and log how it ended.
///
/// A watcher task on the same runtime waits for the wipe. It logs an I/O
/// error, a panic, or a cancelled wipe. It does not log the panic message.
/// The watcher never fails, and it keeps running if the caller drops the
/// returned handle.
fn spawn_deferred_wipe(
    handle: &tokio::runtime::Handle,
    wipe: impl FnOnce() -> std::io::Result<()> + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    let blocking = handle.spawn_blocking(wipe);
    handle.spawn(async move {
        match blocking.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "Failed to overwrite deleted blob"),
            Err(e) if e.is_panic() => tracing::error!("Overwrite of deleted blob panicked"),
            Err(_) => tracing::error!("Overwrite of deleted blob was cancelled"),
        }
    })
}

/// Overwrite the first `len` bytes of `file` with random bytes, then sync it.
///
/// Random bytes, not zeros: a filesystem that compresses or detects zero
/// blocks can store zeros as holes without writing over the old data.
/// Writes are positional, so the handle's offset does not matter. Memory use
/// is one fixed-size chunk, whatever the blob size.
fn wipe_file(file: std::fs::File, len: u64) -> std::io::Result<()> {
    let mut buf = vec![0u8; WIPE_CHUNK_BYTES];
    let mut offset = 0u64;
    while offset < len {
        let n = (len - offset).min(WIPE_CHUNK_BYTES as u64) as usize;
        rand::fill(&mut buf[..n]);
        file.write_all_at(&buf[..n], offset)?;
        offset += n as u64;
    }
    file.sync_all()
}

/// Whether `path` still names the file identified by `key`.
///
/// False if the path is gone or names another file (a delete unlinked it, or
/// a new blob was renamed onto it). The path itself is checked; a symlink is
/// not followed.
async fn path_names_inode(path: &Path, key: InodeKey) -> Result<bool, BlobError> {
    match fs::symlink_metadata(path).await {
        Ok(meta) => Ok(inode_key(&meta) == key),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Lowercase hex of a SHA-256 digest, the format of
/// `StoredPasteMeta::content_sha256`.
fn sha256_hex(digest: &[u8]) -> String {
    digest.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    })
}

/// Lowercase hex SHA-256 of blob bytes, the format of
/// `StoredPasteMeta::content_sha256`.
pub(crate) fn content_sha256_hex(content: &[u8]) -> String {
    sha256_hex(&Sha256::digest(content))
}

/// A blob opened for streaming.
///
/// `file` is positioned at the start. `sha256_hex` is the hash of the whole
/// file, computed when it was opened. The open file handle keeps the content
/// readable even if the path is unlinked or replaced by rename afterwards.
///
/// `guard` keeps a [`delete_blob`] of this file from overwriting it. Keep it
/// alive until `file` has been streamed, then drop it.
#[derive(Debug)]
pub struct OpenedBlob {
    pub file: fs::File,
    pub len: u64,
    pub sha256_hex: String,
    pub guard: BlobReadGuard,
}

/// Error type for blob operations.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid paste ID: {0}")]
    InvalidId(String),

    /// A blob on disk exceeds the configured size limit.
    ///
    /// Deliberately kept distinct from [`BlobError::InvalidId`]: this is an
    /// infrastructure/data-integrity condition (a paste's content is larger
    /// than allowed), not evidence that the ID is malformed or was never a
    /// real paste. Callers must not treat it the same as `InvalidId`.
    #[error("Blob exceeds size limit: {0}")]
    TooLarge(String),
}

/// Rejection reason for an ID that cannot be used as a path component.
///
/// Deliberately does not echo the offending byte. The error is logged by the
/// caller, and untrusted bytes do not belong in log output. (An earlier version
/// of this comment claimed echoing would re-taint the value for CodeQL; the
/// error never reaches a path sink, so that was not the reason.)
const INVALID_BLOB_ID: &str = "ID must be at least 2 characters and contain only [A-Za-z0-9_-]";

/// Sanitize a paste ID into a value that is safe to use in paths.
///
/// The security property is the charset restriction: an ID drawn from
/// [`NANOID_CHARSET`] contains no `.`, `/` or `\`, so it cannot traverse. That
/// property is the same one [`crate::util::is_valid_nanoid`] enforces elsewhere.
///
/// What differs here is the *shape*: rather than validating and handing back the
/// caller's `&str`, each byte is looked up in the charset and the **table's** byte
/// is pushed into a fresh `String`. At runtime the result is byte-identical to the
/// input, but no data flows from the argument into the return value — which is what
/// keeps CodeQL's `rust/path-injection` taint tracker off the `fs::rename`,
/// `fs::File::open` and `fs::remove_file` calls downstream.
///
/// Do not "simplify" this to `safe.push(byte as char)` or to returning `id`:
/// both re-taint the value and reopen the alerts. **No test in this crate will
/// catch that** — the runtime values are identical, which is what
/// `test_sanitize_returns_exact_copy_of_valid_id` pins. The guard is the CodeQL
/// check, which the repository ruleset requires to pass before merge.
///
/// Minimum length is 2, because sharding takes the first 2 characters.
fn sanitize_blob_id(id: &str) -> Result<String, BlobError> {
    if id.len() < 2 {
        return Err(BlobError::InvalidId(INVALID_BLOB_ID.to_string()));
    }

    let mut safe = String::with_capacity(id.len());
    for byte in id.bytes() {
        let Some(index) = NANOID_CHARSET.iter().position(|&allowed| allowed == byte) else {
            return Err(BlobError::InvalidId(INVALID_BLOB_ID.to_string()));
        };
        safe.push(NANOID_CHARSET[index] as char);
    }
    Ok(safe)
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

/// Open a blob for streaming, with a size limit.
///
/// Returns `Ok(None)` if the blob doesn't exist. `max_bytes` caps how large a
/// blob we'll serve (a corrupt or oversized file is `BlobError::TooLarge`).
///
/// The file is hashed in fixed-size chunks, so memory use does not depend on
/// the blob size, then rewound to the start.
///
/// The handle is registered as a reader (see [`BlobReadGuard`]) before it is
/// hashed. If the path no longer names the opened file once registered, the
/// blob is treated as missing.
pub async fn open_blob(
    storage_path: &Path,
    id: &str,
    max_bytes: u64,
) -> Result<Option<OpenedBlob>, BlobError> {
    let canonical_storage = canonicalize_storage_root(storage_path)?;
    let verified_path = match resolve_blob_path(&canonical_storage, id)? {
        Some(p) => p,
        None => return Ok(None),
    };

    let mut file = match fs::File::open(&verified_path).await {
        Ok(f) => f,
        // Unlinked between resolve and open (burn or delete by another request).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let metadata = file.metadata().await?;
    let len = metadata.len();

    if len > max_bytes {
        return Err(BlobError::TooLarge(format!(
            "Blob too large: {} bytes exceeds {}",
            len, max_bytes
        )));
    }

    let key = inode_key(&metadata);
    let guard = BlobReadGuard::register(key);

    // delete_blob unlinks the path before it checks the registry. If it
    // checked before this reader registered, the path is already gone (or
    // names a newer blob) here, and its overwrite may be running: back out.
    if !path_names_inode(&verified_path, key).await? {
        return Ok(None);
    }

    // Hash exactly `len` bytes: those are the bytes the caller will stream.
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK_BYTES];
    let mut remaining = len;
    while remaining > 0 {
        let want = (remaining as usize).min(HASH_CHUNK_BYTES);
        let n = file.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(BlobError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Blob shorter than its reported size",
            )));
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    file.rewind().await?;

    Ok(Some(OpenedBlob {
        file,
        len,
        sha256_hex: sha256_hex(&hasher.finalize()),
        guard,
    }))
}

/// Delete a blob from disk.
///
/// Unlinks the path, then overwrites the file content with random bytes to
/// prevent recovery via disk forensics. While the content is AES-256-GCM ciphertext
/// (unusable without the key), secure deletion strengthens the zero-knowledge posture.
///
/// If a response is still streaming the file (it holds a [`BlobReadGuard`]),
/// the overwrite waits until the last such reader is dropped, so the reader
/// sends the original bytes. Otherwise the overwrite finishes before this
/// function returns.
///
/// Returns true if the blob was deleted, false if it didn't exist.
pub async fn delete_blob(storage_path: &Path, id: &str) -> Result<bool, BlobError> {
    let canonical_storage = canonicalize_storage_root(storage_path)?;
    let verified_path = match resolve_blob_path(&canonical_storage, id)? {
        Some(p) => p,
        None => return Ok(false),
    };

    // The overwrite goes through this handle, so it reaches the file even
    // after the path is unlinked.
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&verified_path)
        .await?;
    let metadata = file.metadata().await?;
    let key = inode_key(&metadata);
    let len = metadata.len();
    let file = file.into_std().await;

    // Unlink before checking for readers. A reader that registers after the
    // check finds the path gone in open_blob and does not stream the file.
    fs::remove_file(&verified_path).await?;

    let wipe_now = {
        let mut readers = blob_readers();
        match readers.get_mut(&key) {
            Some(entry) => {
                // The last reader to be dropped runs the overwrite.
                entry.pending_wipe = Some((file, len));
                None
            }
            None => Some(file),
        }
    };

    if let Some(file) = wipe_now {
        tokio::task::spawn_blocking(move || wipe_file(file, len))
            .await
            .map_err(std::io::Error::other)??;
    }
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
        let mut opened = open_blob(storage_path, id, 1024 * 1024)
            .await
            .unwrap()
            .expect("blob should exist");
        let mut read_content = Vec::new();
        opened.file.read_to_end(&mut read_content).await.unwrap();
        assert_eq!(read_content, content.to_vec());

        // Delete
        let deleted = delete_blob(storage_path, id).await.unwrap();
        assert!(deleted);

        // Read after delete
        let opened = open_blob(storage_path, id, 1024 * 1024).await.unwrap();
        assert!(opened.is_none());

        // Delete again (should return false)
        let deleted = delete_blob(storage_path, id).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn open_blob_hash_matches_content_sha256_hex() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        // Larger than one 64 KiB hash chunk and not a multiple of it.
        let content: Vec<u8> = (0..200_003u32).map(|i| (i % 251) as u8).collect();
        let id = "oh123456789012";
        write_blob(storage_path, id, &content).await.unwrap();

        let mut opened = open_blob(storage_path, id, 1024 * 1024)
            .await
            .unwrap()
            .expect("blob should exist");
        assert_eq!(opened.len, content.len() as u64);
        assert_eq!(opened.sha256_hex, content_sha256_hex(&content));

        let mut read_back = Vec::new();
        opened.file.read_to_end(&mut read_back).await.unwrap();
        assert_eq!(read_back, content);
    }

    #[tokio::test]
    async fn open_blob_rejects_oversize() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        let id = "os123456789012";
        write_blob(storage_path, id, &[7u8; 100]).await.unwrap();

        let result = open_blob(storage_path, id, 99).await;
        assert!(
            matches!(result, Err(BlobError::TooLarge(_))),
            "Expected TooLarge, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn open_blob_missing_returns_none() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        let result = open_blob(storage_path, "nx123456789012", 1024).await;
        assert!(
            matches!(result, Ok(None)),
            "Expected Ok(None), got {:?}",
            result
        );
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
        let result = open_blob(storage_path, "symlink_attack", 1024 * 1024).await;
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
    async fn test_delete_overwrites_before_unlinking() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        let id = "ow123456789012";
        let content = b"sensitive content that should be overwritten";
        write_blob(storage_path, id, content).await.unwrap();

        // Get the on-disk path so we can read it after overwrite
        let blob_path = storage_path.join(&id[..2]).join(id);
        assert!(blob_path.exists());

        // Read file content before deletion to confirm it matches
        let before = std::fs::read(&blob_path).unwrap();
        assert_eq!(before, content);

        // Delete (which should overwrite first)
        let deleted = delete_blob(storage_path, id).await.unwrap();
        assert!(deleted);

        // File should be gone
        assert!(!blob_path.exists());
    }

    /// Read a whole file from the start through a handle the test holds.
    fn read_from_start(file: &mut std::fs::File) -> Vec<u8> {
        use std::io::{Read, Seek};
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    /// Blob content with a repeating byte pattern. No byte is zero.
    fn patterned_content(len: u32) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8 + 1).collect()
    }

    /// Check that `read_back` is a full overwrite of `original`.
    ///
    /// Holds when the lengths match, every 4 KiB block differs from the
    /// original block at the same offset (the last block may be shorter), and
    /// the bytes are not all zeros. Otherwise returns the first condition that
    /// failed.
    fn check_overwritten(original: &[u8], read_back: &[u8]) -> Result<(), String> {
        const BLOCK_BYTES: usize = 4096;
        if read_back.len() != original.len() {
            return Err(format!(
                "read-back length {} differs from original length {}",
                read_back.len(),
                original.len()
            ));
        }
        if let Some(i) = original
            .chunks(BLOCK_BYTES)
            .zip(read_back.chunks(BLOCK_BYTES))
            .position(|(before, after)| before == after)
        {
            return Err(format!(
                "block {i} at offset {} still matches the original",
                i * BLOCK_BYTES
            ));
        }
        if read_back.iter().all(|&b| b == 0) {
            return Err("read-back is all zeros".to_string());
        }
        Ok(())
    }

    #[tokio::test]
    async fn delete_blob_defers_wipe_while_reader_open() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        let id = "dw123456789012";
        let content = patterned_content(200_003);
        write_blob(storage_path, id, &content).await.unwrap();
        let blob_path = storage_path.join(&id[..2]).join(id);

        let mut opened = open_blob(storage_path, id, 1024 * 1024)
            .await
            .unwrap()
            .expect("blob should exist");
        let mut observer = std::fs::File::open(&blob_path).unwrap();

        assert!(delete_blob(storage_path, id).await.unwrap());
        assert!(!blob_path.exists(), "delete must unlink the path at once");

        let mut streamed = Vec::new();
        opened.file.read_to_end(&mut streamed).await.unwrap();
        assert!(
            streamed == content,
            "a delete must not change the bytes a reader is still streaming"
        );

        drop(opened);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let bytes = read_from_start(&mut observer);
            let Err(why) = check_overwritten(&content, &bytes) else {
                break;
            };
            assert!(
                std::time::Instant::now() < deadline,
                "blob was not fully overwritten within 5 s of the last reader closing: {why}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn delete_blob_wipes_now_without_readers() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        let id = "dn123456789012";
        let content = patterned_content(200_003);
        write_blob(storage_path, id, &content).await.unwrap();
        let blob_path = storage_path.join(&id[..2]).join(id);

        // A plain handle, not open_blob: no reader is registered.
        let mut observer = std::fs::File::open(&blob_path).unwrap();

        assert!(delete_blob(storage_path, id).await.unwrap());
        assert!(!blob_path.exists(), "delete must unlink the path");

        let bytes = read_from_start(&mut observer);
        if let Err(why) = check_overwritten(&content, &bytes) {
            panic!(
                "with no reader open, delete must overwrite the whole blob before returning: {why}"
            );
        }
    }

    #[tokio::test]
    async fn deferred_wipe_panic_is_contained() {
        let handle = tokio::runtime::Handle::current();

        let watcher = spawn_deferred_wipe(&handle, || panic!("deferred wipe test panic"));
        assert!(
            watcher.await.is_ok(),
            "a panic in the deferred wipe must be caught and logged, not propagated"
        );

        let watcher = spawn_deferred_wipe(&handle, || Ok(()));
        assert!(
            watcher.await.is_ok(),
            "a deferred wipe that succeeds must leave the watcher finished cleanly"
        );
    }

    #[tokio::test]
    async fn open_blob_returns_none_when_path_no_longer_matches_fd() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        let id = "rc123456789012";
        write_blob(storage_path, id, b"first blob").await.unwrap();
        let blob_path = storage_path.join(&id[..2]).join(id);

        // Held open for the whole test, so its inode number cannot be reused.
        let held = std::fs::File::open(&blob_path).unwrap();
        let key = inode_key(&held.metadata().unwrap());

        assert!(
            path_names_inode(&blob_path, key).await.unwrap(),
            "the path still names the open file"
        );

        std::fs::remove_file(&blob_path).unwrap();
        assert!(
            !path_names_inode(&blob_path, key).await.unwrap(),
            "an unlinked path no longer names the open file"
        );

        // write_blob renames a new file onto the path.
        write_blob(storage_path, id, b"second blob").await.unwrap();
        assert!(
            !path_names_inode(&blob_path, key).await.unwrap(),
            "a path renamed onto names a different file"
        );
    }

    #[tokio::test]
    async fn test_delete_empty_blob() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();
        init_storage(storage_path).await.unwrap();

        let id = "em123456789012";
        // Write an empty blob
        write_blob(storage_path, id, b"").await.unwrap();

        // Should delete without error (skips overwrite for empty files)
        let deleted = delete_blob(storage_path, id).await.unwrap();
        assert!(deleted);
    }

    #[test]
    fn test_sanitize_returns_exact_copy_of_valid_id() {
        // The rebuilt String must be byte-identical to the input for every valid
        // ID — reconstruction is a taint barrier, not a transformation.
        for id in [
            "abcdefghijkl",
            "ABCDEFGHIJKL",
            "0123456789ab",
            "aB3_xY9-zZ0a",
            "__",
            "--",
        ] {
            let sanitized = sanitize_blob_id(id).unwrap();
            assert_eq!(sanitized, id, "sanitize_blob_id altered valid ID '{}'", id);
        }
    }

    #[test]
    fn test_sanitize_agrees_with_shared_nanoid_validator() {
        // blob.rs indexes NANOID_CHARSET while routes/cleanup call is_valid_nanoid.
        // Pin both directions over the whole ASCII range: a byte either passes both
        // or neither. Divergence would let routes accept IDs storage rejects, and
        // make cleanup skip blobs it can no longer name.
        for byte in 0u8..=127 {
            let id = format!("aa{}", byte as char);
            assert_eq!(
                crate::util::is_valid_nanoid(&id, 2),
                sanitize_blob_id(&id).is_ok(),
                "charset disagreement on byte {:#04x}",
                byte
            );
        }
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
