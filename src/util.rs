//! Shared utility helpers.

/// Check that every character in `id` is in the nanoid charset `[A-Za-z0-9_-]`
/// and that `id.len() >= min_len`.
///
/// Returns `true` when the ID is valid, `false` otherwise.
///
/// Used by route validation, blob storage path construction, and the cleanup
/// job to avoid duplicating the same character-set check in multiple places.
pub fn is_valid_nanoid(id: &str, min_len: usize) -> bool {
    id.len() >= min_len
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Get current time as seconds since UNIX epoch.
///
/// Returns 0 if the system clock is before the epoch (avoids panic with `unwrap()`).
/// With `panic = "abort"` in release profile, a panic would kill the server.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
