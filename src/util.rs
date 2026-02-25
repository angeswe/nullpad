//! Shared utility helpers.

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
