//! Shared utility helpers.

/// The nanoid charset: the only bytes an ID may contain.
///
/// Single source of truth for the ID alphabet. `blob.rs` indexes this table to
/// build filesystem paths, `routes` validates request IDs against it, and the
/// cleanup job uses it to tell paste blobs from stray files. If these drifted
/// apart, routes would accept IDs blob storage rejects and cleanup would
/// misclassify live blobs as orphans.
///
/// No byte here is a path separator, so an ID drawn from it cannot traverse.
pub const NANOID_CHARSET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/// Check that every byte of `id` is in [`NANOID_CHARSET`] and `id.len() >= min_len`.
///
/// Returns `true` when the ID is valid, `false` otherwise.
///
/// Scanning bytes rather than chars is equivalent: `&str` is valid UTF-8, where
/// an ASCII byte can only appear as a standalone single-byte char, and every
/// byte of a multi-byte char is >= 0x80 and so absent from the charset.
pub fn is_valid_nanoid(id: &str, min_len: usize) -> bool {
    id.len() >= min_len && id.bytes().all(|b| NANOID_CHARSET.contains(&b))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_charset_is_exactly_alphanumeric_underscore_hyphen() {
        // Both directions matter. Subset is the security property: no separator
        // may sneak in. Superset is the availability one: dropping a byte (a typo
        // duplicating one and losing another still compiles and keeps the length
        // at 64) would make every existing paste whose ID contains it unreadable,
        // and cleanup would then delete those blobs as orphans.
        let mut expected: Vec<u8> = (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'0'..=b'9')
            .chain(*b"_-")
            .collect();
        let mut actual = NANOID_CHARSET.to_vec();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected, "charset drifted from [A-Za-z0-9_-]");
    }

    #[test]
    fn test_is_valid_nanoid_rejects_non_ascii() {
        // Every byte of a multi-byte char is >= 0x80, so none is in the charset.
        assert!(!is_valid_nanoid("café12", 2));
        assert!(!is_valid_nanoid("ab中文cd", 2));
        assert!(is_valid_nanoid("abcd12", 2));
    }
}
