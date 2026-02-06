use base64::{engine::general_purpose, Engine as _};
use std::env;
use std::net::SocketAddr;

#[derive(Clone)]
pub struct Config {
    // Admin identity
    pub admin_pubkey: String,
    pub admin_alias: String,

    // Redis
    pub redis_url: String,

    // Server
    pub bind_addr: SocketAddr,

    // Limits
    pub max_upload_bytes: usize,

    // TTLs (in seconds)
    pub default_ttl_secs: u64,
    pub max_ttl_secs: u64,
    pub invite_ttl_secs: u64,
    pub user_idle_ttl_secs: u64,
    pub user_active_ttl_secs: u64,
    pub session_ttl_secs: u64,
    pub challenge_ttl_secs: u64,

    // Public mode restrictions
    pub public_allowed_extensions: Vec<String>,

    // Rate limiting
    pub rate_limit_paste_per_min: u32,
    pub rate_limit_auth_per_min: u32,

    // Proxy
    pub trusted_proxy_count: usize,

    // Session management
    pub max_sessions_per_user: usize,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("admin_pubkey", &"[REDACTED]")
            .field("admin_alias", &self.admin_alias)
            .field("redis_url", &"[REDACTED]")
            .field("bind_addr", &self.bind_addr)
            .field("max_upload_bytes", &self.max_upload_bytes)
            .field("default_ttl_secs", &self.default_ttl_secs)
            .field("max_ttl_secs", &self.max_ttl_secs)
            .field("invite_ttl_secs", &self.invite_ttl_secs)
            .field("user_idle_ttl_secs", &self.user_idle_ttl_secs)
            .field("user_active_ttl_secs", &self.user_active_ttl_secs)
            .field("session_ttl_secs", &self.session_ttl_secs)
            .field("challenge_ttl_secs", &self.challenge_ttl_secs)
            .field("public_allowed_extensions", &self.public_allowed_extensions)
            .field("rate_limit_paste_per_min", &self.rate_limit_paste_per_min)
            .field("rate_limit_auth_per_min", &self.rate_limit_auth_per_min)
            .field("trusted_proxy_count", &self.trusted_proxy_count)
            .field("max_sessions_per_user", &self.max_sessions_per_user)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    MissingVar(String),

    #[error("Invalid value for {0}: {1}")]
    InvalidValue(String, String),

    #[error("Failed to parse {0}: {1}")]
    ParseError(String, String),
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        // Attempt to load .env file, but don't fail if it doesn't exist
        // (env vars may be set directly in production)
        let _ = dotenvy::dotenv();

        // Admin identity - ADMIN_PUBKEY is required
        let admin_pubkey = env::var("ADMIN_PUBKEY")
            .map_err(|_| ConfigError::MissingVar("ADMIN_PUBKEY".to_string()))?;

        if admin_pubkey.is_empty() {
            return Err(ConfigError::InvalidValue(
                "ADMIN_PUBKEY".to_string(),
                "cannot be empty".to_string(),
            ));
        }

        // Validate ADMIN_PUBKEY is valid base64 and decodes to 32 bytes (Ed25519 public key)
        let pubkey_bytes = general_purpose::STANDARD
            .decode(&admin_pubkey)
            .map_err(|e| {
                ConfigError::InvalidValue(
                    "ADMIN_PUBKEY".to_string(),
                    format!("invalid base64: {}", e),
                )
            })?;
        if pubkey_bytes.len() != 32 {
            return Err(ConfigError::InvalidValue(
                "ADMIN_PUBKEY".to_string(),
                format!(
                    "expected 32 bytes (Ed25519 public key), got {}",
                    pubkey_bytes.len()
                ),
            ));
        }

        let admin_alias = env::var("ADMIN_ALIAS").unwrap_or_else(|_| "admin".to_string());

        // Validate ADMIN_ALIAS: same rules as user aliases (2-64 chars, alphanumeric + hyphen + underscore)
        if admin_alias.len() < 2 || admin_alias.len() > 64 {
            return Err(ConfigError::InvalidValue(
                "ADMIN_ALIAS".to_string(),
                "must be 2-64 characters".to_string(),
            ));
        }
        if !admin_alias
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ConfigError::InvalidValue(
                "ADMIN_ALIAS".to_string(),
                "may only contain alphanumeric characters, hyphens, and underscores".to_string(),
            ));
        }

        // Redis — required to prevent silent unauthenticated connections
        let redis_url =
            env::var("REDIS_URL").map_err(|_| ConfigError::MissingVar("REDIS_URL".to_string()))?;

        // Server
        let bind_addr_str = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
        let bind_addr = bind_addr_str
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::ParseError("BIND_ADDR".to_string(), e.to_string()))?;

        // Limits
        let max_upload_bytes = parse_env_or_default("MAX_UPLOAD_BYTES", 52_428_800)?;

        // TTLs
        let default_ttl_secs = parse_env_or_default("DEFAULT_TTL_SECS", 86_400)?;
        let max_ttl_secs = parse_env_or_default("MAX_TTL_SECS", 604_800)?;
        let invite_ttl_secs = parse_env_or_default("INVITE_TTL_SECS", 43_200)?;
        let user_idle_ttl_secs = parse_env_or_default("USER_IDLE_TTL_SECS", 172_800)?;
        let user_active_ttl_secs = parse_env_or_default("USER_ACTIVE_TTL_SECS", 86_400)?;
        let session_ttl_secs = parse_env_or_default("SESSION_TTL_SECS", 900)?;
        let challenge_ttl_secs = parse_env_or_default("CHALLENGE_TTL_SECS", 30)?;

        // Public mode restrictions
        let public_allowed_extensions_str =
            env::var("PUBLIC_ALLOWED_EXTENSIONS").unwrap_or_else(|_| "md,txt".to_string());
        let public_allowed_extensions: Vec<String> = public_allowed_extensions_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Rate limiting
        let rate_limit_paste_per_min = parse_env_or_default("RATE_LIMIT_PASTE_PER_MIN", 10)?;
        let rate_limit_auth_per_min = parse_env_or_default("RATE_LIMIT_AUTH_PER_MIN", 5)?;

        // Proxy configuration
        let trusted_proxy_count = parse_env_or_default("TRUSTED_PROXY_COUNT", 0)?;

        // Session management
        let max_sessions_per_user = parse_env_or_default("MAX_SESSIONS_PER_USER", 5)?;

        Ok(Config {
            admin_pubkey,
            admin_alias,
            redis_url,
            bind_addr,
            max_upload_bytes,
            default_ttl_secs,
            max_ttl_secs,
            invite_ttl_secs,
            user_idle_ttl_secs,
            user_active_ttl_secs,
            session_ttl_secs,
            challenge_ttl_secs,
            public_allowed_extensions,
            rate_limit_paste_per_min,
            rate_limit_auth_per_min,
            trusted_proxy_count,
            max_sessions_per_user,
        })
    }
}

/// Helper function to parse environment variable with a default value
fn parse_env_or_default<T>(key: &str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(key) {
        Ok(val) => val
            .parse::<T>()
            .map_err(|e| ConfigError::ParseError(key.to_string(), format!("{}: {}", e, val))),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Use a mutex to ensure tests run serially since they modify global env vars.
    // unwrap_or_else handles poison from prior panics.
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn lock_test() -> std::sync::MutexGuard<'static, ()> {
        TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn clear_test_env() {
        env::remove_var("ADMIN_PUBKEY");
        env::remove_var("ADMIN_ALIAS");
        env::remove_var("REDIS_URL");
        env::remove_var("BIND_ADDR");
        env::remove_var("MAX_UPLOAD_BYTES");
        env::remove_var("DEFAULT_TTL_SECS");
        env::remove_var("MAX_TTL_SECS");
        env::remove_var("INVITE_TTL_SECS");
        env::remove_var("USER_IDLE_TTL_SECS");
        env::remove_var("USER_ACTIVE_TTL_SECS");
        env::remove_var("SESSION_TTL_SECS");
        env::remove_var("CHALLENGE_TTL_SECS");
        env::remove_var("PUBLIC_ALLOWED_EXTENSIONS");
        env::remove_var("RATE_LIMIT_PASTE_PER_MIN");
        env::remove_var("RATE_LIMIT_AUTH_PER_MIN");
        env::remove_var("TRUSTED_PROXY_COUNT");
        env::remove_var("MAX_SESSIONS_PER_USER");
    }

    #[test]
    fn test_parse_env_or_default() {
        let _guard = lock_test();

        env::set_var("TEST_U64", "12345");
        let result: Result<u64, ConfigError> = parse_env_or_default("TEST_U64", 100);
        assert_eq!(result.unwrap(), 12345);

        env::remove_var("TEST_U64");
        let result: Result<u64, ConfigError> = parse_env_or_default("TEST_U64", 100);
        assert_eq!(result.unwrap(), 100);
    }

    // Valid 32-byte Ed25519 public key encoded as base64 for tests
    const TEST_PUBKEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn test_invalid_socket_addr() {
        let _guard = lock_test();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", TEST_PUBKEY_B64);
        env::set_var("REDIS_URL", "redis://127.0.0.1:6379");
        env::set_var("BIND_ADDR", "invalid_address");

        let result = Config::from_env();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::ParseError(_, _)));

        clear_test_env();
    }

    #[test]
    fn test_missing_admin_pubkey() {
        let _guard = lock_test();
        clear_test_env();

        // Set ADMIN_PUBKEY to empty to prevent dotenvy from reloading
        // a valid key from .env (dotenvy doesn't override existing vars).
        // This triggers the "cannot be empty" check in from_env().
        env::set_var("ADMIN_PUBKEY", "");

        let result = Config::from_env();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidValue(ref s, _) if s == "ADMIN_PUBKEY"
        ));

        clear_test_env();
    }

    #[test]
    fn test_empty_admin_pubkey() {
        let _guard = lock_test();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", "");

        let result = Config::from_env();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidValue(ref s, _) if s == "ADMIN_PUBKEY"
        ));

        clear_test_env();
    }

    #[test]
    fn test_invalid_admin_pubkey_base64() {
        let _guard = lock_test();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", "not-valid-base64!!!");

        let result = Config::from_env();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidValue(ref s, _) if s == "ADMIN_PUBKEY"
        ));

        clear_test_env();
    }

    #[test]
    fn test_invalid_admin_pubkey_length() {
        let _guard = lock_test();
        clear_test_env();

        // Valid base64 but only 16 bytes (not 32)
        env::set_var("ADMIN_PUBKEY", "AAAAAAAAAAAAAAAAAAAAAA==");

        let result = Config::from_env();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidValue(ref s, _) if s == "ADMIN_PUBKEY"
        ));

        clear_test_env();
    }

    #[test]
    fn test_public_allowed_extensions_parsing() {
        let _guard = lock_test();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", TEST_PUBKEY_B64);
        env::set_var("REDIS_URL", "redis://127.0.0.1:6379");
        env::set_var("PUBLIC_ALLOWED_EXTENSIONS", "md, txt, json ");

        let config = Config::from_env().unwrap();
        assert_eq!(config.public_allowed_extensions, vec!["md", "txt", "json"]);

        clear_test_env();
    }

    #[test]
    fn test_invalid_admin_alias_too_short() {
        let _guard = lock_test();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", TEST_PUBKEY_B64);
        env::set_var("REDIS_URL", "redis://127.0.0.1:6379");
        env::set_var("ADMIN_ALIAS", "a"); // Only 1 character

        let result = Config::from_env();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidValue(ref s, _) if s == "ADMIN_ALIAS"
        ));

        clear_test_env();
    }

    #[test]
    fn test_invalid_admin_alias_too_long() {
        let _guard = lock_test();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", TEST_PUBKEY_B64);
        env::set_var("REDIS_URL", "redis://127.0.0.1:6379");
        // 65 characters (exceeds 64 max)
        env::set_var("ADMIN_ALIAS", "a".repeat(65));

        let result = Config::from_env();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidValue(ref s, _) if s == "ADMIN_ALIAS"
        ));

        clear_test_env();
    }

    #[test]
    fn test_invalid_admin_alias_special_chars() {
        let _guard = lock_test();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", TEST_PUBKEY_B64);
        env::set_var("REDIS_URL", "redis://127.0.0.1:6379");
        env::set_var("ADMIN_ALIAS", "admin@example"); // Contains '@'

        let result = Config::from_env();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidValue(ref s, _) if s == "ADMIN_ALIAS"
        ));

        clear_test_env();
    }

    #[test]
    fn test_invalid_admin_alias_spaces() {
        let _guard = lock_test();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", TEST_PUBKEY_B64);
        env::set_var("REDIS_URL", "redis://127.0.0.1:6379");
        env::set_var("ADMIN_ALIAS", "admin user"); // Contains space

        let result = Config::from_env();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidValue(ref s, _) if s == "ADMIN_ALIAS"
        ));

        clear_test_env();
    }

    #[test]
    fn test_valid_admin_alias_with_hyphens_underscores() {
        let _guard = lock_test();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", TEST_PUBKEY_B64);
        env::set_var("REDIS_URL", "redis://127.0.0.1:6379");
        env::set_var("ADMIN_ALIAS", "admin_user-123");

        let config = Config::from_env().unwrap();
        assert_eq!(config.admin_alias, "admin_user-123");

        clear_test_env();
    }

    #[test]
    fn test_valid_admin_alias_edge_lengths() {
        let _guard = lock_test();
        clear_test_env();

        // Test minimum length (2 chars)
        env::set_var("ADMIN_PUBKEY", TEST_PUBKEY_B64);
        env::set_var("REDIS_URL", "redis://127.0.0.1:6379");
        env::set_var("ADMIN_ALIAS", "ab");

        let config = Config::from_env().unwrap();
        assert_eq!(config.admin_alias, "ab");

        // Test maximum length (64 chars)
        env::set_var("ADMIN_ALIAS", "a".repeat(64));
        let config = Config::from_env().unwrap();
        assert_eq!(config.admin_alias.len(), 64);

        clear_test_env();
    }

    #[test]
    fn test_config_defaults() {
        let _guard = lock_test();
        clear_test_env();

        // Set required var + override any .env defaults to ensure predictable values
        env::set_var("ADMIN_PUBKEY", TEST_PUBKEY_B64);
        env::set_var("REDIS_URL", "redis://127.0.0.1:6379");
        env::set_var("BIND_ADDR", "0.0.0.0:3000");

        let config = Config::from_env().unwrap();

        assert_eq!(config.admin_pubkey, TEST_PUBKEY_B64);
        assert_eq!(config.admin_alias, "admin");
        assert_eq!(config.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(config.bind_addr.to_string(), "0.0.0.0:3000");
        assert_eq!(config.max_upload_bytes, 52_428_800);
        assert_eq!(config.default_ttl_secs, 86_400);
        assert_eq!(config.max_ttl_secs, 604_800);
        assert_eq!(config.invite_ttl_secs, 43_200);
        assert_eq!(config.user_idle_ttl_secs, 172_800);
        assert_eq!(config.user_active_ttl_secs, 86_400);
        assert_eq!(config.session_ttl_secs, 900);
        assert_eq!(config.challenge_ttl_secs, 30);
        assert_eq!(config.public_allowed_extensions, vec!["md", "txt"]);
        assert_eq!(config.rate_limit_paste_per_min, 10);
        assert_eq!(config.rate_limit_auth_per_min, 5);
        assert_eq!(config.max_sessions_per_user, 5);

        clear_test_env();
    }
}
