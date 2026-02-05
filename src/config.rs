use std::env;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
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
    pub rate_limit_paste_per_hour: u32,
    pub rate_limit_auth_per_min: u32,
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

        let admin_alias = env::var("ADMIN_ALIAS").unwrap_or_else(|_| "admin".to_string());

        // Redis
        let redis_url =
            env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

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
        let rate_limit_paste_per_hour = parse_env_or_default("RATE_LIMIT_PASTE_PER_HOUR", 100)?;
        let rate_limit_auth_per_min = parse_env_or_default("RATE_LIMIT_AUTH_PER_MIN", 5)?;

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
            rate_limit_paste_per_hour,
            rate_limit_auth_per_min,
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
        Ok(val) => val.parse::<T>().map_err(|e| {
            ConfigError::ParseError(key.to_string(), format!("{}: {}", e, val))
        }),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Use a mutex to ensure tests run serially since they modify global env vars
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

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
        env::remove_var("RATE_LIMIT_PASTE_PER_HOUR");
        env::remove_var("RATE_LIMIT_AUTH_PER_MIN");
    }

    #[test]
    fn test_parse_env_or_default() {
        let _guard = TEST_MUTEX.lock().unwrap();

        env::set_var("TEST_U64", "12345");
        let result: Result<u64, ConfigError> = parse_env_or_default("TEST_U64", 100);
        assert_eq!(result.unwrap(), 12345);

        env::remove_var("TEST_U64");
        let result: Result<u64, ConfigError> = parse_env_or_default("TEST_U64", 100);
        assert_eq!(result.unwrap(), 100);
    }

    #[test]
    fn test_invalid_socket_addr() {
        let _guard = TEST_MUTEX.lock().unwrap();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", "test_pubkey");
        env::set_var("BIND_ADDR", "invalid_address");

        let result = Config::from_env();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::ParseError(_, _)));

        clear_test_env();
    }

    #[test]
    fn test_missing_admin_pubkey() {
        let _guard = TEST_MUTEX.lock().unwrap();
        clear_test_env();

        let result = Config::from_env();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::MissingVar(ref s) if s == "ADMIN_PUBKEY"
        ));

        clear_test_env();
    }

    #[test]
    fn test_empty_admin_pubkey() {
        let _guard = TEST_MUTEX.lock().unwrap();
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
    fn test_public_allowed_extensions_parsing() {
        let _guard = TEST_MUTEX.lock().unwrap();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", "test_pubkey");
        env::set_var("PUBLIC_ALLOWED_EXTENSIONS", "md, txt, json ");

        let config = Config::from_env().unwrap();
        assert_eq!(config.public_allowed_extensions, vec!["md", "txt", "json"]);

        clear_test_env();
    }

    #[test]
    fn test_config_defaults() {
        let _guard = TEST_MUTEX.lock().unwrap();
        clear_test_env();

        env::set_var("ADMIN_PUBKEY", "test_pubkey_base64");

        let config = Config::from_env().unwrap();

        assert_eq!(config.admin_pubkey, "test_pubkey_base64");
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
        assert_eq!(config.rate_limit_paste_per_hour, 100);
        assert_eq!(config.rate_limit_auth_per_min, 5);

        clear_test_env();
    }
}
