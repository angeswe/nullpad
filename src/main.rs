//! Nullpad application entry point.
//!
//! Bootstraps the server:
//! 1. Load configuration from environment
//! 2. Connect to Redis
//! 3. Upsert admin user
//! 4. Build router with API routes + static file serving
//! 5. Apply security headers middleware
//! 6. Start Axum server
//!
//! Also supports `keygen` subcommand for generating admin keypairs.

use nullpad::{
    auth::middleware::AppState, config::Config, middleware::security_headers, routes, storage,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

/// Generate Ed25519 keypair from alias + secret using Argon2id (same as JS client)
fn keygen(alias: &str, secret: &str) -> Result<String, String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    use ed25519_dalek::SigningKey;

    // Pad alias to 8 bytes minimum (same as JS: alias + '\0'.repeat(8 - alias.length))
    let salt = if alias.len() >= 8 {
        alias.to_string()
    } else {
        let mut padded = alias.to_string();
        padded.push_str(&"\0".repeat(8 - alias.len()));
        padded
    };

    // Argon2id with OWASP recommended params (same as JS):
    // m=19456 (19MB), t=2, p=1
    let params = Params::new(19456, 2, 1, Some(32)).map_err(|e| format!("Argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut seed = [0u8; 32];
    argon2
        .hash_password_into(secret.as_bytes(), salt.as_bytes(), &mut seed)
        .map_err(|e| format!("Argon2 hash: {}", e))?;

    // Create Ed25519 signing key from seed
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    // Zero the seed
    seed.fill(0);

    // Return base64-encoded public key
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        verifying_key.as_bytes(),
    ))
}

fn print_keygen_usage() {
    eprintln!("Usage: nullpad keygen <alias> <secret>");
    eprintln!();
    eprintln!("Generate Ed25519 public key from alias + secret for ADMIN_PUBKEY.");
    eprintln!();
    eprintln!("Example:");
    eprintln!("  nullpad keygen admin mysecretpassword");
    eprintln!();
    eprintln!("Then set in .env:");
    eprintln!("  ADMIN_ALIAS=admin");
    eprintln!("  ADMIN_PUBKEY=<output>");
}

#[tokio::main]
async fn main() {
    // Check for keygen subcommand
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "keygen" {
        if args.len() != 4 {
            print_keygen_usage();
            std::process::exit(1);
        }
        let alias = &args[2];
        let secret = &args[3];

        match keygen(alias, secret) {
            Ok(pubkey) => {
                println!("{}", pubkey);
            }
            Err(e) => {
                eprintln!("Error generating keypair: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }
    // Initialize tracing with env filter support (RUST_LOG)
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Load config from environment
    let config = Config::from_env().expect("Failed to load config");
    tracing::info!("Starting nullpad on {}", config.bind_addr);

    // Connect to Redis
    let redis_client = redis::Client::open(config.redis_url.as_str()).expect("Invalid Redis URL");

    // Verify Redis connection
    let mut con = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Failed to connect to Redis");

    // Upsert admin user (permanent, no TTL)
    storage::user::upsert_admin(&mut con, &config.admin_pubkey, &config.admin_alias)
        .await
        .expect("Failed to upsert admin user");
    tracing::info!("Admin user '{}' configured", config.admin_alias);

    // Build shared state
    let state = AppState {
        redis: redis_client,
        config: Arc::new(config.clone()),
    };

    // Build router:
    // - API routes (with state)
    // - Static file serving (fallback)
    // - Security headers middleware
    // Explicit CORS: deny all cross-origin requests (single-origin deployment).
    // CorsLayer::new() with no allowed origins rejects all CORS preflight requests.
    let cors = CorsLayer::new();

    let app = routes::api_router()
        .fallback_service(ServeDir::new("static"))
        .layer(axum::extract::DefaultBodyLimit::max(
            config.max_upload_bytes,
        ))
        .layer(cors)
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state);

    // Bind to configured address
    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .expect("Failed to bind");
    tracing::info!("Listening on {}", config.bind_addr);

    // Start server (with_connect_info required for ConnectInfo<SocketAddr> extractors)
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Server error");
}
