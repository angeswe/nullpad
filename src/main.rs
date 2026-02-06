//! Nullpad application entry point.
//!
//! Bootstraps the server:
//! 1. Load configuration from environment
//! 2. Connect to Redis
//! 3. Upsert admin user
//! 4. Build router with API routes + static file serving
//! 5. Apply security headers middleware
//! 6. Start Axum server

use nullpad::{
    auth::middleware::AppState, config::Config, middleware::security_headers, routes, storage,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
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
    let app = routes::api_router()
        .fallback_service(ServeDir::new("static"))
        .layer(axum::extract::DefaultBodyLimit::max(
            config.max_upload_bytes,
        ))
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
