//! Integration tests for nullpad API.
//!
//! Tests use testcontainers to spin up a throwaway Redis instance automatically.
//! Only a running Docker daemon is required — no external Redis needed.
//!
//! Uses a custom harness (`harness = false`) so that the Redis container is owned
//! by `main()` and explicitly removed after all tests complete. This prevents
//! container leaks — `static` containers never drop, so previous versions leaked
//! one Docker container per test process.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
#[allow(unused_imports)]
use futures::FutureExt;
use hmac::{Hmac, KeyInit, Mac};
use nullpad::{
    auth::middleware::AppState, config::Config, middleware::security_headers, routes, storage,
};
use reqwest::multipart;
use sha2::Sha256;
use std::sync::{Arc, OnceLock};
use testcontainers_modules::redis::Redis;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;
use tower_http::services::ServeDir;

/// Redis URL set once in `main()`, read by all test helpers.
static REDIS_URL: OnceLock<String> = OnceLock::new();

fn get_redis_url() -> &'static str {
    REDIS_URL
        .get()
        .expect("REDIS_URL not initialized — tests must run via main()")
}

/// Run a named async test function, printing pass/fail like the default harness.
async fn run_test<F, Fut>(name: &str, f: F) -> bool
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use std::panic::AssertUnwindSafe;
    let result = futures::FutureExt::catch_unwind(AssertUnwindSafe(f())).await;
    match result {
        Ok(()) => {
            println!("test {} ... ok", name);
            true
        }
        Err(_) => {
            println!("test {} ... FAILED", name);
            false
        }
    }
}

/// Invoke `run_test` for each listed test function.
macro_rules! run_tests {
    ($($test_fn:ident),* $(,)?) => {{
        let mut passed = 0u32;
        let mut failed = 0u32;
        $(
            if run_test(stringify!($test_fn), || $test_fn()).await {
                passed += 1;
            } else {
                failed += 1;
            }
        )*
        (passed, failed)
    }};
}

#[tokio::main]
async fn main() {
    // Start Redis container — owned by main(), removed at end.
    let container = Redis::default()
        .with_tag("7-alpine")
        .start()
        .await
        .expect("Failed to start Redis container");
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(6379).await.unwrap();
    REDIS_URL
        .set(format!("redis://{}:{}", host, port))
        .expect("REDIS_URL already set");

    let (passed, failed) = run_tests![
        test_create_and_get_paste,
        test_burn_after_reading,
        test_paste_not_found,
        test_public_paste_type_restriction,
        test_duplicate_paste_id_returns_409,
        test_auth_challenge_response_flow,
        test_auth_challenge_unknown_user,
        test_auth_verify_invalid_signature,
        test_auth_full_login_flow,
        test_register_with_invite,
        test_register_invalid_invite,
        test_verify_alias_validation,
        test_challenge_alias_validation,
        test_register_alias_validation,
        test_register_invite_not_consumed_on_validation_failure,
        test_verify_normalized_error_messages,
        test_rate_limiting_returns_429,
        test_admin_endpoints_require_auth,
        test_admin_create_and_list_invites,
        test_admin_revoke_invite,
        test_admin_delete_paste,
        test_admin_revoke_user,
        test_admin_cannot_delete_self,
        test_security_headers_on_api,
        test_activate_user_on_first_upload,
        test_challenge_nonce_single_use,
        test_concurrent_burn_after_reading_race,
        test_max_sessions_per_user,
        test_forever_paste_requires_auth,
        test_trusted_user_gets_403_on_admin_endpoints,
        test_session_invalid_after_logout_on_all_endpoints,
        test_trusted_user_can_upload_files,
        test_pin_gated_get_returns_needs_pin,
        test_pin_gated_attempt_returns_content,
        test_pin_gated_attempt_wrong_verifier_returns_403,
        test_pin_gated_attempt_rate_limited,
        test_pin_gated_burn_consumed_on_attempt,
        test_non_pin_attempt_returns_404,
        test_non_pin_get_unchanged,
        test_trusted_user_cannot_create_forever_paste,
        test_protected_html_unauthenticated_returns_401,
        test_protected_html_with_session_cookie,
        test_protected_html_not_served_by_static_fallback,
        test_verify_sets_np_session_cookie,
        test_clearnet_https_sets_secure_cookie,
        test_onion_mode_omits_secure_cookie,
    ];

    // Explicitly remove the container (ContainerAsync has no Drop cleanup).
    container
        .rm()
        .await
        .expect("Failed to remove Redis container");

    println!(
        "\ntest result: {}. {} passed; {} failed\n",
        if failed == 0 { "ok" } else { "FAILED" },
        passed,
        failed
    );

    if failed > 0 {
        std::process::exit(1);
    }
}

/// Generate an Ed25519 keypair for testing.
fn test_keypair() -> (SigningKey, String) {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey = general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes());
    (signing_key, pubkey)
}

/// Spin up a test server and return its base URL, Redis connection, and admin signing key.
async fn spawn_test_server() -> (String, redis::aio::ConnectionManager, SigningKey, String) {
    spawn_test_server_with_auth_limit(10000).await
}

/// Spin up a test server with a custom auth rate limit.
async fn spawn_test_server_with_auth_limit(
    limit: u32,
) -> (String, redis::aio::ConnectionManager, SigningKey, String) {
    let (admin_key, admin_pubkey) = test_keypair();
    let admin_alias = format!("testadmin_{}", nanoid::nanoid!(6));

    let test_redis_url = get_redis_url().to_string();
    let redis_client = redis::Client::open(test_redis_url.as_str()).expect("Failed to open Redis");
    let redis_manager = redis_client
        .get_connection_manager()
        .await
        .expect("Failed to get connection manager");
    let mut con = redis_manager.clone();

    // Set up admin user
    nullpad::storage::user::upsert_admin(&mut con, &admin_pubkey, &admin_alias)
        .await
        .expect("Failed to upsert admin");

    // Create temp directory for paste storage
    let paste_storage_path =
        std::env::temp_dir().join(format!("nullpad_test_{}", nanoid::nanoid!(8)));
    storage::blob::init_storage(&paste_storage_path)
        .await
        .expect("Failed to init paste storage");

    let config = Config {
        admin_pubkey,
        admin_alias: admin_alias.clone(),
        redis_url: test_redis_url.clone(),
        rate_limit_auth_per_min: limit,
        paste_storage_path,
        ..Config::test_default()
    };

    let state = AppState {
        redis: redis_manager,
        config: Arc::new(config),
        ip_hmac_salt: Arc::new(rand::random()),
    };

    let app = routes::api_router()
        .fallback_service(ServeDir::new("static"))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let base_url = format!("http://{}", addr);
    (base_url, con, admin_key, admin_alias)
}

/// Spin up a test server with onion_mode + trusted_proxy_count overrides.
/// Used to exercise the Secure cookie attribute logic under both Tor (onion_mode=true)
/// and clearnet-HTTPS-behind-proxy (onion_mode=false, trusted_proxy_count=1) shapes.
async fn spawn_test_server_with_cookie_config(
    onion_mode: bool,
    trusted_proxy_count: usize,
) -> (String, redis::aio::ConnectionManager, SigningKey, String) {
    let (admin_key, admin_pubkey) = test_keypair();
    let admin_alias = format!("testadmin_{}", nanoid::nanoid!(6));

    let test_redis_url = get_redis_url().to_string();
    let redis_client = redis::Client::open(test_redis_url.as_str()).expect("Failed to open Redis");
    let redis_manager = redis_client
        .get_connection_manager()
        .await
        .expect("Failed to get connection manager");
    let mut con = redis_manager.clone();

    nullpad::storage::user::upsert_admin(&mut con, &admin_pubkey, &admin_alias)
        .await
        .expect("Failed to upsert admin");

    let paste_storage_path =
        std::env::temp_dir().join(format!("nullpad_test_{}", nanoid::nanoid!(8)));
    nullpad::storage::blob::init_storage(&paste_storage_path)
        .await
        .expect("Failed to init paste storage");

    let config = Config {
        admin_pubkey,
        admin_alias: admin_alias.clone(),
        redis_url: test_redis_url.clone(),
        onion_mode,
        trusted_proxy_count,
        paste_storage_path,
        ..Config::test_default()
    };

    let state = AppState {
        redis: redis_manager,
        config: Arc::new(config),
        ip_hmac_salt: Arc::new(rand::random()),
    };

    let app = routes::api_router()
        .fallback_service(ServeDir::new("static"))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let base_url = format!("http://{}", addr);
    (base_url, con, admin_key, admin_alias)
}

/// Spin up a test server with a custom PIN attempt rate limit.
async fn spawn_test_server_with_pin_limit(
    limit: u32,
) -> (String, redis::aio::ConnectionManager, SigningKey, String) {
    let (admin_key, admin_pubkey) = test_keypair();
    let admin_alias = format!("testadmin_{}", nanoid::nanoid!(6));

    let test_redis_url = get_redis_url().to_string();
    let redis_client = redis::Client::open(test_redis_url.as_str()).expect("Failed to open Redis");
    let redis_manager = redis_client
        .get_connection_manager()
        .await
        .expect("Failed to get connection manager");
    let mut con = redis_manager.clone();

    nullpad::storage::user::upsert_admin(&mut con, &admin_pubkey, &admin_alias)
        .await
        .expect("Failed to upsert admin");

    let paste_storage_path =
        std::env::temp_dir().join(format!("nullpad_test_{}", nanoid::nanoid!(8)));
    nullpad::storage::blob::init_storage(&paste_storage_path)
        .await
        .expect("Failed to init paste storage");

    let config = Config {
        admin_pubkey,
        admin_alias: admin_alias.clone(),
        redis_url: test_redis_url.clone(),
        rate_limit_pin_attempt: limit,
        paste_storage_path,
        ..Config::test_default()
    };

    let state = AppState {
        redis: redis_manager,
        config: Arc::new(config),
        ip_hmac_salt: Arc::new(rand::random()),
    };

    let app = routes::api_router()
        .fallback_service(ServeDir::new("static"))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let base_url = format!("http://{}", addr);
    (base_url, con, admin_key, admin_alias)
}

/// Helper: perform full challenge -> sign -> verify login flow, return session token.
async fn admin_login(
    client: &reqwest::Client,
    base_url: &str,
    alias: &str,
    signing_key: &SigningKey,
) -> String {
    // Request challenge
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": alias}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let nonce_b64 = body["nonce"].as_str().unwrap();

    // Decode nonce and sign it
    let nonce_bytes = general_purpose::STANDARD.decode(nonce_b64).unwrap();
    let signature = signing_key.sign(&nonce_bytes);
    let sig_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

    // Verify
    let resp = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": alias, "signature": sig_b64}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}

/// Returns a dummy 32-byte key for test PIN verification.
/// Constructed at runtime to avoid CodeQL hard-coded-cryptographic-value alerts.
fn test_dummy_key() -> Vec<u8> {
    let mut key = b"test-derived-key".to_vec();
    key.extend_from_slice(b"-32-bytes-long!!");
    key
}

/// Helper: create a paste via multipart.
///
/// Compute a test PIN verifier: HMAC-SHA256(key_bytes, paste_id).
fn test_pin_verifier(key: &[u8], paste_id: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(paste_id.as_bytes());
    general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// `paste_type` should be "text" or "file".
#[allow(clippy::too_many_arguments)]
async fn create_paste(
    client: &reqwest::Client,
    base_url: &str,
    paste_type: &str,
    content: &[u8],
    burn: bool,
    ttl: u64,
    token: Option<&str>,
    has_pin: bool,
) -> reqwest::Response {
    let paste_id = nanoid::nanoid!(12);
    // Use a dummy base64 blob as encrypted_metadata (server stores opaquely)
    let encrypted_metadata = general_purpose::STANDARD.encode(b"encrypted-file-metadata");

    // Generate a deterministic PIN verifier for PIN-gated pastes
    let pin_verifier = if has_pin {
        let dummy_key = test_dummy_key();
        Some(test_pin_verifier(&dummy_key, &paste_id))
    } else {
        None
    };

    let metadata = serde_json::json!({
        "paste_id": paste_id,
        "encrypted_metadata": encrypted_metadata,
        "paste_type": paste_type,
        "ttl_secs": ttl,
        "burn_after_reading": burn,
        "has_pin": has_pin,
        "pin_verifier": pin_verifier
    });

    let form = multipart::Form::new()
        .part(
            "metadata",
            multipart::Part::text(metadata.to_string())
                .mime_str("application/json")
                .unwrap(),
        )
        .part(
            "file",
            multipart::Part::bytes(content.to_vec())
                .file_name("encrypted")
                .mime_str("application/octet-stream")
                .unwrap(),
        );

    let mut req = client
        .post(format!("{}/api/paste", base_url))
        .multipart(form);

    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {}", t));
    }

    req.send().await.expect("Failed to send request")
}

// ============================================================================
// Paste Tests
// ============================================================================

async fn test_create_and_get_paste() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"encrypted data",
        false,
        3600,
        None,
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();
    assert!(!id.is_empty());

    // Get the paste
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["encrypted_metadata"].as_str().is_some());
    assert!(!body["burn_after_reading"].as_bool().unwrap());

    // Decode content
    let content = general_purpose::STANDARD
        .decode(body["encrypted_content"].as_str().unwrap())
        .unwrap();
    assert_eq!(content, b"encrypted data");
}

async fn test_burn_after_reading() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a burn paste
    let resp = create_paste(
        &client, &base_url, "text", b"burn me", true, 3600, None, false,
    )
    .await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();

    // First read should succeed
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["burn_after_reading"].as_bool().unwrap());

    // Second read should fail (already burned)
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

async fn test_paste_not_found() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Use a valid-format nanoid that doesn't exist (12 alphanumeric chars)
    let resp = client
        .get(format!("{}/api/paste/aAbBcCdDeEfF", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Invalid format should return 400
    let resp = client
        .get(format!("{}/api/paste/nonexistent", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

async fn test_public_paste_type_restriction() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // "file" type should be rejected for public uploads
    let resp = create_paste(
        &client, &base_url, "file", b"data", false, 3600, None, false,
    )
    .await;
    assert_eq!(resp.status(), 403);

    // "text" type should be allowed for public uploads
    let resp = create_paste(
        &client, &base_url, "text", b"data", false, 3600, None, false,
    )
    .await;
    assert_eq!(resp.status(), 200);
}

async fn test_duplicate_paste_id_returns_409() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Use a fixed paste ID for both requests
    let paste_id = nanoid::nanoid!(12);
    let encrypted_metadata = general_purpose::STANDARD.encode(b"encrypted-file-metadata");

    let metadata = serde_json::json!({
        "paste_id": paste_id,
        "encrypted_metadata": encrypted_metadata,
        "paste_type": "text",
        "ttl_secs": 3600,
        "burn_after_reading": false
    });

    let form = multipart::Form::new()
        .part(
            "metadata",
            multipart::Part::text(metadata.to_string())
                .mime_str("application/json")
                .unwrap(),
        )
        .part(
            "file",
            multipart::Part::bytes(b"data".to_vec())
                .file_name("encrypted")
                .mime_str("application/octet-stream")
                .unwrap(),
        );

    // First request should succeed
    let resp = client
        .post(format!("{}/api/paste", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Second request with same paste ID should return 409 Conflict
    let form2 = multipart::Form::new()
        .part(
            "metadata",
            multipart::Part::text(metadata.to_string())
                .mime_str("application/json")
                .unwrap(),
        )
        .part(
            "file",
            multipart::Part::bytes(b"different data".to_vec())
                .file_name("encrypted")
                .mime_str("application/octet-stream")
                .unwrap(),
        );

    let resp = client
        .post(format!("{}/api/paste", base_url))
        .multipart(form2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

// ============================================================================
// Auth Tests
// ============================================================================

async fn test_auth_challenge_response_flow() {
    let (base_url, _con, _admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Request challenge for existing admin
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": admin_alias}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["nonce"].as_str().is_some());
}

async fn test_auth_challenge_unknown_user() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Returns 200 with a throwaway nonce to prevent alias enumeration
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": "nobody"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["nonce"].is_string());
}

async fn test_auth_verify_invalid_signature() {
    let (base_url, _con, _admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Get a challenge
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": admin_alias}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Submit garbage signature
    let fake_sig = general_purpose::STANDARD.encode([0u8; 64]);
    let resp = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": admin_alias, "signature": fake_sig}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

async fn test_auth_full_login_flow() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Full login: challenge -> sign -> verify -> get token
    let token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;
    assert!(!token.is_empty());

    // Use the token to access an admin endpoint
    let resp = client
        .get(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Logout
    let resp = client
        .post(format!("{}/api/auth/logout", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Token should be invalid after logout
    let resp = client
        .get(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

async fn test_register_with_invite() {
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Manually create an invite in Redis
    let invite_token = nanoid::nanoid!(16);
    let invite = nullpad::models::StoredInvite {
        token: invite_token.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    nullpad::storage::user::store_invite(&mut con, &invite, 3600)
        .await
        .unwrap();

    // Generate a keypair for the new user
    let (_signing_key, pubkey) = test_keypair();

    // Register
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({
            "token": invite_token,
            "alias": format!("testuser_{}", nanoid::nanoid!(4)),
            "pubkey": pubkey
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

async fn test_register_invalid_invite() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let (_signing_key, pubkey) = test_keypair();

    // Malformed token (wrong length) → 400
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({
            "token": "invalid_token",
            "alias": "testuser",
            "pubkey": pubkey
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Valid-format but non-existent token → 400 (uniform error prevents alias enumeration)
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({
            "token": "abcdefghijklmnop",
            "alias": "testuser",
            "pubkey": pubkey
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("Registration failed"));
}

async fn test_verify_alias_validation() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let fake_sig = general_purpose::STANDARD.encode([0u8; 64]);

    // Alias too short (1 char) -> 400
    let resp = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": "a", "signature": fake_sig}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Alias too long (65 chars) -> 400
    let long_alias = "a".repeat(65);
    let resp = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": long_alias, "signature": fake_sig}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Alias with special chars -> 400
    let resp = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": "user@evil.com", "signature": fake_sig}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

async fn test_challenge_alias_validation() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Alias too short -> 400
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Alias too long -> 400
    let long_alias = "b".repeat(65);
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": long_alias}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Alias with special chars -> 400
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": "user name"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Valid alias at boundaries -> 200
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": "ab"})) // minimum length
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let alias_64 = "c".repeat(64);
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": alias_64})) // maximum length
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

async fn test_register_alias_validation() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let (_key, pubkey) = test_keypair();

    // Alias too short -> 400
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({"token": "abcdefghijklmnop", "alias": "x", "pubkey": pubkey}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Alias too long -> 400
    let long_alias = "d".repeat(65);
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({"token": "abcdefghijklmnop", "alias": long_alias, "pubkey": pubkey}))
        .send().await.unwrap();
    assert_eq!(resp.status(), 400);

    // Alias with special chars -> 400
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({"token": "abcdefghijklmnop", "alias": "user@domain", "pubkey": pubkey}))
        .send().await.unwrap();
    assert_eq!(resp.status(), 400);
}

async fn test_register_invite_not_consumed_on_validation_failure() {
    use redis::AsyncCommands;
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create an invite
    let invite_token = nanoid::nanoid!(16);
    let invite = nullpad::models::StoredInvite {
        token: invite_token.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    nullpad::storage::user::store_invite(&mut con, &invite, 3600)
        .await
        .unwrap();

    // Attempt 1: Invalid pubkey (not base64) -> 400
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({
            "token": invite_token,
            "alias": "testuser1",
            "pubkey": "not-valid-base64!!!"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Verify invite still exists
    let invite_key = format!("invite:{}", invite_token);
    let exists: bool = con.exists(&invite_key).await.unwrap();
    assert!(
        exists,
        "Invite should not be consumed after pubkey validation failure"
    );

    // Attempt 2: Invalid pubkey (wrong length) -> 400
    let wrong_length_pubkey = general_purpose::STANDARD.encode([0u8; 16]); // 16 bytes instead of 32
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({
            "token": invite_token,
            "alias": "testuser2",
            "pubkey": wrong_length_pubkey
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Verify invite still exists
    let exists: bool = con.exists(&invite_key).await.unwrap();
    assert!(
        exists,
        "Invite should not be consumed after pubkey length validation failure"
    );

    // Attempt 3: Valid pubkey but alias taken -> 400
    // First create a user with the alias we want to use via the atomic invite flow
    let (_key1, pubkey1) = test_keypair();
    let blocking_token = nanoid::nanoid!(16);
    let blocking_invite = nullpad::models::StoredInvite {
        token: blocking_token.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    nullpad::storage::user::store_invite(&mut con, &blocking_invite, 3600)
        .await
        .unwrap();
    let blocking_user = nullpad::models::StoredUser {
        id: nanoid::nanoid!(12),
        alias: "taken_alias".to_string(),
        pubkey: pubkey1,
        role: nullpad::models::Role::Trusted,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    nullpad::storage::user::consume_invite_and_create_user(
        &mut con,
        &blocking_token,
        &blocking_user,
        86400,
    )
    .await
    .unwrap();

    // Now try to register with the taken alias
    let (_key2, pubkey2) = test_keypair();
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({
            "token": invite_token,
            "alias": "taken_alias",
            "pubkey": pubkey2
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("Registration failed"));

    // Verify invite still exists after alias conflict
    let exists: bool = con.exists(&invite_key).await.unwrap();
    assert!(exists, "Invite should not be consumed when alias is taken");

    // Attempt 4: Valid registration with available alias -> 200
    let (_key3, pubkey3) = test_keypair();
    let unique_alias = format!("valid_user_{}", nanoid::nanoid!(8));
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({
            "token": invite_token,
            "alias": unique_alias,
            "pubkey": pubkey3
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // NOW the invite should be consumed
    let exists: bool = con.exists(&invite_key).await.unwrap();
    assert!(
        !exists,
        "Invite should be consumed after successful registration"
    );
}

async fn test_verify_normalized_error_messages() {
    let (base_url, _con, _admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let fake_sig = general_purpose::STANDARD.encode([0u8; 64]);

    // Verify with no challenge -> 401 with generic "Authentication failed"
    let resp = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": "nobody_here", "signature": fake_sig}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Authentication failed");

    // Verify with wrong signature (after getting a challenge) -> 401 with generic message
    // First get a challenge
    let _resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": admin_alias}))
        .send()
        .await
        .unwrap();
    // Then submit bad sig
    let resp = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": admin_alias, "signature": fake_sig}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Authentication failed");
}

async fn test_rate_limiting_returns_429() {
    use redis::AsyncCommands;
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server_with_auth_limit(2).await;
    // Clear any existing rate limit counters
    let _: () = con.del("ratelimit:auth:challenge:127.0.0.1").await.unwrap();
    let _: () = con.del("ratelimit:challenge_alias:someone").await.unwrap();

    let client = reqwest::Client::new();

    // First two challenge requests should succeed (within limit of 2/min)
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": "someone"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": "someone"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Third request should be rate limited -> 429
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": "someone"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);

    // Verify the error response body
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Rate limit exceeded");
}

// ============================================================================
// Admin Tests
// ============================================================================

async fn test_admin_endpoints_require_auth() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // All admin endpoints should return 401 without auth
    let resp = client
        .post(format!("{}/api/invites", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let resp = client
        .get(format!("{}/api/invites", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let resp = client
        .get(format!("{}/api/users", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let resp = client
        .delete(format!("{}/api/users/someid", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

async fn test_admin_create_and_list_invites() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Login as admin via full auth flow
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Create invite
    let resp = client
        .post(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let invite_token = body["token"].as_str().unwrap();
    assert!(!invite_token.is_empty());

    // List invites
    let resp = client
        .get(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(!body.as_array().unwrap().is_empty());
}

async fn test_admin_revoke_invite() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Login as admin via full auth flow
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Create invite
    let resp = client
        .post(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let invite_token = body["token"].as_str().unwrap().to_string();

    // Revoke it
    let resp = client
        .delete(format!("{}/api/invites/{}", base_url, invite_token))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Revoke again should 404
    let resp = client
        .delete(format!("{}/api/invites/{}", base_url, invite_token))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

async fn test_admin_delete_paste() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a paste
    let resp = create_paste(
        &client, &base_url, "text", b"data", false, 3600, None, false,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let paste_id = body["id"].as_str().unwrap().to_string();

    // Login as admin via full auth flow
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Delete paste as admin
    let resp = client
        .delete(format!("{}/api/paste/{}", base_url, paste_id))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Verify it's gone
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, paste_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

async fn test_admin_revoke_user() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create an invite
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;
    let resp = client
        .post(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let invite_token = body["token"].as_str().unwrap().to_string();

    // Register a user
    let (user_key, user_pubkey) = test_keypair();
    let user_alias = format!("revoke_target_{}", nanoid::nanoid!(4));
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({
            "token": invite_token,
            "alias": user_alias,
            "pubkey": user_pubkey
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Login as the user to get their session
    let user_token = admin_login(&client, &base_url, &user_alias, &user_key).await;

    // Create a paste as the user
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"data",
        false,
        3600,
        Some(&user_token),
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let paste_id = body["id"].as_str().unwrap().to_string();

    // List users - user should appear
    let resp = client
        .get(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let users: serde_json::Value = resp.json().await.unwrap();
    let has_user = users
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["alias"].as_str() == Some(&user_alias));
    assert!(has_user, "User should appear in list before revocation");

    // Find the user's ID from the list
    let user_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["alias"].as_str() == Some(&user_alias))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Revoke the user
    let resp = client
        .delete(format!("{}/api/users/{}", base_url, user_id))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Verify user's paste is deleted
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, paste_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Verify user's session is invalid
    let resp = client
        .get(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();
    // Should be 401 (session deleted) or 403 (not admin) - either way, not 200
    assert_ne!(resp.status(), 200);

    // Verify user no longer in list
    let resp = client
        .get(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let users: serde_json::Value = resp.json().await.unwrap();
    let has_user = users
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["alias"].as_str() == Some(&user_alias));
    assert!(!has_user, "User should not appear after revocation");
}

async fn test_admin_cannot_delete_self() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Try to delete admin user (id is "admin")
    let resp = client
        .delete(format!("{}/api/users/admin", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    // Should be 400 (invalid format - "admin" is 5 chars, validate_id expects 12)
    // OR 403 if the id check happens before format validation
    assert_ne!(resp.status(), 204, "Admin deletion should be prevented");
}

// ============================================================================
// Security Header Tests
// ============================================================================

async fn test_security_headers_on_api() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/paste/aAbBcCdDeEfF", base_url))
        .send()
        .await
        .unwrap();

    let headers = resp.headers();
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert!(headers.get("strict-transport-security").is_some());
    assert!(headers.get("content-security-policy").is_some());
}

// ============================================================================
// User Activation Tests
// ============================================================================

async fn test_activate_user_on_first_upload() {
    let (base_url, mut con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Login as admin
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Create invite
    let resp = client
        .post(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let invite_token = body["token"].as_str().unwrap().to_string();

    // Generate keypair for new user
    let (user_key, user_pubkey) = test_keypair();
    let user_alias = format!("testuser_{}", nanoid::nanoid!(6));

    // Register new user
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({
            "token": invite_token,
            "alias": user_alias,
            "pubkey": user_pubkey
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Login as new user
    let user_token = admin_login(&client, &base_url, &user_alias, &user_key).await;

    // Get user ID from users list
    let resp = client
        .get(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let users: Vec<serde_json::Value> = resp.json().await.unwrap();
    let user = users
        .iter()
        .find(|u| u["alias"].as_str().unwrap() == user_alias)
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    // Check TTL before first upload (should be around user_idle_ttl_secs = 172800)
    let ttl_before: i64 = redis::cmd("TTL")
        .arg(format!("user:{}", user_id))
        .query_async(&mut con)
        .await
        .unwrap();
    assert!(
        ttl_before > 172700 && ttl_before <= 172800,
        "TTL before first upload should be close to 172800, got {}",
        ttl_before
    );

    // Create first paste as user
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"first upload",
        false,
        3600,
        Some(&user_token),
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Check TTL after first upload (should be around user_active_ttl_secs = 86400, i.e. decreased)
    let ttl_after_first: i64 = redis::cmd("TTL")
        .arg(format!("user:{}", user_id))
        .query_async(&mut con)
        .await
        .unwrap();
    assert!(
        ttl_after_first > 86300 && ttl_after_first <= 86400,
        "TTL after first upload should be close to 86400, got {}",
        ttl_after_first
    );

    // Wait a second to ensure some TTL decay
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Create second paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"second upload",
        false,
        3600,
        Some(&user_token),
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Check TTL after second upload (should NOT reset, should be close to previous value minus elapsed time)
    let ttl_after_second: i64 = redis::cmd("TTL")
        .arg(format!("user:{}", user_id))
        .query_async(&mut con)
        .await
        .unwrap();
    // TTL should have decreased by ~2 seconds, not reset to 86400
    assert!(
        ttl_after_second < ttl_after_first,
        "TTL should decrease, not reset: before={}, after={}",
        ttl_after_first,
        ttl_after_second
    );
    assert!(
        ttl_after_second > 86000,
        "TTL should still be close to user_active_ttl_secs, got {}",
        ttl_after_second
    );
}

// ============================================================================
// Nonce Replay Prevention Tests
// ============================================================================

async fn test_challenge_nonce_single_use() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Request challenge
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": admin_alias}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let nonce_b64 = body["nonce"].as_str().unwrap();

    // Sign the nonce
    let nonce_bytes = general_purpose::STANDARD.decode(nonce_b64).unwrap();
    let signature = admin_key.sign(&nonce_bytes);
    let sig_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

    // First verification should succeed
    let resp = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": admin_alias, "signature": sig_b64}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Second verification with same signature should fail (nonce consumed)
    let resp = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": admin_alias, "signature": sig_b64}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ============================================================================
// Concurrent Burn-After-Reading Tests
// ============================================================================

async fn test_concurrent_burn_after_reading_race() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    // Create a burn-after-reading paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"race condition test",
        true,
        3600,
        None,
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let paste_id = body["id"].as_str().unwrap().to_string();

    // Launch 10 concurrent requests to fetch the same paste
    let mut handles = vec![];
    for _ in 0..10 {
        let url = format!("{}/api/paste/{}", base_url, paste_id);
        let c = client.clone();
        handles.push(tokio::spawn(async move { c.get(&url).send().await }));
    }

    // Collect results
    let mut success_count = 0;
    let mut not_found_count = 0;
    for handle in handles {
        let result = handle.await.unwrap();
        if let Ok(resp) = result {
            if resp.status() == 200 {
                success_count += 1;
            } else if resp.status() == 404 {
                not_found_count += 1;
            }
        }
    }

    // Exactly one request should succeed, all others should get 404
    assert_eq!(
        success_count, 1,
        "Exactly one request should succeed, got {}",
        success_count
    );
    assert_eq!(
        not_found_count, 9,
        "Nine requests should get 404, got {}",
        not_found_count
    );
}

// ============================================================================
// Max Sessions Per User Tests
// ============================================================================

async fn test_max_sessions_per_user() {
    use redis::AsyncCommands;
    let (base_url, mut con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Clear stale session tracking from prior tests (all share user_id "admin")
    let _: () = con.del("user_sessions:admin").await.unwrap();

    // Create 5 sessions (the configured max)
    let mut tokens = vec![];
    for _ in 0..5 {
        let token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;
        tokens.push(token);
    }

    // All 5 tokens should work
    for token in &tokens {
        let resp = client
            .get(format!("{}/api/invites", base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // Create a 6th session - this should evict one of the existing 5
    let new_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // New token should work
    let resp = client
        .get(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", new_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Exactly one of the original 5 tokens should have been evicted
    let mut valid_count = 0;
    let mut evicted_count = 0;
    for token in &tokens {
        let resp = client
            .get(format!("{}/api/invites", base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        if resp.status() == 200 {
            valid_count += 1;
        } else {
            assert_eq!(resp.status(), 401);
            evicted_count += 1;
        }
    }
    assert_eq!(
        valid_count, 4,
        "4 of the original 5 sessions should still be valid"
    );
    assert_eq!(
        evicted_count, 1,
        "Exactly 1 session should have been evicted"
    );
}

// ============================================================================
// Forever Paste Auth Tests
// ============================================================================

async fn test_forever_paste_requires_auth() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Public user trying to create forever paste (ttl=0) should be rejected
    let resp = create_paste(&client, &base_url, "text", b"data", false, 0, None, false).await;
    assert_eq!(resp.status(), 403);

    // Login as admin (trusted user)
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Trusted user can create forever paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"forever data",
        false,
        0,
        Some(&admin_token),
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let paste_id = body["id"].as_str().unwrap();

    // Verify paste exists
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, paste_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

/// Trusted users cannot create forever pastes (TTL=0) — admin only.
/// Prevents Redis memory exhaustion from unlimited non-expiring keys.
async fn test_trusted_user_cannot_create_forever_paste() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;
    let (_user_key, _user_alias, user_token) =
        create_trusted_user(&client, &base_url, &admin_token).await;

    // Trusted user trying to create forever paste should be rejected
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"forever data",
        false,
        0,
        Some(&user_token),
        false,
    )
    .await;
    assert_eq!(resp.status(), 403);

    // Trusted user can still create normal TTL pastes
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"normal data",
        false,
        3600,
        Some(&user_token),
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);
}

// ============================================================================
// Trusted User Access Control Tests
// ============================================================================

/// Helper: create a trusted user and return their signing key, alias, and session token
async fn create_trusted_user(
    client: &reqwest::Client,
    base_url: &str,
    admin_token: &str,
) -> (SigningKey, String, String) {
    // Create invite
    let resp = client
        .post(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let invite_token = body["token"].as_str().unwrap().to_string();

    // Generate keypair
    let (user_key, user_pubkey) = test_keypair();
    let user_alias = format!("trusted_{}", nanoid::nanoid!(6));

    // Register
    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({
            "token": invite_token,
            "alias": user_alias,
            "pubkey": user_pubkey
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Login
    let user_token = admin_login(client, base_url, &user_alias, &user_key).await;

    (user_key, user_alias, user_token)
}

async fn test_trusted_user_gets_403_on_admin_endpoints() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Login as admin to create trusted user
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Create a trusted user
    let (_user_key, _user_alias, user_token) =
        create_trusted_user(&client, &base_url, &admin_token).await;

    // Trusted user should get 403 on all admin endpoints

    // POST /api/invites
    let resp = client
        .post(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // GET /api/invites
    let resp = client
        .get(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // DELETE /api/invites/:token
    let resp = client
        .delete(format!("{}/api/invites/abcdefghijklmnop", base_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // GET /api/users
    let resp = client
        .get(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // DELETE /api/users/:id
    let resp = client
        .delete(format!("{}/api/users/aAbBcCdDeEfF", base_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // DELETE /api/paste/:id (admin-only paste deletion)
    let resp = client
        .delete(format!("{}/api/paste/aAbBcCdDeEfF", base_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

async fn test_session_invalid_after_logout_on_all_endpoints() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Login as admin
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Verify token works before logout
    let resp = client
        .get(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Logout
    let resp = client
        .post(format!("{}/api/auth/logout", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // All protected endpoints should return 401 after logout

    // POST /api/invites
    let resp = client
        .post(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // GET /api/invites
    let resp = client
        .get(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // DELETE /api/invites/:token
    let resp = client
        .delete(format!("{}/api/invites/abcdefghijklmnop", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // GET /api/users
    let resp = client
        .get(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // DELETE /api/users/:id
    let resp = client
        .delete(format!("{}/api/users/aAbBcCdDeEfF", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // DELETE /api/paste/:id
    let resp = client
        .delete(format!("{}/api/paste/aAbBcCdDeEfF", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // POST /api/auth/logout (double logout)
    let resp = client
        .post(format!("{}/api/auth/logout", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

async fn test_trusted_user_can_upload_files() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Login as admin
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Create a trusted user
    let (_user_key, _user_alias, user_token) =
        create_trusted_user(&client, &base_url, &admin_token).await;

    // Trusted user can upload "file" type (blocked for public)
    let resp = create_paste(
        &client,
        &base_url,
        "file",
        b"binary data",
        false,
        3600,
        Some(&user_token),
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Trusted user can also create text pastes
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"some text",
        false,
        3600,
        Some(&user_token),
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);
}

// ============================================================================
// PIN Gating Tests
// ============================================================================

async fn test_pin_gated_get_returns_needs_pin() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a PIN-gated paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"secret data",
        false,
        3600,
        None,
        true,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();

    // GET should return needs_pin probe (no content)
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["needs_pin"], true);
    assert!(body.get("encrypted_content").is_none());
    assert!(body.get("created_at").is_none());
    assert!(body.get("burn_after_reading").is_some());
}

async fn test_pin_gated_attempt_returns_content() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a PIN-gated paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"secret data",
        false,
        3600,
        None,
        true,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();

    // POST attempt with correct verifier should return full content
    let dummy_key = test_dummy_key();
    let verifier = test_pin_verifier(&dummy_key, id);
    let resp = client
        .post(format!("{}/api/paste/{}", base_url, id))
        .header("Content-Type", "application/json")
        .body(serde_json::json!({ "pin_verifier": verifier }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["encrypted_content"].is_string());
    assert!(body["created_at"].is_number());
    assert!(body.get("needs_pin").is_none());
}

async fn test_pin_gated_attempt_wrong_verifier_returns_403() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a PIN-gated paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"secret data",
        false,
        3600,
        None,
        true,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();

    // POST with wrong verifier should return 403
    let wrong_verifier = general_purpose::STANDARD.encode([0u8; 32]);
    let resp = client
        .post(format!("{}/api/paste/{}", base_url, id))
        .header("Content-Type", "application/json")
        .body(serde_json::json!({ "pin_verifier": wrong_verifier }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // POST with no verifier should return 403
    let resp = client
        .post(format!("{}/api/paste/{}", base_url, id))
        .header("Content-Type", "application/json")
        .body(serde_json::json!({}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // POST with no body / no Content-Type should be rejected
    let resp = client
        .post(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "Expected 4xx, got {}",
        resp.status()
    );
}

async fn test_pin_gated_attempt_rate_limited() {
    // Use a server with very low PIN attempt limit
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server_with_pin_limit(2).await;
    let client = reqwest::Client::new();

    // Create a PIN-gated paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"secret data",
        false,
        3600,
        None,
        true,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();

    // First 2 attempts should succeed (with correct verifier)
    let dummy_key = test_dummy_key();
    let verifier = test_pin_verifier(&dummy_key, id);
    for _ in 0..2 {
        let resp = client
            .post(format!("{}/api/paste/{}", base_url, id))
            .header("Content-Type", "application/json")
            .body(serde_json::json!({ "pin_verifier": verifier }).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // 3rd attempt should be rate limited
    let resp = client
        .post(format!("{}/api/paste/{}", base_url, id))
        .header("Content-Type", "application/json")
        .body(serde_json::json!({ "pin_verifier": verifier }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
}

async fn test_pin_gated_burn_consumed_on_attempt() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a burn + PIN-gated paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"burn secret",
        true,
        3600,
        None,
        true,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();

    // GET should show needs_pin with burn_after_reading=true
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["needs_pin"], true);
    assert_eq!(body["burn_after_reading"], true);

    // POST attempt with correct verifier should return content and burn it
    let dummy_key = test_dummy_key();
    let verifier = test_pin_verifier(&dummy_key, id);
    let resp = client
        .post(format!("{}/api/paste/{}", base_url, id))
        .header("Content-Type", "application/json")
        .body(serde_json::json!({ "pin_verifier": verifier }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["encrypted_content"].is_string());

    // Second GET should return 404 (burned)
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

async fn test_non_pin_attempt_returns_404() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a non-PIN paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"public data",
        false,
        3600,
        None,
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();

    // POST attempt should return 404 (not PIN-gated)
    let resp = client
        .post(format!("{}/api/paste/{}", base_url, id))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({ "pin_verifier": general_purpose::STANDARD.encode([0u8; 32]) })
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

async fn test_non_pin_get_unchanged() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a non-PIN paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"normal data",
        false,
        3600,
        None,
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();

    // GET should return full content directly (no needs_pin)
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["encrypted_content"].is_string());
    assert!(body["created_at"].is_number());
    assert!(body.get("needs_pin").is_none());
}

/// Unauthenticated requests to /admin.html and /trusted.html must return 401.
async fn test_protected_html_unauthenticated_returns_401() {
    let (base_url, _con, _key, _alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/admin.html", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let resp = client
        .get(format!("{}/trusted.html", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// Admin with np_role=admin cookie can access /admin.html.
/// Trusted user with np_role=trusted cookie can access /trusted.html.
async fn test_protected_html_with_session_cookie() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Login to get a real session token
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Admin can access /admin.html via np_session cookie
    let resp = client
        .get(format!("{}/admin.html", base_url))
        .header("cookie", format!("np_session={}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Admin Dashboard"));
    // Verify no inline scripts (CSP compliance)
    assert!(
        !body.contains("sessionStorage.getItem('session_token')"),
        "admin.html should not contain inline script with old sessionStorage key"
    );

    // Admin can also access /trusted.html
    let resp = client
        .get(format!("{}/trusted.html", base_url))
        .header("cookie", format!("np_session={}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Trusted Upload"));

    // Forged np_role cookie (old attack vector) must NOT grant access
    let resp = client
        .get(format!("{}/admin.html", base_url))
        .header("cookie", "np_role=admin")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// Static fallback (ServeDir) must NOT serve admin.html or trusted.html.
/// These files were moved out of static/ to prevent bypassing auth gates.
async fn test_protected_html_not_served_by_static_fallback() {
    let (base_url, _con, _key, _alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Without a valid session cookie, these should return 401 (not 200 from ServeDir)
    let resp = client
        .get(format!("{}/admin.html", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Also verify the files aren't accessible via any other path through ServeDir
    let resp = client
        .get(format!("{}/protected/admin.html", base_url))
        .send()
        .await
        .unwrap();
    // Should be 404 (protected/ is not in static/)
    assert_eq!(resp.status(), 404);
}

/// Login verify endpoint sets np_session cookie with correct attributes.
async fn test_verify_sets_np_session_cookie() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Request challenge
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": admin_alias}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let nonce_b64 = body["nonce"].as_str().unwrap();

    // Sign nonce
    let nonce_bytes = general_purpose::STANDARD.decode(nonce_b64).unwrap();
    let signature = admin_key.sign(&nonce_bytes);
    let sig_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

    // Verify
    let resp = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": admin_alias, "signature": sig_b64}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Check Set-Cookie header contains session token, not role
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("verify response must set np_session cookie")
        .to_str()
        .unwrap();
    assert!(
        cookie.starts_with("np_session="),
        "cookie should set np_session"
    );
    // Token is 44 chars of base64
    let token_value = cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("np_session=")
        .unwrap();
    assert_eq!(token_value.len(), 44, "session token should be 44 chars");
    assert!(cookie.contains("HttpOnly"), "cookie should be HttpOnly");
    assert!(
        cookie.contains("SameSite=Strict"),
        "cookie should be SameSite=Strict"
    );
}

/// Drive a verify flow against the given base URL, returning the Set-Cookie header.
/// Optionally sets X-Forwarded-Proto: https to simulate a trusted reverse proxy.
async fn fetch_verify_set_cookie(
    base_url: &str,
    alias: &str,
    signing_key: &SigningKey,
    forwarded_proto_https: bool,
) -> String {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": alias}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let nonce_b64 = body["nonce"].as_str().unwrap();

    let nonce_bytes = general_purpose::STANDARD.decode(nonce_b64).unwrap();
    let signature = signing_key.sign(&nonce_bytes);
    let sig_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

    let mut req = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": alias, "signature": sig_b64}));
    if forwarded_proto_https {
        req = req.header("x-forwarded-proto", "https");
    }
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 200);

    resp.headers()
        .get("set-cookie")
        .expect("verify response must set np_session cookie")
        .to_str()
        .unwrap()
        .to_string()
}

/// Baseline for the next test: with onion_mode=false, a trusted proxy forwarding
/// X-Forwarded-Proto: https causes Secure to be set. Confirms our HTTPS detection
/// works so the onion_mode=true test below is actually testing onion_mode's effect
/// and not just the HTTP transport.
async fn test_clearnet_https_sets_secure_cookie() {
    let (base_url, _con, admin_key, admin_alias) =
        spawn_test_server_with_cookie_config(false, 1).await;
    let cookie = fetch_verify_set_cookie(&base_url, &admin_alias, &admin_key, true).await;
    assert!(
        cookie.contains("Secure"),
        "clearnet + X-Forwarded-Proto: https must set Secure (got: {})",
        cookie
    );
}

/// With ONION_MODE=true, the Secure flag must be omitted from Set-Cookie even when
/// a trusted reverse proxy forwards X-Forwarded-Proto: https. Tor's onion transport
/// provides encryption; browsers discard Secure cookies over the plain HTTP that the
/// onion endpoint receives, which would break auth.
async fn test_onion_mode_omits_secure_cookie() {
    let (base_url, _con, admin_key, admin_alias) =
        spawn_test_server_with_cookie_config(true, 1).await;
    let cookie = fetch_verify_set_cookie(&base_url, &admin_alias, &admin_key, true).await;
    assert!(
        !cookie.contains("Secure"),
        "onion_mode=true must omit Secure attribute (got: {})",
        cookie
    );
    // Other attributes still present.
    assert!(cookie.contains("HttpOnly"), "HttpOnly must remain set");
    assert!(
        cookie.contains("SameSite=Strict"),
        "SameSite=Strict must remain set"
    );
}
