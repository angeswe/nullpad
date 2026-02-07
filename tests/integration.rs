//! Integration tests for nullpad API.
//!
//! Tests use testcontainers to spin up a throwaway Redis instance automatically.
//! Only a running Docker daemon is required — no external Redis needed.
//!
//! Tests run sequentially (--test-threads=1) because they share a Redis instance.
//! Each test flushes its database before starting.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use nullpad::{auth::middleware::AppState, config::Config, middleware::security_headers, routes};
use reqwest::multipart;
use std::sync::Arc;
use testcontainers_modules::redis::Redis;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ContainerAsync;
use tokio::sync::OnceCell;
use tower_http::services::ServeDir;

struct TestRedis {
    _container: ContainerAsync<Redis>,
    url: String,
}

static TEST_REDIS: OnceCell<TestRedis> = OnceCell::const_new();

async fn get_redis_url() -> &'static str {
    let test_redis = TEST_REDIS
        .get_or_init(|| async {
            let container = Redis::default().start().await.unwrap();
            let host = container.get_host().await.unwrap();
            let port = container.get_host_port_ipv4(6379).await.unwrap();
            let url = format!("redis://{}:{}", host, port);
            TestRedis {
                _container: container,
                url,
            }
        })
        .await;
    &test_redis.url
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
async fn spawn_test_server() -> (
    String,
    redis::aio::MultiplexedConnection,
    SigningKey,
    String,
) {
    spawn_test_server_with_auth_limit(10000).await
}

/// Spin up a test server with a custom auth rate limit.
async fn spawn_test_server_with_auth_limit(
    limit: u32,
) -> (
    String,
    redis::aio::MultiplexedConnection,
    SigningKey,
    String,
) {
    let (admin_key, admin_pubkey) = test_keypair();
    let admin_alias = format!("testadmin_{}", nanoid::nanoid!(6));

    let test_redis_url = get_redis_url().await.to_string();
    let redis_client = redis::Client::open(test_redis_url.as_str()).expect("Failed to open Redis");
    let mut con = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Failed to connect to Redis");

    // Set up admin user
    nullpad::storage::user::upsert_admin(&mut con, &admin_pubkey, &admin_alias)
        .await
        .expect("Failed to upsert admin");

    let config = Config {
        admin_pubkey,
        admin_alias: admin_alias.clone(),
        redis_url: test_redis_url.clone(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        max_upload_bytes: 52_428_800,
        default_ttl_secs: 86400,
        max_ttl_secs: 604800,
        invite_ttl_secs: 43200,
        user_idle_ttl_secs: 172800,
        user_active_ttl_secs: 86400,
        session_ttl_secs: 900,
        challenge_ttl_secs: 30,
        public_allowed_extensions: vec!["md".to_string(), "txt".to_string()],
        rate_limit_paste_per_min: 10000,
        rate_limit_auth_per_min: limit,
        trusted_proxy_count: 0,
        max_sessions_per_user: 5,
    };

    let state = AppState {
        redis: redis_client,
        config: Arc::new(config),
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

/// Helper: create a paste via multipart.
async fn create_paste(
    client: &reqwest::Client,
    base_url: &str,
    filename: &str,
    content: &[u8],
    burn: bool,
    ttl: u64,
    token: Option<&str>,
) -> reqwest::Response {
    let metadata = serde_json::json!({
        "filename": filename,
        "content_type": "application/octet-stream",
        "ttl_secs": ttl,
        "burn_after_reading": burn
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
                .file_name(filename.to_string())
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

#[tokio::test]
async fn test_create_and_get_paste() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a paste
    let resp = create_paste(
        &client,
        &base_url,
        "test.md",
        b"encrypted data",
        false,
        3600,
        None,
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
    assert_eq!(body["filename"].as_str().unwrap(), "test.md");
    assert!(!body["burn_after_reading"].as_bool().unwrap());

    // Decode content
    let content = general_purpose::STANDARD
        .decode(body["encrypted_content"].as_str().unwrap())
        .unwrap();
    assert_eq!(content, b"encrypted data");
}

#[tokio::test]
async fn test_burn_after_reading() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a burn paste
    let resp = create_paste(
        &client,
        &base_url,
        "secret.txt",
        b"burn me",
        true,
        3600,
        None,
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

#[tokio::test]
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

#[tokio::test]
async fn test_public_extension_restriction() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // .exe should be rejected for public uploads
    let resp = create_paste(
        &client,
        &base_url,
        "malware.exe",
        b"data",
        false,
        3600,
        None,
    )
    .await;
    assert_eq!(resp.status(), 403);

    // .md should be allowed
    let resp = create_paste(&client, &base_url, "readme.md", b"data", false, 3600, None).await;
    assert_eq!(resp.status(), 200);

    // .txt should be allowed
    let resp = create_paste(&client, &base_url, "notes.txt", b"data", false, 3600, None).await;
    assert_eq!(resp.status(), 200);
}

// ============================================================================
// Auth Tests
// ============================================================================

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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

    // Valid-format but non-existent token → 404
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
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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
    // First create a user with the alias we want to use
    let (_key1, pubkey1) = test_keypair();
    let user = nullpad::models::StoredUser {
        id: nanoid::nanoid!(12),
        alias: "taken_alias".to_string(),
        pubkey: pubkey1,
        role: "trusted".to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    nullpad::storage::user::store_user(&mut con, &user, 86400)
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
    assert!(body["error"].as_str().unwrap().contains("already taken"));

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

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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
    assert!(body.as_array().unwrap().len() >= 1);
}

#[tokio::test]
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

#[tokio::test]
async fn test_admin_delete_paste() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create a paste
    let resp = create_paste(
        &client,
        &base_url,
        "deleteme.txt",
        b"data",
        false,
        3600,
        None,
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

#[tokio::test]
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
        "user_paste.md",
        b"data",
        false,
        3600,
        Some(&user_token),
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

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
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
        "first.txt",
        b"first upload",
        false,
        3600,
        Some(&user_token),
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
        "second.txt",
        b"second upload",
        false,
        3600,
        Some(&user_token),
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

#[tokio::test]
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

#[tokio::test]
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
        "race.txt",
        b"race condition test",
        true,
        3600,
        None,
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
        match result {
            Ok(resp) => {
                if resp.status() == 200 {
                    success_count += 1;
                } else if resp.status() == 404 {
                    not_found_count += 1;
                }
            }
            Err(_) => {}
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

#[tokio::test]
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

#[tokio::test]
async fn test_forever_paste_requires_auth() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Public user trying to create forever paste (ttl=0) should be rejected
    let resp = create_paste(&client, &base_url, "forever.md", b"data", false, 0, None).await;
    assert_eq!(resp.status(), 403);

    // Login as admin (trusted user)
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Trusted user can create forever paste
    let resp = create_paste(
        &client,
        &base_url,
        "forever.md",
        b"forever data",
        false,
        0,
        Some(&admin_token),
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

#[tokio::test]
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

#[tokio::test]
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

#[tokio::test]
async fn test_trusted_user_can_upload_any_extension() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Login as admin
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Create a trusted user
    let (_user_key, _user_alias, user_token) =
        create_trusted_user(&client, &base_url, &admin_token).await;

    // Trusted user can upload .exe (blocked for public)
    let resp = create_paste(
        &client,
        &base_url,
        "program.exe",
        b"MZ...",
        false,
        3600,
        Some(&user_token),
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Trusted user can upload .zip
    let resp = create_paste(
        &client,
        &base_url,
        "archive.zip",
        b"PK...",
        false,
        3600,
        Some(&user_token),
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Trusted user can upload .pdf
    let resp = create_paste(
        &client,
        &base_url,
        "document.pdf",
        b"%PDF...",
        false,
        3600,
        Some(&user_token),
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Trusted user can upload file with no extension
    let resp = create_paste(
        &client,
        &base_url,
        "Makefile",
        b"all: build",
        false,
        3600,
        Some(&user_token),
    )
    .await;
    assert_eq!(resp.status(), 200);
}
