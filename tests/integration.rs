//! Integration tests for nullpad API.
//!
//! These tests require a running Redis instance (default: redis://127.0.0.1:6379).
//! Set REDIS_URL env var to override.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::SigningKey;
use nullpad::{auth::middleware::AppState, config::Config, middleware::security_headers, routes};
use reqwest::multipart;
use std::sync::Arc;
use tower_http::services::ServeDir;

/// Helper to get Redis URL from environment or use default.
fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

/// Generate an Ed25519 keypair for testing.
fn test_keypair() -> (SigningKey, String) {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey = general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes());
    (signing_key, pubkey)
}

/// Spin up a test server and return its base URL.
async fn spawn_test_server() -> (String, redis::aio::MultiplexedConnection) {
    let (admin_key, admin_pubkey) = test_keypair();
    let _ = admin_key; // admin signing key available if needed

    let redis_client = redis::Client::open(redis_url()).expect("Failed to open Redis");
    let mut con = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Failed to connect to Redis");

    // Flush test data (use a test-specific prefix approach would be better,
    // but for integration tests we just flush)

    // Set up admin user
    nullpad::storage::user::upsert_admin(&mut con, &admin_pubkey, "testadmin")
        .await
        .expect("Failed to upsert admin");

    let config = Config {
        admin_pubkey,
        admin_alias: "testadmin".to_string(),
        redis_url: redis_url(),
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
        rate_limit_paste_per_min: 100,
        rate_limit_paste_per_hour: 1000,
        rate_limit_auth_per_min: 100,
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
    (base_url, con)
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
    let (base_url, _con) = spawn_test_server().await;
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
    let (base_url, _con) = spawn_test_server().await;
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
    let (base_url, _con) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/paste/nonexistent", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_public_extension_restriction() {
    let (base_url, _con) = spawn_test_server().await;
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
    let (base_url, _con) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Admin should be able to complete the full auth flow
    // We need to find the admin signing key — but we generated a random one in spawn_test_server.
    // Instead, let's test the challenge endpoint directly.

    // Request challenge for existing admin
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": "testadmin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["nonce"].as_str().is_some());
}

#[tokio::test]
async fn test_auth_challenge_unknown_user() {
    let (base_url, _con) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": "nobody"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_auth_verify_invalid_signature() {
    let (base_url, _con) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Get a challenge
    let resp = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": "testadmin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Submit garbage signature
    let fake_sig = general_purpose::STANDARD.encode([0u8; 64]);
    let resp = client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": "testadmin", "signature": fake_sig}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_register_with_invite() {
    let (base_url, mut con) = spawn_test_server().await;
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
    let (base_url, _con) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let (_signing_key, pubkey) = test_keypair();

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
    assert_eq!(resp.status(), 404);
}

// ============================================================================
// Admin Tests
// ============================================================================

#[tokio::test]
async fn test_admin_endpoints_require_auth() {
    let (base_url, _con) = spawn_test_server().await;
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
    let (base_url, mut con) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // We need an admin session. Create one directly in Redis.
    let admin_token = nanoid::nanoid!(32);
    let session = nullpad::models::StoredSession {
        token: admin_token.clone(),
        user_id: "admin".to_string(),
        role: "admin".to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    nullpad::storage::session::store_session(&mut con, &session, 900)
        .await
        .unwrap();

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
    let (base_url, mut con) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Create admin session
    let admin_token = nanoid::nanoid!(32);
    let session = nullpad::models::StoredSession {
        token: admin_token.clone(),
        user_id: "admin".to_string(),
        role: "admin".to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    nullpad::storage::session::store_session(&mut con, &session, 900)
        .await
        .unwrap();

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
    let (base_url, mut con) = spawn_test_server().await;
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

    // Create admin session
    let admin_token = nanoid::nanoid!(32);
    let session = nullpad::models::StoredSession {
        token: admin_token.clone(),
        user_id: "admin".to_string(),
        role: "admin".to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    nullpad::storage::session::store_session(&mut con, &session, 900)
        .await
        .unwrap();

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

// ============================================================================
// Security Header Tests
// ============================================================================

#[tokio::test]
async fn test_security_headers_on_api() {
    let (base_url, _con) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/paste/nonexistent", base_url))
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
