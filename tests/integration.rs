//! Integration tests for nullpad API.
//!
//! Tests use testcontainers to spin up a throwaway Valkey instance automatically.
//! Only a running Docker daemon is required — no external Valkey needed.
//!
//! Uses a custom harness (`harness = false`) so that the Valkey container is owned
//! by `main()` and explicitly removed after all tests complete. This prevents
//! container leaks — `static` containers never drop, so previous versions leaked
//! one Docker container per test process.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
#[allow(unused_imports)]
use futures::FutureExt;
use hmac::{Hmac, KeyInit, Mac};
use nullpad::{
    auth::middleware::AppState, cleanup, config::Config, listener::WriteTimeoutListener,
    middleware::security_headers, routes, routes::paste::MAX_BLOB_READS_PER_IP, storage,
};
use reqwest::multipart;
use sha2::Sha256;
use std::sync::{Arc, OnceLock};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::valkey::Valkey;
use tower_http::services::ServeDir;

/// Valkey URL set once in `main()`, read by all test helpers.
static VALKEY_URL: OnceLock<String> = OnceLock::new();

fn get_valkey_url() -> &'static str {
    VALKEY_URL
        .get()
        .expect("VALKEY_URL not initialized — tests must run via main()")
}

/// Parent of every per-test paste storage directory. `main()` owns the
/// `TempDir` and deletes it after all tests, including ones that panicked.
static STORAGE_ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();

fn storage_root() -> &'static std::path::Path {
    STORAGE_ROOT
        .get()
        .expect("STORAGE_ROOT not initialized — tests must run via main()")
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
    // Start a throwaway Valkey testcontainer — owned by main(), removed at end.
    // Pinned to the tag deployed in CI and the cluster.
    let container = Valkey::default()
        .with_tag("9.1.0-alpine")
        .start()
        .await
        .expect("Failed to start Valkey container");
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(6379).await.unwrap();
    VALKEY_URL
        .set(format!("redis://{}:{}", host, port))
        .expect("VALKEY_URL already set");
    let storage_dir = tempfile::Builder::new()
        .prefix("nullpad_test_")
        .tempdir()
        .expect("Failed to create test storage root");
    STORAGE_ROOT
        .set(storage_dir.path().to_path_buf())
        .expect("STORAGE_ROOT already set");

    let (passed, failed) = run_tests![
        test_create_and_get_paste,
        test_get_paste_returns_framed_octet_stream,
        test_burn_after_reading,
        test_paste_not_found,
        test_anon_paste_type_is_not_an_authz_input,
        test_anon_upload_over_anon_max_bytes_returns_413,
        test_anon_daily_paste_quota_per_ip,
        test_concurrent_creates_respect_max_pastes_per_user,
        test_failed_commit_leaves_no_record_or_owner_entry,
        test_store_paste_returns_typed_rejections,
        test_duplicate_paste_id_returns_409,
        test_paste_id_not_reusable_after_burn,
        test_paste_id_not_reusable_after_admin_delete,
        test_paste_id_not_reusable_after_expiry,
        test_unreserved_paste_id_refused,
        test_reserve_issues_id_with_ttl,
        test_expired_reservation_refused,
        test_concurrent_creates_with_one_reservation_store_one,
        test_reserve_rate_limited,
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
        test_register_rejects_small_order_pubkey,
        test_verify_normalized_error_messages,
        test_verify_malformed_signature_does_not_reveal_alias,
        test_verify_malformed_signature_keeps_pending_challenge,
        test_verify_malformed_challenge_id_returns_401,
        test_challenge_alias_limit_is_per_requester,
        test_other_requester_does_not_invalidate_pending_nonce,
        test_verify_weak_stored_pubkey_returns_401,
        test_admin_login_rejects_stale_valkey_pubkey,
        test_admin_login_uses_config_pubkey_after_restore,
        test_admin_role_with_other_id_refused,
        test_rate_limiting_returns_429,
        test_admin_endpoints_require_auth,
        test_admin_create_and_list_invites,
        test_admin_revoke_invite,
        test_admin_delete_paste,
        test_paste_id_never_logged,
        test_stale_tmp_file_id_never_logged,
        test_admin_revoke_user,
        test_admin_cannot_delete_self,
        test_security_headers_on_api,
        test_activate_user_on_first_upload,
        test_upsert_admin_fails_on_alias_owned_by_user,
        test_upsert_admin_keeps_old_alias_owned_by_other,
        test_delete_user_keeps_alias_owned_by_other,
        test_activate_user_keeps_alias_ttl_owned_by_other,
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
        test_pin_gated_global_attempt_rate_limited,
        test_pin_gated_burn_consumed_on_attempt,
        test_non_pin_attempt_returns_404,
        test_non_pin_get_unchanged,
        test_trusted_user_cannot_create_forever_paste,
        test_protected_html_unauthenticated_returns_401,
        test_protected_html_with_session_cookie,
        test_protected_html_not_served_by_static_fallback,
        test_protected_pages_are_no_store,
        test_protected_pages_unauthenticated_no_store,
        test_public_pages_keep_no_cache,
        test_login_sets_host_prefixed_session_cookie,
        test_legacy_np_session_cookie_not_accepted,
        test_logout_clears_host_prefixed_session_cookie,
        test_stored_blob_preserves_bucket_size,
        test_unreadable_blob_returns_500_not_404,
        test_pin_verifier_rejected_when_has_pin_false,
        test_small_pin_verifier_rejected_when_has_pin_false,
        test_metadata_field_size_capped,
        test_reclaimed_id_does_not_serve_stale_blob,
        test_blob_metadata_mismatch_returns_not_found,
        test_legacy_meta_without_content_hash_is_still_served,
        test_legacy_meta_without_has_pin_is_refused,
        test_legacy_burn_meta_without_has_pin_is_not_consumed,
        test_legacy_meta_without_has_pin_attempt_returns_404,
        test_mismatched_burn_paste_is_not_consumed,
        test_meta_with_null_content_hash_is_not_served,
        test_concurrent_blob_reads_bounded,
        test_stalled_blob_reader_released_by_write_timeout,
        test_pin_attempt_503_does_not_consume_pin_attempt,
        test_blob_reads_per_ip_capped,
        test_per_ip_cap_leaves_blob_reads_for_other_ips,
        test_admin_delete_during_stream_keeps_streamed_bytes,
        test_oversized_json_body_returns_413,
        test_paste_over_default_body_limit_succeeds,
        test_unfinished_headers_time_out,
        test_idle_keep_alive_closes_after_header_timeout,
        test_upload_over_max_upload_bytes_returns_413,
        test_second_file_field_replaces_first,
        test_slow_request_times_out_with_408,
        test_timeout_after_paste_id_claim_still_records_owner,
        test_concurrency_limit_queues_requests,
        test_healthz_not_blocked_by_concurrency_limit,
        test_cleanup_reclaims_all_orphans_beyond_cap,
    ];

    // Explicitly remove the container (ContainerAsync has no Drop cleanup).
    container
        .rm()
        .await
        .expect("Failed to remove Valkey container");
    // `process::exit` below skips destructors, so remove the directory here.
    storage_dir
        .close()
        .expect("Failed to remove test storage root");

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

/// Overrides for [`spawn_test_server_configured`]. Only the fields that differ
/// between test scenarios need to be set; everything else stays at safe defaults.
struct TestServerOverrides {
    rate_limit_auth_per_min: u32,
    rate_limit_pin_attempt: u32,
    rate_limit_pin_attempt_global: u32,
    /// Number of trusted proxies (affects which XFF entry is used as client IP).
    trusted_proxy_count: usize,
    /// Paste bodies the server streams at once before answering 503.
    max_concurrent_blob_reads: usize,
    /// Seconds a blocked socket write may last before the connection drops.
    write_timeout_secs: u64,
    /// Time a client may take to send the request headers.
    header_read_timeout: std::time::Duration,
    max_upload_bytes: usize,
    anon_max_bytes: usize,
    anon_max_pastes_per_ip_per_day: u32,
    max_pastes_per_user: usize,
    /// Longest time a request may take to be handled.
    request_timeout: std::time::Duration,
    /// Requests handled at once; further requests wait for a slot.
    max_concurrent_requests: usize,
    rate_limit_paste_per_min: u32,
}

impl Default for TestServerOverrides {
    fn default() -> Self {
        Self {
            rate_limit_auth_per_min: 10000,
            rate_limit_pin_attempt: 10000,
            rate_limit_pin_attempt_global: 10000,
            trusted_proxy_count: 0,
            max_concurrent_blob_reads: 32,
            write_timeout_secs: 60,
            header_read_timeout: std::time::Duration::from_secs(30),
            max_upload_bytes: 52_428_800,
            anon_max_bytes: 262_172,
            anon_max_pastes_per_ip_per_day: 10000,
            max_pastes_per_user: 50,
            request_timeout: std::time::Duration::from_secs(120),
            max_concurrent_requests: 256,
            rate_limit_paste_per_min: 10000,
        }
    }
}

/// Core helper: spin up a test server with configurable rate limits.
///
/// All callers go through this function. Varying fields are supplied via
/// `TestServerOverrides`; everything else is fixed to safe test defaults.
/// Returns the paste storage path as the final tuple element so tests that
/// inspect on-disk blobs can locate them; callers that don't need it discard it.
async fn spawn_test_server_configured(
    overrides: TestServerOverrides,
) -> (
    String,
    redis::aio::ConnectionManager,
    SigningKey,
    String,
    std::path::PathBuf,
) {
    let (admin_key, admin_pubkey) = test_keypair();
    let admin_alias = format!("testadmin_{}", nanoid::nanoid!(6));

    let test_valkey_url = get_valkey_url().to_string();
    let valkey_client =
        redis::Client::open(test_valkey_url.as_str()).expect("Failed to open Valkey");
    let valkey_manager = valkey_client
        .get_connection_manager()
        .await
        .expect("Failed to get connection manager");
    let mut con = valkey_manager.clone();

    nullpad::storage::user::upsert_admin(&mut con, &admin_pubkey, &admin_alias)
        .await
        .expect("Failed to upsert admin");

    let paste_storage_path = storage_root().join(format!("server_{}", nanoid::nanoid!(8)));
    storage::blob::init_storage(&paste_storage_path)
        .await
        .expect("Failed to init paste storage");

    let config = Config {
        admin_pubkey,
        admin_alias: admin_alias.clone(),
        valkey_url: test_valkey_url.clone(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        max_upload_bytes: overrides.max_upload_bytes,
        anon_max_bytes: overrides.anon_max_bytes,
        anon_max_pastes_per_ip_per_day: overrides.anon_max_pastes_per_ip_per_day,
        max_concurrent_blob_reads: overrides.max_concurrent_blob_reads,
        write_timeout_secs: overrides.write_timeout_secs,
        default_ttl_secs: 86400,
        max_ttl_secs: 604800,
        invite_ttl_secs: 43200,
        user_idle_ttl_secs: 172800,
        user_active_ttl_secs: 86400,
        session_ttl_secs: 900,
        challenge_ttl_secs: 30,
        rate_limit_paste_per_min: overrides.rate_limit_paste_per_min,
        rate_limit_auth_per_min: overrides.rate_limit_auth_per_min,
        rate_limit_pin_attempt: overrides.rate_limit_pin_attempt,
        rate_limit_pin_attempt_global: overrides.rate_limit_pin_attempt_global,
        trusted_proxy_count: overrides.trusted_proxy_count,
        max_sessions_per_user: 5,
        max_pastes_per_user: overrides.max_pastes_per_user,
        paste_storage_path: paste_storage_path.clone(),
    };

    let max_upload_bytes = config.max_upload_bytes;
    let state = AppState {
        redis: valkey_manager,
        blob_read_permits: Arc::new(tokio::sync::Semaphore::new(
            config.max_concurrent_blob_reads,
        )),
        blob_reads_per_ip: Default::default(),
        config: Arc::new(config),
        ip_hmac_salt: Arc::new(rand::random()),
    };

    let app = routes::api_router(
        max_upload_bytes,
        overrides.request_timeout,
        overrides.max_concurrent_requests,
    )
    .fallback_service(ServeDir::new("static"))
    .layer(axum::middleware::from_fn(security_headers))
    .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();
    // Same listener and serve loop as main.rs.
    let listener = WriteTimeoutListener::new(
        listener,
        std::time::Duration::from_secs(overrides.write_timeout_secs),
    );
    tokio::spawn(nullpad::listener::serve(
        listener,
        app,
        overrides.header_read_timeout,
    ));

    let base_url = format!("http://{}", addr);
    (base_url, con, admin_key, admin_alias, paste_storage_path)
}

/// Spin up a test server with a custom auth rate limit.
async fn spawn_test_server_with_auth_limit(
    limit: u32,
) -> (String, redis::aio::ConnectionManager, SigningKey, String) {
    let (base_url, con, admin_key, admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            rate_limit_auth_per_min: limit,
            ..Default::default()
        })
        .await;
    (base_url, con, admin_key, admin_alias)
}

/// Spin up a test server with custom per-IP and global PIN attempt rate limits.
/// Uses `trusted_proxy_count=1` so XFF headers control client IP selection.
async fn spawn_test_server_with_pin_limits(
    per_ip_limit: u32,
    global_limit: u32,
) -> (String, redis::aio::ConnectionManager, SigningKey, String) {
    let (base_url, con, admin_key, admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            rate_limit_pin_attempt: per_ip_limit,
            rate_limit_pin_attempt_global: global_limit,
            trusted_proxy_count: 1,
            ..Default::default()
        })
        .await;
    (base_url, con, admin_key, admin_alias)
}

/// Spin up a test server and also return the paste storage path, for tests
/// that need to inspect blobs on disk.
async fn spawn_test_server_with_storage() -> (
    String,
    redis::aio::ConnectionManager,
    SigningKey,
    String,
    std::path::PathBuf,
) {
    spawn_test_server_configured(TestServerOverrides::default()).await
}

/// Spin up a test server that takes the client IP from `X-Forwarded-For`
/// (see [`get_from_ip`]). Returns the base URL, a Valkey connection, the
/// paste storage path and a client with a 10 s timeout.
async fn spawn_trusted_proxy_server(
    overrides: TestServerOverrides,
) -> (
    String,
    redis::aio::ConnectionManager,
    std::path::PathBuf,
    reqwest::Client,
) {
    let (base_url, con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_configured(TestServerOverrides {
            trusted_proxy_count: 1,
            ..overrides
        })
        .await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    (base_url, con, storage_path, client)
}

/// GET `url` as client IP `ip`, on a server from [`spawn_trusted_proxy_server`].
async fn get_from_ip(
    client: &reqwest::Client,
    url: &str,
    ip: &str,
) -> reqwest::Result<reqwest::Response> {
    client.get(url).header("X-Forwarded-For", ip).send().await
}

/// Helper: perform full challenge -> sign -> verify login flow, return session token.
async fn admin_login(
    client: &reqwest::Client,
    base_url: &str,
    alias: &str,
    signing_key: &SigningKey,
) -> String {
    let (challenge_id, nonce) = request_challenge(client, base_url, alias).await;
    let sig_b64 = general_purpose::STANDARD.encode(signing_key.sign(&nonce).to_bytes());
    let (status, body) = post_verify(client, base_url, alias, &challenge_id, &sig_b64).await;
    assert_eq!(status, 200);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
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

/// Split a paste GET / PIN attempt 200 body into its JSON metadata and its
/// raw content bytes. The frame is a big-endian u32 length N, then N bytes of
/// JSON, then the content. Panics on a malformed frame.
fn parse_paste_frame(bytes: &[u8]) -> (serde_json::Value, Vec<u8>) {
    assert!(bytes.len() >= 4, "frame shorter than its length prefix");
    let json_len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert!(
        json_len <= bytes.len() - 4,
        "frame metadata length exceeds the body"
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&bytes[4..4 + json_len]).expect("frame metadata is not JSON");
    (meta, bytes[4 + json_len..].to_vec())
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
    let paste_id = reserve_id(client, base_url).await;
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

    let (body, content) = parse_paste_frame(&resp.bytes().await.unwrap());
    assert!(body["encrypted_metadata"].as_str().is_some());
    assert!(!body["burn_after_reading"].as_bool().unwrap());
    assert_eq!(content, b"encrypted data");
}

async fn test_get_paste_returns_framed_octet_stream() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let uploaded: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let resp = create_paste(
        &client, &base_url, "text", &uploaded, false, 3600, None, false,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();

    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()[reqwest::header::CONTENT_TYPE],
        "application/octet-stream"
    );
    let content_length: usize = resp.headers()[reqwest::header::CONTENT_LENGTH]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();

    let bytes = resp.bytes().await.unwrap();
    let json_len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(content_length, 4 + json_len + uploaded.len());

    let (meta, content) = parse_paste_frame(&bytes);
    assert!(meta.get("burn_after_reading").is_some());
    assert!(meta.get("encrypted_content").is_none());
    assert_eq!(content, uploaded);
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

    let (body, content) = parse_paste_frame(&resp.bytes().await.unwrap());
    assert!(body["burn_after_reading"].as_bool().unwrap());
    assert_eq!(content, b"burn me");

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

async fn test_anon_paste_type_is_not_an_authz_input() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let resp = create_paste(
        &client, &base_url, "file", b"data", false, 3600, None, false,
    )
    .await;
    assert_eq!(resp.status(), 200);
}

async fn test_anon_upload_over_anon_max_bytes_returns_413() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;
    let (_key, _alias, user_token) = create_trusted_user(&client, &base_url, &admin_token).await;

    let anon_max_bytes = TestServerOverrides::default().anon_max_bytes;
    let at_cap = vec![0u8; anon_max_bytes];
    let over_cap = vec![0u8; anon_max_bytes + 1];
    let resp = create_paste(
        &client, &base_url, "text", &at_cap, false, 3600, None, false,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let resp = create_paste(
        &client, &base_url, "text", &over_cap, false, 3600, None, false,
    )
    .await;
    assert_eq!(resp.status(), 413);
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        &over_cap,
        false,
        3600,
        Some(&user_token),
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);
}

async fn test_anon_daily_paste_quota_per_ip() {
    let (base_url, _con, admin_key, admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            anon_max_pastes_per_ip_per_day: 3,
            ..Default::default()
        })
        .await;
    let client = reqwest::Client::new();

    for _ in 0..3 {
        let resp = create_paste(
            &client, &base_url, "text", b"data", false, 3600, None, false,
        )
        .await;
        assert_eq!(resp.status(), 200);
    }
    let resp = create_paste(
        &client, &base_url, "text", b"data", false, 3600, None, false,
    )
    .await;
    assert_eq!(resp.status(), 429);

    let token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"data",
        false,
        3600,
        Some(&token),
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);
}

async fn test_failed_commit_leaves_no_record_or_owner_entry() {
    use redis::AsyncCommands;

    let (_base_url, mut con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_with_storage().await;
    // The blob path check rejects this ID, so the commit fails after the
    // record and the user_pastes entry were written.
    let id = format!("../{}", nanoid::nanoid!(12));
    let owner = format!("owner_{}", nanoid::nanoid!(8));
    // reserve_paste_id never issues an ID like this one.
    let _: () = con.set(format!("paste_reserve:{}", id), 1).await.unwrap();
    let meta = nullpad::models::StoredPasteMeta {
        id: id.clone(),
        encrypted_metadata: general_purpose::STANDARD.encode(b"encrypted-file-metadata"),
        paste_type: nullpad::models::PasteType::default(),
        filename: None,
        content_type: None,
        burn_after_reading: false,
        created_at: 0,
        owner_id: Some(owner.clone()),
        has_pin: Some(false),
        pin_verifier: None,
        content_sha256: None,
    };
    let upload = storage::blob::BlobUpload::create(&storage_path)
        .await
        .expect("Failed to create upload");
    let result =
        storage::paste::store_paste(&mut con, &storage_path, &meta, upload, 3600, 604800, 50).await;
    assert!(result.is_err(), "commit to an invalid blob ID must fail");

    let stored: bool = con.exists(format!("paste:{}", id)).await.unwrap();
    assert!(!stored, "paste record left after failed commit");
    let listed: bool = con
        .sismember(format!("user_pastes:{}", owner), &id)
        .await
        .unwrap();
    assert!(!listed, "user_pastes entry left after failed commit");
}

/// Store an empty paste through `store_paste` with a 1 h TTL.
async fn store_test_paste<C: redis::AsyncCommands>(
    con: &mut C,
    storage_path: &std::path::Path,
    id: &str,
    owner_id: Option<&str>,
    max_pastes_per_user: usize,
) -> Result<(), storage::paste::StorePasteError> {
    let meta = nullpad::models::StoredPasteMeta {
        id: id.to_string(),
        encrypted_metadata: general_purpose::STANDARD.encode(b"encrypted-file-metadata"),
        paste_type: nullpad::models::PasteType::default(),
        filename: None,
        content_type: None,
        burn_after_reading: false,
        created_at: 0,
        owner_id: owner_id.map(str::to_string),
        has_pin: Some(false),
        pin_verifier: None,
        content_sha256: None,
    };
    let upload = storage::blob::BlobUpload::create(storage_path)
        .await
        .expect("Failed to create upload");
    storage::paste::store_paste(
        con,
        storage_path,
        &meta,
        upload,
        3600,
        604800,
        max_pastes_per_user,
    )
    .await
}

async fn test_store_paste_returns_typed_rejections() {
    use redis::AsyncCommands;
    use storage::paste::StorePasteError;

    let (_base_url, mut con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_with_storage().await;
    let owner = format!("owner_{}", nanoid::nanoid!(8));
    let first = storage::paste::reserve_paste_id(&mut con).await.unwrap();
    let second = storage::paste::reserve_paste_id(&mut con).await.unwrap();

    assert!(
        store_test_paste(&mut con, &storage_path, &first, Some(&owner), 1)
            .await
            .is_ok()
    );
    assert!(matches!(
        store_test_paste(&mut con, &storage_path, &second, Some(&owner), 1).await,
        Err(StorePasteError::QuotaExceeded)
    ));
    // No reservation: `second` spent its own on the store the quota refused.
    assert!(matches!(
        store_test_paste(&mut con, &storage_path, &second, Some(&owner), 0).await,
        Err(StorePasteError::Conflict)
    ));
    // Reserved again, so this store reaches the SET NX on the existing record.
    let _: () = con
        .set(format!("paste_reserve:{}", first), 1)
        .await
        .unwrap();
    assert!(matches!(
        store_test_paste(&mut con, &storage_path, &first, None, 0).await,
        Err(StorePasteError::Conflict)
    ));
}

async fn test_duplicate_paste_id_returns_409() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Use a fixed paste ID for both requests
    let paste_id = reserve_id(&client, &base_url).await;
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
// Paste ID Reservation Tests
// ============================================================================

/// POST /api/paste/reserve and return the issued paste ID.
async fn reserve_id(client: &reqwest::Client, base_url: &str) -> String {
    let resp = client
        .post(format!("{}/api/paste/reserve", base_url))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    body["id"].as_str().unwrap().to_string()
}

/// POST /api/paste without auth: a text paste stored under `paste_id`.
async fn post_paste_with_id(
    client: &reqwest::Client,
    base_url: &str,
    paste_id: &str,
    burn: bool,
) -> reqwest::Response {
    let mut metadata = anon_text_paste_metadata(paste_id);
    metadata["burn_after_reading"] = serde_json::Value::Bool(burn);
    post_paste_with_raw_metadata(client, base_url, metadata.to_string()).await
}

async fn test_paste_id_not_reusable_after_burn() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let id = reserve_id(&client, &base_url).await;
    let resp = post_paste_with_id(&client, &base_url, &id, true).await;
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = post_paste_with_id(&client, &base_url, &id, false).await;
    assert_eq!(resp.status(), 409);
}

async fn test_paste_id_not_reusable_after_admin_delete() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let id = reserve_id(&client, &base_url).await;
    let resp = post_paste_with_id(&client, &base_url, &id, false).await;
    assert_eq!(resp.status(), 200);
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;
    let resp = client
        .delete(format!("{}/api/paste/{}", base_url, id))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let resp = post_paste_with_id(&client, &base_url, &id, false).await;
    assert_eq!(resp.status(), 409);
}

async fn test_paste_id_not_reusable_after_expiry() {
    use redis::AsyncCommands;
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let id = reserve_id(&client, &base_url).await;
    let resp = post_paste_with_id(&client, &base_url, &id, false).await;
    assert_eq!(resp.status(), 200);
    let _: () = con.del(format!("paste:{}", id)).await.unwrap();

    let resp = post_paste_with_id(&client, &base_url, &id, false).await;
    assert_eq!(resp.status(), 409);
}

async fn test_unreserved_paste_id_refused() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let resp = post_paste_with_id(&client, &base_url, &nanoid::nanoid!(12), false).await;
    assert_eq!(resp.status(), 409);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"],
        "Paste ID is not reserved or was already used. Reload the page and try again."
    );
}

async fn test_reserve_issues_id_with_ttl() {
    use redis::AsyncCommands;
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let id = reserve_id(&client, &base_url).await;
    assert_eq!(id.len(), 12);
    let ttl: i64 = con.ttl(format!("paste_reserve:{}", id)).await.unwrap();
    assert!((1..=600).contains(&ttl), "reservation TTL was {}", ttl);
}

async fn test_expired_reservation_refused() {
    use redis::AsyncCommands;
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let id = reserve_id(&client, &base_url).await;
    let _: () = con.del(format!("paste_reserve:{}", id)).await.unwrap();

    let resp = post_paste_with_id(&client, &base_url, &id, false).await;
    assert_eq!(resp.status(), 409);
}

async fn test_concurrent_creates_with_one_reservation_store_one() {
    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let id = reserve_id(&client, &base_url).await;
    let responses = futures::future::join_all(
        (0..8).map(|_| post_paste_with_id(&client, &base_url, &id, false)),
    )
    .await;
    let stored = responses.iter().filter(|r| r.status() == 200).count();
    assert_eq!(stored, 1);
}

async fn test_reserve_rate_limited() {
    let (base_url, _con, _admin_key, _admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            rate_limit_paste_per_min: 2,
            ..Default::default()
        })
        .await;
    let client = reqwest::Client::new();

    reserve_id(&client, &base_url).await;
    reserve_id(&client, &base_url).await;
    let resp = client
        .post(format!("{}/api/paste/reserve", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
}

// ============================================================================
// Per-User Paste Quota Race Tests
// ============================================================================

async fn test_concurrent_creates_respect_max_pastes_per_user() {
    use redis::AsyncCommands;
    use storage::paste::StorePasteError;

    let (base_url, mut con, admin_key, admin_alias, storage_path) =
        spawn_test_server_configured(TestServerOverrides {
            max_pastes_per_user: 3,
            ..Default::default()
        })
        .await;
    let client = reqwest::Client::new();
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;
    let (_key, user_alias, user_token) =
        create_trusted_user(&client, &base_url, &admin_token).await;
    let user_id: String = con.get(format!("alias:{}", user_alias)).await.unwrap();

    // Each task stores on its own connection, and all start together, so the
    // stores reach Valkey concurrently. A count check apart from the SET NX
    // would let more than three through.
    let valkey = redis::Client::open(get_valkey_url()).unwrap();
    let mut task_cons = Vec::new();
    for _ in 0..10 {
        task_cons.push(valkey.get_multiplexed_async_connection().await.unwrap());
    }
    let start = Arc::new(tokio::sync::Barrier::new(task_cons.len()));
    let mut handles = Vec::new();
    for mut task_con in task_cons {
        let storage_path = storage_path.clone();
        let user_id = user_id.clone();
        let start = start.clone();
        let id = storage::paste::reserve_paste_id(&mut con).await.unwrap();
        handles.push(tokio::spawn(async move {
            start.wait().await;
            store_test_paste(&mut task_con, &storage_path, &id, Some(&user_id), 3).await
        }));
    }
    let (mut stored, mut rejected) = (0, 0);
    for handle in handles {
        match handle.await.unwrap() {
            Ok(()) => stored += 1,
            Err(StorePasteError::QuotaExceeded) => rejected += 1,
            Err(e) => panic!("unexpected store_paste error: {}", e),
        }
    }
    assert_eq!((stored, rejected), (3, 7));
    let count: usize = con.scard(format!("user_pastes:{}", user_id)).await.unwrap();
    assert_eq!(count, 3);

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
    assert_eq!(resp.status(), 400);
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
    assert!(body["challenge_id"].as_str().is_some());
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
    assert!(body["challenge_id"].is_string());
}

async fn test_auth_verify_invalid_signature() {
    let (base_url, _con, _admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let (challenge_id, _nonce) = request_challenge(&client, &base_url, &admin_alias).await;

    // Submit garbage signature
    let fake_sig = general_purpose::STANDARD.encode([0u8; 64]);
    let (status, _) = post_verify(&client, &base_url, &admin_alias, &challenge_id, &fake_sig).await;
    assert_eq!(status, 401);
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

    // Alias too short (1 char), too long (65 chars), special chars -> 400
    let long_alias = "a".repeat(65);
    for alias in ["a", long_alias.as_str(), "user@evil.com"] {
        let (status, _) = post_verify(
            &client,
            &base_url,
            alias,
            WELL_FORMED_CHALLENGE_ID,
            &fake_sig,
        )
        .await;
        assert_eq!(status, 400, "alias={alias}");
    }
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

async fn test_register_rejects_small_order_pubkey() {
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let invite_token = nanoid::nanoid!(16);
    let invite = nullpad::models::StoredInvite {
        token: invite_token.clone(),
        created_at: nullpad::util::now_secs(),
    };
    nullpad::storage::user::store_invite(&mut con, &invite, 3600)
        .await
        .unwrap();

    let resp = client
        .post(format!("{}/api/register", base_url))
        .json(&serde_json::json!({
            "token": invite_token,
            "alias": "weakkeyuser",
            "pubkey": general_purpose::STANDARD.encode([0u8; 32])
        }))
        .send()
        .await
        .unwrap();
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
    let (status, body) = post_verify(
        &client,
        &base_url,
        "nobody_here",
        WELL_FORMED_CHALLENGE_ID,
        &fake_sig,
    )
    .await;
    assert_eq!(status, 401);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["error"], "Authentication failed");

    // Verify with wrong signature (after getting a challenge) -> 401 with generic message
    // First get a challenge
    let (challenge_id, _nonce) = request_challenge(&client, &base_url, &admin_alias).await;
    // Then submit bad sig
    let (status, body) =
        post_verify(&client, &base_url, &admin_alias, &challenge_id, &fake_sig).await;
    assert_eq!(status, 401);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["error"], "Authentication failed");
}

const WELL_FORMED_CHALLENGE_ID: &str = "00000000000000000000000000000000";

async fn send_verify(
    client: &reqwest::Client,
    base_url: &str,
    alias: &str,
    challenge_id: &str,
    signature: &str,
) -> reqwest::Response {
    client
        .post(format!("{}/api/auth/verify", base_url))
        .json(&serde_json::json!({"alias": alias, "challenge_id": challenge_id, "signature": signature}))
        .send()
        .await
        .unwrap()
}

async fn post_verify(
    client: &reqwest::Client,
    base_url: &str,
    alias: &str,
    challenge_id: &str,
    signature: &str,
) -> (reqwest::StatusCode, String) {
    let resp = send_verify(client, base_url, alias, challenge_id, signature).await;
    (resp.status(), resp.text().await.unwrap())
}

async fn send_challenge(
    client: &reqwest::Client,
    base_url: &str,
    alias: &str,
    client_ip: Option<&str>,
) -> reqwest::Response {
    let mut req = client
        .post(format!("{}/api/auth/challenge", base_url))
        .json(&serde_json::json!({"alias": alias}));
    if let Some(ip) = client_ip {
        req = req.header("X-Forwarded-For", ip);
    }
    req.send().await.unwrap()
}

async fn parse_challenge(resp: reqwest::Response) -> (String, Vec<u8>) {
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let nonce = general_purpose::STANDARD
        .decode(body["nonce"].as_str().unwrap())
        .unwrap();
    (body["challenge_id"].as_str().unwrap().to_string(), nonce)
}

async fn request_challenge(
    client: &reqwest::Client,
    base_url: &str,
    alias: &str,
) -> (String, Vec<u8>) {
    parse_challenge(send_challenge(client, base_url, alias, None).await).await
}

async fn unknown_alias_verify_response(
    client: &reqwest::Client,
    base_url: &str,
) -> (reqwest::StatusCode, String) {
    let fake_sig = general_purpose::STANDARD.encode([0u8; 64]);
    let response = post_verify(
        client,
        base_url,
        "nobody_here",
        WELL_FORMED_CHALLENGE_ID,
        &fake_sig,
    )
    .await;
    assert_eq!(response.0, 401);
    response
}

async fn test_verify_malformed_signature_does_not_reveal_alias() {
    let (base_url, _con, _admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let expected = unknown_alias_verify_response(&client, &base_url).await;
    let short_sig = general_purpose::STANDARD.encode([0u8; 10]);

    for signature in ["not-base64!", short_sig.as_str()] {
        for alias in [admin_alias.as_str(), "nobody_here"] {
            let (challenge_id, _nonce) = request_challenge(&client, &base_url, alias).await;
            let response = post_verify(&client, &base_url, alias, &challenge_id, signature).await;
            assert_eq!(response, expected, "alias={alias} signature={signature}");
        }
    }
}

async fn test_verify_malformed_signature_keeps_pending_challenge() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let (challenge_id, nonce) = request_challenge(&client, &base_url, &admin_alias).await;
    let (status, _) = post_verify(
        &client,
        &base_url,
        &admin_alias,
        &challenge_id,
        "not-base64!",
    )
    .await;
    assert_eq!(status, 401);

    let sig_b64 = general_purpose::STANDARD.encode(admin_key.sign(&nonce).to_bytes());
    let (status, _) = post_verify(&client, &base_url, &admin_alias, &challenge_id, &sig_b64).await;
    assert_eq!(status, 200);
}

async fn test_verify_malformed_challenge_id_returns_401() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let expected = unknown_alias_verify_response(&client, &base_url).await;

    let (challenge_id, nonce) = request_challenge(&client, &base_url, &admin_alias).await;
    let sig_b64 = general_purpose::STANDARD.encode(admin_key.sign(&nonce).to_bytes());
    let suffixed = format!("{challenge_id}:x");
    let malformed = [
        "",
        &challenge_id[..31],
        suffixed.as_str(),
        "../../../../../../../../../../ab",
        "0000000000000000000000000000000G",
    ];
    for bad_id in malformed {
        let response = post_verify(&client, &base_url, &admin_alias, bad_id, &sig_b64).await;
        assert_eq!(response, expected, "challenge_id={bad_id:?}");
    }
}

async fn test_challenge_alias_limit_is_per_requester() {
    let (base_url, _con, _admin_key, admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            trusted_proxy_count: 1,
            ..Default::default()
        })
        .await;
    let client = reqwest::Client::new();

    for ip in ["10.0.1.1", "10.0.1.2"] {
        for _ in 0..5 {
            let resp = send_challenge(&client, &base_url, &admin_alias, Some(ip)).await;
            assert_eq!(resp.status(), 200);
        }
    }

    let resp = send_challenge(&client, &base_url, &admin_alias, Some("10.0.1.3")).await;
    assert_eq!(resp.status(), 200);
}

async fn test_other_requester_does_not_invalidate_pending_nonce() {
    let (base_url, _con, admin_key, admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            trusted_proxy_count: 1,
            ..Default::default()
        })
        .await;
    let client = reqwest::Client::new();

    let owner = send_challenge(&client, &base_url, &admin_alias, Some("10.0.2.1")).await;
    let (challenge_id, nonce) = parse_challenge(owner).await;
    let attacker = send_challenge(&client, &base_url, &admin_alias, Some("10.0.2.2")).await;
    assert_eq!(attacker.status(), 200);

    let sig_b64 = general_purpose::STANDARD.encode(admin_key.sign(&nonce).to_bytes());
    let (status, _) = post_verify(&client, &base_url, &admin_alias, &challenge_id, &sig_b64).await;
    assert_eq!(status, 200);
}

async fn test_verify_weak_stored_pubkey_returns_401() {
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let expected = unknown_alias_verify_response(&client, &base_url).await;

    let invite_token = nanoid::nanoid!(16);
    let invite = nullpad::models::StoredInvite {
        token: invite_token.clone(),
        created_at: nullpad::util::now_secs(),
    };
    nullpad::storage::user::store_invite(&mut con, &invite, 3600)
        .await
        .unwrap();
    let weak_user = nullpad::models::StoredUser {
        id: nanoid::nanoid!(12),
        alias: "weak_key_user".to_string(),
        pubkey: general_purpose::STANDARD.encode([0u8; 32]),
        role: nullpad::models::Role::Trusted,
        created_at: nullpad::util::now_secs(),
    };
    nullpad::storage::user::consume_invite_and_create_user(
        &mut con,
        &invite_token,
        &weak_user,
        86400,
    )
    .await
    .unwrap();

    let (challenge_id, _nonce) = request_challenge(&client, &base_url, "weak_key_user").await;
    let fake_sig = general_purpose::STANDARD.encode([0u8; 64]);
    let response = post_verify(
        &client,
        &base_url,
        "weak_key_user",
        &challenge_id,
        &fake_sig,
    )
    .await;
    assert_eq!(response, expected);
}

async fn test_admin_login_rejects_stale_valkey_pubkey() {
    let (base_url, mut con, _admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let (old_key, old_pubkey) = test_keypair();
    nullpad::storage::user::upsert_admin(&mut con, &old_pubkey, &admin_alias)
        .await
        .unwrap();

    let (challenge_id, nonce) = request_challenge(&client, &base_url, &admin_alias).await;
    let sig_b64 = general_purpose::STANDARD.encode(old_key.sign(&nonce).to_bytes());
    let (status, _body) =
        post_verify(&client, &base_url, &admin_alias, &challenge_id, &sig_b64).await;
    assert_eq!(status, 401);
}

async fn test_admin_login_uses_config_pubkey_after_restore() {
    let (base_url, mut con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let (_old_key, old_pubkey) = test_keypair();
    nullpad::storage::user::upsert_admin(&mut con, &old_pubkey, &admin_alias)
        .await
        .unwrap();

    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    let resp = client
        .get(format!("{}/api/invites", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

async fn test_admin_role_with_other_id_refused() {
    use redis::AsyncCommands;
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let (other_key, other_pubkey) = test_keypair();
    let other_admin = nullpad::models::StoredUser {
        id: "x-admin".to_string(),
        alias: "xadmin".to_string(),
        pubkey: other_pubkey,
        role: nullpad::models::Role::Admin,
        created_at: nullpad::util::now_secs(),
    };
    let _: () = con
        .set("user:x-admin", serde_json::to_string(&other_admin).unwrap())
        .await
        .unwrap();
    let _: () = con.set("alias:xadmin", "x-admin").await.unwrap();

    let (challenge_id, nonce) = request_challenge(&client, &base_url, "xadmin").await;
    let sig_b64 = general_purpose::STANDARD.encode(other_key.sign(&nonce).to_bytes());
    let (status, _body) = post_verify(&client, &base_url, "xadmin", &challenge_id, &sig_b64).await;

    let _: () = con.del(&["user:x-admin", "alias:xadmin"]).await.unwrap();
    assert_eq!(status, 401);
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

#[derive(Clone)]
struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn test_paste_id_never_logged() {
    let logs = LogBuffer(Arc::new(std::sync::Mutex::new(Vec::new())));
    let writer = logs.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();

    let (base_url, _con, admin_key, admin_alias, storage_path) =
        spawn_test_server_configured(TestServerOverrides {
            rate_limit_pin_attempt_global: 1,
            trusted_proxy_count: 1,
            ..Default::default()
        })
        .await;
    let client = reqwest::Client::new();
    let mut ids = Vec::new();

    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"pin data",
        false,
        3600,
        None,
        true,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let pin_id = body["id"].as_str().unwrap().to_string();
    let verifier = test_pin_verifier(&test_dummy_key(), &pin_id);
    for (ip_suffix, expected) in [(1u8, 200), (2, 429)] {
        let resp = pin_attempt_with_xff(&client, &base_url, &pin_id, &verifier, ip_suffix)
            .await
            .unwrap();
        assert_eq!(resp.status(), expected);
    }
    ids.push(pin_id);

    for _ in 0..3 {
        let resp = create_paste(
            &client, &base_url, "text", b"data", false, 3600, None, false,
        )
        .await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        ids.push(body["id"].as_str().unwrap().to_string());
    }

    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;
    let resp = client
        .delete(format!("{}/api/paste/{}", base_url, ids[1]))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let missing_blob = storage_path.join(&ids[2][..2]).join(&ids[2]);
    std::fs::remove_file(&missing_blob).unwrap();
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, ids[2]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let unreadable_blob = storage_path.join(&ids[3][..2]).join(&ids[3]);
    std::fs::remove_file(&unreadable_blob).unwrap();
    std::fs::create_dir(&unreadable_blob).unwrap();
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, ids[3]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);

    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for expected in [
        "Paste created",
        "Rate limit exceeded",
        "Admin deleted paste",
        "blob missing on disk",
        "Failed to read blob",
    ] {
        assert!(
            logs.contains(expected),
            "expected log line {expected:?} not captured"
        );
    }
    for id in &ids {
        assert!(
            !logs.contains(id.as_str()),
            "paste ID {id} appears in logs:\n{logs}"
        );
    }
}

async fn test_stale_tmp_file_id_never_logged() {
    use std::os::unix::fs::PermissionsExt;
    use tracing::instrument::WithSubscriber;

    let logs = LogBuffer(Arc::new(std::sync::Mutex::new(Vec::new())));
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();

    let mut con = redis::Client::open(get_valkey_url())
        .unwrap()
        .get_connection_manager()
        .await
        .unwrap();
    let storage_path = storage_root().join(format!("tmp_log_{}", nanoid::nanoid!(8)));
    let id = nanoid::nanoid!(12);
    let shard = storage_path.join(&id[..2]);
    std::fs::create_dir_all(&shard).unwrap();
    let tmp_file = std::fs::File::create(shard.join(format!("{id}.tmp"))).unwrap();
    tmp_file
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(7200))
        .unwrap();
    std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o555)).unwrap();

    let result = cleanup::cleanup_orphaned_files(&mut con, &storage_path)
        .with_subscriber(subscriber)
        .await;

    std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _ = std::fs::remove_dir_all(&storage_path);
    result.unwrap();

    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("Failed to delete stale tmp file"),
        "expected stale tmp warning not captured:\n{logs}"
    );
    assert!(
        !logs.contains(id.as_str()),
        "paste ID {id} appears in logs:\n{logs}"
    );
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

    // Pubkey must NOT be exposed in the response (it is brute-force material)
    for user in users.as_array().unwrap() {
        assert!(
            user.get("pubkey").is_none(),
            "pubkey must not be present in /api/users response"
        );
    }

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

async fn test_upsert_admin_fails_on_alias_owned_by_user() {
    use redis::AsyncCommands;
    let (_base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let token = nanoid::nanoid!(16);
    let invite = nullpad::models::StoredInvite {
        token: token.clone(),
        created_at: nullpad::util::now_secs(),
    };
    nullpad::storage::user::store_invite(&mut con, &invite, 3600)
        .await
        .unwrap();
    let (_key, pubkey) = test_keypair();
    let user = nullpad::models::StoredUser {
        id: nanoid::nanoid!(12),
        alias: format!("owned_{}", nanoid::nanoid!(8)),
        pubkey: pubkey.clone(),
        role: nullpad::models::Role::Trusted,
        created_at: nullpad::util::now_secs(),
    };
    nullpad::storage::user::consume_invite_and_create_user(&mut con, &token, &user, 3600)
        .await
        .unwrap();
    let alias_key = format!("alias:{}", user.alias);

    let result = nullpad::storage::user::upsert_admin(&mut con, &pubkey, &user.alias).await;
    let owner: Option<String> = con.get(&alias_key).await.unwrap();
    let _: () = con
        .del(&[alias_key.clone(), format!("user:{}", user.id)])
        .await
        .unwrap();

    assert!(result.is_err(), "upsert_admin must refuse a user's alias");
    assert_eq!(owner.as_deref(), Some(user.id.as_str()));
}

async fn test_upsert_admin_keeps_old_alias_owned_by_other() {
    use redis::AsyncCommands;
    let (_base_url, mut con, _admin_key, admin_alias) = spawn_test_server().await;
    let (_key, pubkey) = test_keypair();
    let old_alias_key = format!("alias:{}", admin_alias);
    let other_id = nanoid::nanoid!(12);
    let _: () = con.set(&old_alias_key, &other_id).await.unwrap();
    let new_alias = format!("testadmin_{}", nanoid::nanoid!(6));

    let result = nullpad::storage::user::upsert_admin(&mut con, &pubkey, &new_alias).await;
    let owner: Option<String> = con.get(&old_alias_key).await.unwrap();
    let _: () = con.del(&old_alias_key).await.unwrap();

    assert!(result.is_ok(), "upsert_admin must succeed: {:?}", result);
    assert_eq!(owner.as_deref(), Some(other_id.as_str()));
}

async fn test_delete_user_keeps_alias_owned_by_other() {
    use redis::AsyncCommands;
    let (_base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let (_key, pubkey) = test_keypair();
    let user = nullpad::models::StoredUser {
        id: nanoid::nanoid!(12),
        alias: format!("shared_{}", nanoid::nanoid!(8)),
        pubkey,
        role: nullpad::models::Role::Trusted,
        created_at: nullpad::util::now_secs(),
    };
    let alias_key = format!("alias:{}", user.alias);
    let _: () = con
        .set(
            format!("user:{}", user.id),
            serde_json::to_string(&user).unwrap(),
        )
        .await
        .unwrap();
    let _: () = con.set(&alias_key, "admin").await.unwrap();

    nullpad::storage::user::delete_user(&mut con, &user.id)
        .await
        .unwrap();
    let owner: Option<String> = con.get(&alias_key).await.unwrap();
    let _: () = con.del(&alias_key).await.unwrap();

    assert_eq!(owner.as_deref(), Some("admin"));
}

async fn test_activate_user_keeps_alias_ttl_owned_by_other() {
    use redis::AsyncCommands;
    let (_base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let idle_ttl: u64 = 172800;
    let active_ttl: u64 = 86400;
    let (_key, pubkey) = test_keypair();
    let user = nullpad::models::StoredUser {
        id: nanoid::nanoid!(12),
        alias: format!("shared_{}", nanoid::nanoid!(8)),
        pubkey,
        role: nullpad::models::Role::Trusted,
        created_at: nullpad::util::now_secs(),
    };
    let user_key = format!("user:{}", user.id);
    let pastes_key = format!("user_pastes:{}", user.id);
    let alias_key = format!("alias:{}", user.alias);
    let _: () = con
        .set_ex(
            &user_key,
            serde_json::to_string(&user).unwrap(),
            idle_ttl - 30,
        )
        .await
        .unwrap();
    let _: () = con.sadd(&pastes_key, nanoid::nanoid!(12)).await.unwrap();
    let _: () = con.set(&alias_key, "admin").await.unwrap();

    nullpad::storage::paste::activate_user_on_first_upload(
        &mut con, &user.id, idle_ttl, active_ttl,
    )
    .await
    .unwrap();
    let alias_ttl: i64 = con.ttl(&alias_key).await.unwrap();
    let _: () = con
        .del(&[alias_key.clone(), user_key.clone(), pastes_key.clone()])
        .await
        .unwrap();

    assert_eq!(alias_ttl, -1);
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

    let (challenge_id, nonce) = request_challenge(&client, &base_url, &admin_alias).await;
    let sig_b64 = general_purpose::STANDARD.encode(admin_key.sign(&nonce).to_bytes());

    // First verification should succeed
    let (status, _) = post_verify(&client, &base_url, &admin_alias, &challenge_id, &sig_b64).await;
    assert_eq!(status, 200);

    // Second verification with same signature should fail (nonce consumed)
    let (status, _) = post_verify(&client, &base_url, &admin_alias, &challenge_id, &sig_b64).await;
    assert_eq!(status, 401);
}

// ============================================================================
// Concurrent Burn-After-Reading Tests
// ============================================================================

async fn test_concurrent_burn_after_reading_race() {
    // Each request comes from its own IP, so the per-IP read cap does not apply.
    let (base_url, _con, _storage_path, client) =
        spawn_trusted_proxy_server(TestServerOverrides::default()).await;

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
    for i in 0..10 {
        let url = format!("{}/api/paste/{}", base_url, paste_id);
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            get_from_ip(&c, &url, &format!("203.0.113.{}", i)).await
        }));
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

/// POST a PIN attempt with a spoofed client IP via X-Forwarded-For.
///
/// `client_ip_suffix` sets the last octet of a 10.0.0.N address in the XFF
/// header alongside a fixed trusted proxy IP, giving each distinct suffix its
/// own per-IP rate-limit bucket.
async fn pin_attempt_with_xff(
    client: &reqwest::Client,
    base_url: &str,
    id: &str,
    verifier: &str,
    client_ip_suffix: u8,
) -> Result<reqwest::Response, reqwest::Error> {
    let xff = format!("10.0.0.{}, 192.168.1.1", client_ip_suffix);
    client
        .post(format!("{}/api/paste/{}", base_url, id))
        .header("Content-Type", "application/json")
        .header("X-Forwarded-For", xff)
        .body(serde_json::json!({ "pin_verifier": verifier }).to_string())
        .send()
        .await
}

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
    let (body, content) = parse_paste_frame(&resp.bytes().await.unwrap());
    assert_eq!(body["needs_pin"], true);
    assert!(body.get("encrypted_content").is_none());
    assert!(
        content.is_empty(),
        "needs_pin response must carry no content"
    );
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
    let (body, content) = parse_paste_frame(&resp.bytes().await.unwrap());
    assert_eq!(content, b"secret data");
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
    // per-IP limit = 2, global limit = 10000 (well above attempt count, won't fire)
    let (base_url, _con, _admin_key, _admin_alias) =
        spawn_test_server_with_pin_limits(2, 10000).await;
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
    let retry_after: u64 = resp
        .headers()
        .get("retry-after")
        .expect("429 must include Retry-After header")
        .to_str()
        .unwrap()
        .parse()
        .expect("Retry-After must be a positive integer");
    assert!(retry_after > 0, "Retry-After must be positive");
}

async fn test_pin_gated_global_attempt_rate_limited() {
    // Global cap = 3. Per-IP cap = 100: set well above the 3 attempts made here
    // so only the global cap can fire, not any per-IP bucket.
    // Three distinct client IPs each make 1 attempt (each under per-IP limit).
    // The 4th attempt from yet another IP must be 429 due to global cap.
    let (base_url, _con, _admin_key, _admin_alias) =
        spawn_test_server_with_pin_limits(100, 3).await;
    let client = reqwest::Client::new();

    // Create a PIN-gated paste
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        b"global secret",
        false,
        3600,
        None,
        true,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();

    let dummy_key = test_dummy_key();
    let verifier = test_pin_verifier(&dummy_key, &id);

    // Three distinct client IPs, each within per-IP limit → correct PIN → 200.
    //
    // With trusted_proxy_count=1, client_ip() reads XFF[len - 1 - 1] = XFF[0]
    // from a two-entry header "10.0.0.N, 192.168.1.1", so 10.0.0.N is the client
    // IP. Each distinct N lands in its own per-IP rate-limit bucket.
    for ip_suffix in 1u8..=3 {
        let resp = pin_attempt_with_xff(&client, &base_url, &id, &verifier, ip_suffix)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "Expected 200 for client IP 10.0.0.{}, got {}",
            ip_suffix,
            resp.status()
        );
    }

    // 4th attempt from a fresh IP — global cap exhausted → 429
    let resp = pin_attempt_with_xff(&client, &base_url, &id, &verifier, 4)
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        429,
        "Expected 429 after global cap exhausted"
    );
    let retry_after: u64 = resp
        .headers()
        .get("retry-after")
        .expect("429 must include Retry-After header")
        .to_str()
        .unwrap()
        .parse()
        .expect("Retry-After must be a positive integer");
    assert!(retry_after > 0, "Retry-After must be positive");
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
    let (body, _content) = parse_paste_frame(&resp.bytes().await.unwrap());
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
    let (_body, content) = parse_paste_frame(&resp.bytes().await.unwrap());
    assert_eq!(content, b"burn secret");

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
    let (body, content) = parse_paste_frame(&resp.bytes().await.unwrap());
    assert_eq!(content, b"normal data");
    assert!(body["created_at"].is_number());
    assert!(body.get("needs_pin").is_none());
}

// ============================================================================
// Paste Metadata Validation Tests
// ============================================================================

/// Valid metadata for an anonymous text paste with `has_pin` false and
/// `pin_verifier` null. Tests change single fields to build invalid variants.
fn anon_text_paste_metadata(paste_id: &str) -> serde_json::Value {
    serde_json::json!({
        "paste_id": paste_id,
        "encrypted_metadata": general_purpose::STANDARD.encode(b"encrypted-file-metadata"),
        "paste_type": "text",
        "ttl_secs": 3600,
        "burn_after_reading": false,
        "has_pin": false,
        "pin_verifier": null
    })
}

/// POST /api/paste without auth, sending `metadata` as the raw body of the
/// "metadata" part and a small "file" part.
async fn post_paste_with_raw_metadata(
    client: &reqwest::Client,
    base_url: &str,
    metadata: String,
) -> reqwest::Response {
    let form = multipart::Form::new()
        .part(
            "metadata",
            multipart::Part::text(metadata)
                .mime_str("application/json")
                .unwrap(),
        )
        .part(
            "file",
            multipart::Part::bytes(b"encrypted data".to_vec())
                .file_name("encrypted")
                .mime_str("application/octet-stream")
                .unwrap(),
        );

    client
        .post(format!("{}/api/paste", base_url))
        .multipart(form)
        .send()
        .await
        .expect("Failed to send request")
}

/// Assert that no `paste:{id}` key exists in Valkey for a rejected paste.
async fn assert_paste_not_stored(con: &mut redis::aio::ConnectionManager, paste_id: &str) {
    use redis::AsyncCommands;
    let key = format!("paste:{}", paste_id);
    let exists: bool = con.exists(&key).await.unwrap();
    assert!(
        !exists,
        "Rejected paste must not be stored in Valkey, but key {} exists",
        key
    );
}

/// A 1 MB pin_verifier with has_pin false must be rejected, not stored.
async fn test_pin_verifier_rejected_when_has_pin_false() {
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let paste_id = nanoid::nanoid!(12);
    let mut metadata = anon_text_paste_metadata(&paste_id);
    metadata["pin_verifier"] = serde_json::Value::String("A".repeat(1024 * 1024));

    let resp = post_paste_with_raw_metadata(&client, &base_url, metadata.to_string()).await;
    assert_eq!(resp.status(), 400);

    assert_paste_not_stored(&mut con, &paste_id).await;
}

/// A small, well-formed pin_verifier with has_pin false must also be rejected.
/// The metadata field stays far below the size cap, so only the has_pin rule
/// can cause the 400.
async fn test_small_pin_verifier_rejected_when_has_pin_false() {
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let paste_id = nanoid::nanoid!(12);
    let mut metadata = anon_text_paste_metadata(&paste_id);
    metadata["pin_verifier"] =
        serde_json::Value::String(general_purpose::STANDARD.encode([7u8; 32]));
    let body = metadata.to_string();
    assert!(body.len() < 1024, "metadata must stay well under the cap");

    let resp = post_paste_with_raw_metadata(&client, &base_url, body).await;
    assert_eq!(resp.status(), 400);

    assert_paste_not_stored(&mut con, &paste_id).await;
}

/// A 'metadata' field larger than 16 KB must be rejected before parsing.
async fn test_metadata_field_size_capped() {
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let paste_id = nanoid::nanoid!(12);
    let mut metadata = anon_text_paste_metadata(&paste_id);
    // Unknown fields are ignored by serde, so only the size cap can reject this.
    metadata["padding"] = serde_json::Value::String("A".repeat(17 * 1024));
    let body = metadata.to_string();
    assert!(body.len() > 16 * 1024);

    let resp = post_paste_with_raw_metadata(&client, &base_url, body).await;
    assert_eq!(resp.status(), 400);

    assert_paste_not_stored(&mut con, &paste_id).await;
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

    // Admin can access /admin.html via __Host-np_session cookie
    let resp = client
        .get(format!("{}/admin.html", base_url))
        .header("cookie", format!("__Host-np_session={}", admin_token))
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
        .header("cookie", format!("__Host-np_session={}", admin_token))
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

fn cache_control(resp: &reqwest::Response) -> String {
    resp.headers()
        .get("cache-control")
        .expect("response must set cache-control")
        .to_str()
        .unwrap()
        .to_string()
}

/// Gated pages must not be stored by browsers or shared caches.
async fn test_protected_pages_are_no_store() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    for path in routes::PROTECTED_PATHS {
        let resp = client
            .get(format!("{}{}", base_url, path))
            .header("cookie", format!("__Host-np_session={}", admin_token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{}", path);
        assert_eq!(cache_control(&resp), "no-store, private", "{}", path);
    }
}

/// Auth failures on gated pages must not be cached either.
async fn test_protected_pages_unauthenticated_no_store() {
    let (base_url, _con, _key, _alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    for path in routes::PROTECTED_PATHS {
        let resp = client
            .get(format!("{}{}", base_url, path))
            .send()
            .await
            .unwrap();
        assert!(
            resp.status() == 401 || resp.status() == 403,
            "{} returned {}",
            path,
            resp.status()
        );
        assert!(cache_control(&resp).contains("no-store"), "{}", path);
    }
}

/// Public pages keep the revalidating cache policy.
async fn test_public_pages_keep_no_cache() {
    let (base_url, _con, _key, _alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    for path in ["/view.html", "/index.html"] {
        let resp = client
            .get(format!("{}{}", base_url, path))
            .send()
            .await
            .unwrap();
        assert_eq!(cache_control(&resp), "public, no-cache", "{}", path);
    }
}

/// Upload payloads whose sizes land exactly on ciphertext bucket boundaries and
/// verify the on-disk file size equals the uploaded byte count exactly.
///
/// Bucket sizes are powers-of-two multiples of 1024 bytes. The AES-256-GCM
/// overhead is 28 bytes (12 IV + 16 tag), so for a bucket of N bytes the
/// plaintext is N-28 bytes, and the total ciphertext is exactly N bytes.
/// Tests two buckets: 1024 (→ 1052 upload bytes) and 4096 (→ 4124 upload bytes).
async fn test_stored_blob_preserves_bucket_size() {
    let (base_url, _con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_with_storage().await;
    let client = reqwest::Client::new();

    // AES-256-GCM overhead: 12 (IV) + 16 (auth tag) = 28 bytes
    const GCM_OVERHEAD: usize = 28;

    for bucket in [1024usize, 4096usize] {
        let upload_len = bucket + GCM_OVERHEAD;
        let payload: Vec<u8> = (0..upload_len).map(|i| (i & 0xff) as u8).collect();

        // Use a fixed paste ID so we can locate the blob on disk
        let paste_id = reserve_id(&client, &base_url).await;
        let encrypted_metadata = general_purpose::STANDARD.encode(b"encrypted-file-metadata");

        let metadata = serde_json::json!({
            "paste_id": paste_id,
            "encrypted_metadata": encrypted_metadata,
            "paste_type": "text",
            "ttl_secs": 3600,
            "burn_after_reading": false,
            "has_pin": false,
        });

        let form = reqwest::multipart::Form::new()
            .part(
                "metadata",
                reqwest::multipart::Part::text(metadata.to_string())
                    .mime_str("application/json")
                    .expect("valid mime type"),
            )
            .part(
                "file",
                reqwest::multipart::Part::bytes(payload.clone())
                    .file_name("encrypted")
                    .mime_str("application/octet-stream")
                    .expect("valid mime type"),
            );

        let resp = client
            .post(format!("{}/api/paste", base_url))
            .multipart(form)
            .send()
            .await
            .expect("Failed to send request");
        assert_eq!(
            resp.status(),
            200,
            "Upload failed for bucket {} (upload_len={})",
            bucket,
            upload_len
        );

        // Assert the server echoed back the paste_id we submitted so the
        // on-disk check below can't silently inspect a different blob.
        let resp_json: serde_json::Value = resp.json().await.expect("response must be JSON");
        assert_eq!(
            resp_json["id"].as_str(),
            Some(paste_id.as_str()),
            "Server returned a different paste id than submitted (bucket={})",
            bucket
        );

        // Blobs are stored at {storage_path}/{id[0..2]}/{id}
        let blob_path = storage_path.join(&paste_id[..2]).join(&paste_id);
        assert!(blob_path.exists(), "blob not found at {:?}", blob_path);
        let on_disk_len = std::fs::metadata(&blob_path)
            .expect("failed to read blob metadata")
            .len() as usize;

        assert_eq!(
            on_disk_len, upload_len,
            "On-disk size mismatch for bucket {} (paste_id={}): expected {}, got {}",
            bucket, paste_id, upload_len, on_disk_len
        );
    }
}

/// An unreadable blob (disk failure, permissions, corruption, etc.) must not
/// present to the client as a missing paste. Simulates an unreadable blob by
/// replacing the blob file with a directory at the same path, which makes
/// `File::open` fail with a real I/O error (EISDIR) rather than NotFound.
/// The paste's metadata is still present in Valkey, so a correct fix returns
/// 500 (server error), not 404 (not found).
async fn test_unreadable_blob_returns_500_not_404() {
    let (base_url, _con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_with_storage().await;
    let client = reqwest::Client::new();

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
    let id = body["id"].as_str().unwrap().to_string();

    // Blobs are stored at {storage_path}/{id[0..2]}/{id}. Replace the file
    // with a directory so File::open fails with a real I/O error instead of
    // NotFound, simulating disk corruption / an unreadable blob.
    let blob_path = storage_path.join(&id[..2]).join(&id);
    assert!(blob_path.exists(), "blob not found at {:?}", blob_path);
    std::fs::remove_file(&blob_path).expect("failed to remove blob file");
    std::fs::create_dir(&blob_path).expect("failed to create directory in place of blob");

    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        500,
        "an unreadable blob must surface as a server error, not a 404 'not found'"
    );
}

/// Lowercase hex SHA-256, the same encoding the server records in
/// `content_sha256`.
fn sha256_hex(bytes: &[u8]) -> String {
    <Sha256 as sha2::Digest>::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
            s
        })
}

/// Read the stored `paste:{id}` record from Valkey as a JSON object.
async fn read_paste_record(
    con: &mut redis::aio::ConnectionManager,
    id: &str,
) -> serde_json::Map<String, serde_json::Value> {
    use redis::AsyncCommands;
    let json: String = con
        .get(format!("paste:{}", id))
        .await
        .expect("paste record missing from Valkey");
    match serde_json::from_str(&json).expect("paste record is not JSON") {
        serde_json::Value::Object(obj) => obj,
        other => panic!("paste record is not a JSON object: {}", other),
    }
}

/// When a PIN paste's Valkey record expires, its blob stays on disk until the
/// cleanup job runs. Paste IDs were once client-chosen, so anyone could then
/// claim the same ID with a new paste that has no PIN. store_paste claims the
/// key before the new blob replaces the old one, so a GET in that window saw
/// the new record (no PIN) next to the OLD blob. The server now issues each ID
/// once; the hash check stays as a second barrier.
///
/// This test builds that window directly: it replaces the record with what
/// store_paste writes for the attacker's paste (no PIN, hash of the
/// attacker's bytes) and leaves the old blob on disk. The old ciphertext must
/// not be served.
async fn test_reclaimed_id_does_not_serve_stale_blob() {
    use redis::AsyncCommands;
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let old_content = b"old pin-protected ciphertext";
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        old_content,
        false,
        3600,
        None,
        true,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();

    // The record an attacker's reclaiming paste would get: no PIN, and the
    // hash of the attacker's (not yet written) blob.
    let mut record = read_paste_record(&mut con, &id).await;
    record.insert("has_pin".to_string(), serde_json::Value::Bool(false));
    record.insert("pin_verifier".to_string(), serde_json::Value::Null);
    record.insert(
        "content_sha256".to_string(),
        serde_json::Value::String(sha256_hex(b"attacker ciphertext")),
    );
    let key = format!("paste:{}", id);
    let _: () = con.del(&key).await.unwrap();
    let _: () = con
        .set_ex(&key, serde_json::Value::Object(record).to_string(), 3600)
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "a blob that does not match the record's hash must not be served"
    );
    let body = resp.bytes().await.unwrap();
    assert!(
        !body.windows(old_content.len()).any(|w| w == old_content),
        "response leaked the old PIN-protected ciphertext"
    );
}

/// A blob on disk whose bytes differ from the hash recorded at create time
/// must not be served.
async fn test_blob_metadata_mismatch_returns_not_found() {
    let (base_url, _con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_with_storage().await;
    let client = reqwest::Client::new();

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
    let id = body["id"].as_str().unwrap().to_string();

    // Blobs are stored at {storage_path}/{id[0..2]}/{id}.
    let blob_path = storage_path.join(&id[..2]).join(&id);
    assert!(blob_path.exists(), "blob not found at {:?}", blob_path);
    let other_bytes = b"some other paste's ciphertext";
    std::fs::write(&blob_path, other_bytes).expect("failed to overwrite blob");

    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "a blob that does not match the record's hash must not be served"
    );
    let body = resp.bytes().await.unwrap();
    assert!(
        !body.windows(other_bytes.len()).any(|w| w == other_bytes),
        "response served the mismatched blob"
    );
}

/// Records written before `content_sha256` existed have no hash. They must
/// still be served, or old pastes (including admin forever pastes) become
/// unreadable.
async fn test_legacy_meta_without_content_hash_is_still_served() {
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let content = b"legacy encrypted data";
    let resp = create_paste(
        &client, &base_url, "text", content, false, 3600, None, false,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();

    // Drop the hash field, keeping the key's TTL (KEEPTTL).
    let mut record = read_paste_record(&mut con, &id).await;
    assert!(
        record.remove("content_sha256").is_some(),
        "stored record should carry content_sha256"
    );
    let key = format!("paste:{}", id);
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(serde_json::Value::Object(record).to_string())
        .arg("KEEPTTL")
        .query_async(&mut con)
        .await
        .unwrap();
    let ttl: i64 = redis::cmd("TTL")
        .arg(&key)
        .query_async(&mut con)
        .await
        .unwrap();
    assert!(ttl > 0, "TTL was not kept (got {})", ttl);

    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "legacy record must still be served");
    let (_meta, served) = parse_paste_frame(&resp.bytes().await.unwrap());
    assert_eq!(served, content);
}

/// Create a paste, then rewrite its record the way it looked before
/// server-side PIN gating: no `has_pin` and no `pin_verifier` keys.
/// Returns the paste ID and the path of its blob.
async fn create_legacy_pre_pin_gate_paste(
    client: &reqwest::Client,
    base_url: &str,
    con: &mut redis::aio::ConnectionManager,
    storage_path: &std::path::Path,
    burn: bool,
) -> (String, std::path::PathBuf) {
    let resp = create_paste(
        client,
        base_url,
        "text",
        b"pre-pin-gate ciphertext",
        burn,
        3600,
        None,
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();

    let mut record = read_paste_record(con, &id).await;
    assert!(record.remove("has_pin").is_some());
    record.remove("pin_verifier");
    let _: () = redis::cmd("SET")
        .arg(format!("paste:{}", id))
        .arg(serde_json::Value::Object(record).to_string())
        .arg("KEEPTTL")
        .query_async(con)
        .await
        .unwrap();

    let blob_path = storage_path.join(&id[..2]).join(&id);
    (id, blob_path)
}

async fn assert_legacy_get_refused_and_kept(burn: bool) {
    use redis::AsyncCommands;
    let (base_url, mut con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_with_storage().await;
    let client = reqwest::Client::new();
    let (id, blob_path) =
        create_legacy_pre_pin_gate_paste(&client, &base_url, &mut con, &storage_path, burn).await;

    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "a record without has_pin must not be served"
    );

    let record_exists: bool = con.exists(format!("paste:{}", id)).await.unwrap();
    assert!(record_exists, "refused legacy record was deleted");
    assert!(blob_path.exists(), "refused legacy blob was deleted");
}

async fn test_legacy_meta_without_has_pin_is_refused() {
    assert_legacy_get_refused_and_kept(false).await;
}

async fn test_legacy_burn_meta_without_has_pin_is_not_consumed() {
    assert_legacy_get_refused_and_kept(true).await;
}

async fn test_legacy_meta_without_has_pin_attempt_returns_404() {
    let (base_url, mut con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_with_storage().await;
    let client = reqwest::Client::new();
    let (id, _blob_path) =
        create_legacy_pre_pin_gate_paste(&client, &base_url, &mut con, &storage_path, false).await;

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

/// A GET that finds a blob not matching the record's hash must not consume a
/// burn-after-reading paste. This happens, for example, when a GET lands after
/// a new paste claims the ID but before its blob replaces a stale one. The
/// record must stay in place, so the paste can be read once its real blob is
/// on disk.
async fn test_mismatched_burn_paste_is_not_consumed() {
    let (base_url, mut con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_with_storage().await;
    let client = reqwest::Client::new();

    let content = b"burn after reading ciphertext";
    let resp = create_paste(&client, &base_url, "text", content, true, 3600, None, false).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();

    // Blobs are stored at {storage_path}/{id[0..2]}/{id}.
    let blob_path = storage_path.join(&id[..2]).join(&id);
    let original = std::fs::read(&blob_path).expect("failed to read blob");
    std::fs::write(&blob_path, b"stale blob from an earlier paste")
        .expect("failed to overwrite blob");

    let url = format!("{}/api/paste/{}", base_url, id);
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 404, "a mismatched blob must not be served");

    let exists: bool = redis::cmd("EXISTS")
        .arg(format!("paste:{}", id))
        .query_async(&mut con)
        .await
        .unwrap();
    assert!(exists, "a mismatched read must not consume the burn paste");

    std::fs::write(&blob_path, &original).expect("failed to restore blob");

    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200, "restored paste must be served once");
    let (_meta, served) = parse_paste_frame(&resp.bytes().await.unwrap());
    assert_eq!(served, content);

    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 404, "burn paste must be gone after one read");
}

/// A record whose `content_sha256` is JSON null is not a legacy record (those
/// have no field at all). The check must fail closed and not serve it.
async fn test_meta_with_null_content_hash_is_not_served() {
    let (base_url, mut con, _admin_key, _admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();

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
    let id = body["id"].as_str().unwrap().to_string();

    // Set the hash field to JSON null, keeping the key's TTL (KEEPTTL).
    let mut record = read_paste_record(&mut con, &id).await;
    record.insert("content_sha256".to_string(), serde_json::Value::Null);
    let _: () = redis::cmd("SET")
        .arg(format!("paste:{}", id))
        .arg(serde_json::Value::Object(record).to_string())
        .arg("KEEPTTL")
        .query_async(&mut con)
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "a record with a null content hash must not be served"
    );
}

async fn login_set_cookie(
    client: &reqwest::Client,
    base_url: &str,
    alias: &str,
    key: &SigningKey,
) -> String {
    let (challenge_id, nonce) = request_challenge(client, base_url, alias).await;
    let sig_b64 = general_purpose::STANDARD.encode(key.sign(&nonce).to_bytes());
    let resp = send_verify(client, base_url, alias, &challenge_id, &sig_b64).await;
    assert_eq!(resp.status(), 200);
    resp.headers()
        .get("set-cookie")
        .expect("verify response must set the session cookie")
        .to_str()
        .unwrap()
        .to_string()
}

fn cookie_attributes(cookie: &str) -> Vec<String> {
    cookie
        .split(';')
        .skip(1)
        .map(|a| a.trim().to_string())
        .collect()
}

/// Login verify endpoint sets __Host-np_session cookie with correct attributes.
/// The test server is plain HTTP with no proxy headers, so this also shows the
/// cookie is Secure when the request carries no HTTPS signal.
async fn test_login_sets_host_prefixed_session_cookie() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    assert!(base_url.starts_with("http://"));
    let client = reqwest::Client::new();
    let cookie = login_set_cookie(&client, &base_url, &admin_alias, &admin_key).await;

    let token_value = cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("__Host-np_session=")
        .expect("cookie should set __Host-np_session");
    assert_eq!(token_value.len(), 44, "session token should be 44 chars");
    let attrs = cookie_attributes(&cookie);
    for expected in ["HttpOnly", "SameSite=Strict", "Secure", "Path=/"] {
        assert!(
            attrs.iter().any(|a| a == expected),
            "missing {expected}: {cookie}"
        );
    }
    assert!(
        !attrs
            .iter()
            .any(|a| a.to_ascii_lowercase().starts_with("domain")),
        "cookie must not set Domain: {cookie}"
    );
}

/// The unprefixed np_session cookie is ignored, as if no cookie were sent.
async fn test_legacy_np_session_cookie_not_accepted() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    let without_cookie = client
        .get(format!("{}/admin.html", base_url))
        .send()
        .await
        .unwrap();
    let with_legacy = client
        .get(format!("{}/admin.html", base_url))
        .header("cookie", format!("np_session={}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(with_legacy.status(), 401);
    assert_eq!(with_legacy.status(), without_cookie.status());
    assert_eq!(
        with_legacy.text().await.unwrap(),
        without_cookie.text().await.unwrap()
    );
}

/// Logout clears __Host-np_session with the attributes the prefix requires.
async fn test_logout_clears_host_prefixed_session_cookie() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    let resp = client
        .post(format!("{}/api/auth/logout", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("logout must clear the session cookie")
        .to_str()
        .unwrap();
    assert!(
        cookie.starts_with("__Host-np_session=;"),
        "logout should clear __Host-np_session: {cookie}"
    );
    let attrs = cookie_attributes(cookie);
    for expected in ["Secure", "Path=/", "Max-Age=0"] {
        assert!(
            attrs.iter().any(|a| a == expected),
            "missing {expected}: {cookie}"
        );
    }
}

// ============================================================================
// Blob Read Concurrency Tests
// ============================================================================

/// Size of the paste used to hold a blob read permit. Much larger than the
/// socket buffers, so a response whose body is not read stays in progress.
const LARGE_PASTE_BYTES: usize = 40 * 1024 * 1024;

/// Store a non-PIN paste of `len` bytes straight through the storage layer
/// and return its ID.
async fn store_large_paste(
    con: &mut redis::aio::ConnectionManager,
    storage_path: &std::path::Path,
    len: usize,
) -> String {
    let id = storage::paste::reserve_paste_id(con)
        .await
        .expect("Failed to reserve paste ID");
    let meta = nullpad::models::StoredPasteMeta {
        id: id.clone(),
        encrypted_metadata: general_purpose::STANDARD.encode(b"encrypted-file-metadata"),
        paste_type: nullpad::models::PasteType::default(),
        filename: None,
        content_type: None,
        burn_after_reading: false,
        created_at: 0,
        owner_id: None,
        has_pin: Some(false),
        pin_verifier: None,
        content_sha256: None,
    };
    let mut upload = storage::blob::BlobUpload::create(storage_path)
        .await
        .expect("Failed to create upload");
    upload
        .write(&vec![0x5a; len])
        .await
        .expect("Failed to write upload");
    storage::paste::store_paste(con, storage_path, &meta, upload, 3600, 604800, 50)
        .await
        .expect("Failed to store large paste");
    id
}

/// Send a request until the response is not 503, and return that response.
/// Panics if every response within `limit` is 503.
async fn retry_while_503<F, Fut>(limit: std::time::Duration, mut send: F) -> reqwest::Response
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = reqwest::Result<reqwest::Response>>,
{
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let resp = send().await.unwrap();
        if resp.status() != 503 {
            return resp;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "request still got 503 after {:?}",
            limit
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// GET `url` until it returns 200. Panics if that takes longer than `limit`.
async fn wait_for_get_200(
    client: &reqwest::Client,
    url: &str,
    limit: std::time::Duration,
) -> reqwest::Response {
    let resp = retry_while_503(limit, || client.get(url).send()).await;
    assert_eq!(resp.status(), 200, "GET did not return 200");
    resp
}

async fn test_concurrent_blob_reads_bounded() {
    let (base_url, mut con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_configured(TestServerOverrides {
            max_concurrent_blob_reads: 1,
            ..Default::default()
        })
        .await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let id = store_large_paste(&mut con, &storage_path, LARGE_PASTE_BYTES).await;
    let url = format!("{}/api/paste/{}", base_url, id);

    // Takes the only permit: headers received, body left unread.
    let held = client.get(&url).send().await.unwrap();
    assert_eq!(held.status(), 200);

    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        503,
        "a read with no free permit must get 503"
    );

    drop(held);
    let resp = wait_for_get_200(&client, &url, std::time::Duration::from_secs(10)).await;
    drop(resp);
}

async fn test_stalled_blob_reader_released_by_write_timeout() {
    let (base_url, mut con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_configured(TestServerOverrides {
            max_concurrent_blob_reads: 1,
            write_timeout_secs: 1,
            ..Default::default()
        })
        .await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let id = store_large_paste(&mut con, &storage_path, LARGE_PASTE_BYTES).await;
    let url = format!("{}/api/paste/{}", base_url, id);

    // Kept alive and never read: the server's writes to it stall.
    let held = client.get(&url).send().await.unwrap();
    assert_eq!(held.status(), 200);

    let resp = wait_for_get_200(&client, &url, std::time::Duration::from_secs(10)).await;
    drop(resp);
    drop(held);
}

async fn test_pin_attempt_503_does_not_consume_pin_attempt() {
    let (base_url, mut con, _admin_key, _admin_alias, storage_path) =
        spawn_test_server_configured(TestServerOverrides {
            max_concurrent_blob_reads: 1,
            rate_limit_pin_attempt: 1,
            rate_limit_pin_attempt_global: 1,
            ..Default::default()
        })
        .await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let pin_content = b"pin protected ciphertext";
    let resp = create_paste(
        &client,
        &base_url,
        "text",
        pin_content,
        false,
        3600,
        None,
        true,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let pin_id = body["id"].as_str().unwrap().to_string();
    let verifier = test_pin_verifier(&test_dummy_key(), &pin_id);
    let attempt_url = format!("{}/api/paste/{}", base_url, pin_id);
    let attempt = || {
        client
            .post(&attempt_url)
            .header("Content-Type", "application/json")
            .body(serde_json::json!({ "pin_verifier": verifier }).to_string())
            .send()
    };

    // Hold the only permit with an unread GET of a large paste.
    let large_id = store_large_paste(&mut con, &storage_path, LARGE_PASTE_BYTES).await;
    let held = client
        .get(format!("{}/api/paste/{}", base_url, large_id))
        .send()
        .await
        .unwrap();
    assert_eq!(held.status(), 200);

    let resp = attempt().await.unwrap();
    assert_eq!(
        resp.status(),
        503,
        "a PIN attempt with no free permit must get 503"
    );

    drop(held);

    // The permit is freed once the server sees the dropped connection. A 503
    // while that happens is retried: it must not count as a PIN attempt.
    let resp = retry_while_503(std::time::Duration::from_secs(10), attempt).await;
    assert_eq!(
        resp.status(),
        200,
        "the 503 attempt must not have used up the PIN attempt limit"
    );
    let (_meta, content) = parse_paste_frame(&resp.bytes().await.unwrap());
    assert_eq!(content, pin_content);
}

async fn test_blob_reads_per_ip_capped() {
    let (base_url, mut con, storage_path, client) =
        spawn_trusted_proxy_server(TestServerOverrides::default()).await;
    let id = store_large_paste(&mut con, &storage_path, LARGE_PASTE_BYTES).await;
    let url = format!("{}/api/paste/{}", base_url, id);
    let get = || get_from_ip(&client, &url, "203.0.113.7");

    let mut held = Vec::new();
    for _ in 0..MAX_BLOB_READS_PER_IP {
        let resp = get().await.unwrap();
        assert_eq!(resp.status(), 200);
        held.push(resp);
    }

    let resp = get().await.unwrap();
    assert_eq!(
        resp.status(),
        429,
        "a read over the per-IP cap must get 429"
    );

    drop(held);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let resp = get().await.unwrap();
        if resp.status() == 200 {
            break;
        }
        assert_eq!(resp.status(), 429);
        assert!(
            tokio::time::Instant::now() < deadline,
            "per-IP read slots were not released after the bodies were dropped"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn test_per_ip_cap_leaves_blob_reads_for_other_ips() {
    let (base_url, mut con, storage_path, client) =
        spawn_trusted_proxy_server(TestServerOverrides {
            max_concurrent_blob_reads: MAX_BLOB_READS_PER_IP + 1,
            ..Default::default()
        })
        .await;
    let id = store_large_paste(&mut con, &storage_path, LARGE_PASTE_BYTES).await;
    let url = format!("{}/api/paste/{}", base_url, id);

    // One IP tries to hold every global permit with reads it never finishes.
    let mut held = Vec::new();
    for _ in 0..=MAX_BLOB_READS_PER_IP {
        held.push(get_from_ip(&client, &url, "203.0.113.7").await.unwrap());
    }

    let resp = get_from_ip(&client, &url, "198.51.100.9").await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "one IP at its per-IP cap must not block reads from another IP"
    );
    drop(resp);
    drop(held);
}

async fn test_admin_delete_during_stream_keeps_streamed_bytes() {
    let (base_url, mut con, admin_key, admin_alias, storage_path) =
        spawn_test_server_with_storage().await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    let admin_token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    // Stored through the storage layer: see store_large_paste.
    let len = 8 * 1024 * 1024;
    let id = store_large_paste(&mut con, &storage_path, len).await;
    let url = format!("{}/api/paste/{}", base_url, id);

    // Start the stream: headers and the first chunk only.
    let mut resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp
        .chunk()
        .await
        .unwrap()
        .expect("body should have a first chunk")
        .to_vec();

    let del = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 204, "admin delete should succeed mid-stream");

    while let Some(chunk) = resp.chunk().await.unwrap() {
        body.extend_from_slice(&chunk);
    }
    let (_meta, content) = parse_paste_frame(&body);
    assert_eq!(content.len(), len);
    let changed = content.iter().filter(|&&b| b != 0x5a).count();
    assert_eq!(
        changed, 0,
        "a delete must not change the bytes of a paste that is still streaming"
    );

    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

// ============================================================================
// Request Body Limit Tests
// ============================================================================

/// Larger than axum's default 2 MB body limit, smaller than max_upload_bytes.
const OVER_DEFAULT_LIMIT_BYTES: usize = 3 * 1024 * 1024;

async fn test_oversized_json_body_returns_413() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (base_url, _con, _admin_key, _admin_alias) = spawn_test_server().await;
    let mut stream = tokio::net::TcpStream::connect(base_url.trim_start_matches("http://"))
        .await
        .unwrap();

    // Declare a 3 MB JSON body but send only one byte over the limit. The
    // server has then read all sent bytes when it answers, so closing the
    // connection cannot reset it before the response is read. A client that
    // sends the full 3 MB gets a broken pipe instead of the response.
    let head = format!(
        "POST /api/auth/challenge HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        OVER_DEFAULT_LIMIT_BYTES
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream
        .write_all(&vec![b' '; routes::MAX_JSON_BODY_BYTES + 1])
        .await
        .unwrap();

    let mut status_line = [0u8; 12];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut status_line),
    )
    .await
    .expect("no response within 5 s")
    .unwrap();
    assert_eq!(&status_line, b"HTTP/1.1 413");
}

async fn test_paste_over_default_body_limit_succeeds() {
    let (base_url, _con, admin_key, admin_alias) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;
    let content = vec![0x5a; OVER_DEFAULT_LIMIT_BYTES];

    let resp = create_paste(
        &client,
        &base_url,
        "text",
        &content,
        false,
        3600,
        Some(&token),
        false,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = client
        .get(format!("{}/api/paste/{}", base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let (_meta, stored) = parse_paste_frame(&resp.bytes().await.unwrap());
    assert_eq!(stored, content);
}

async fn test_unfinished_headers_time_out() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (base_url, _con, _admin_key, _admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            header_read_timeout: std::time::Duration::from_secs(1),
            ..Default::default()
        })
        .await;
    let mut stream = tokio::net::TcpStream::connect(base_url.trim_start_matches("http://"))
        .await
        .unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    let closed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut response),
    )
    .await;
    assert!(
        closed.is_ok(),
        "connection with unfinished headers was still open after 5 s"
    );
}

async fn test_idle_keep_alive_closes_after_header_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (base_url, _con, _admin_key, _admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            header_read_timeout: std::time::Duration::from_secs(1),
            ..Default::default()
        })
        .await;
    let mut stream = tokio::net::TcpStream::connect(base_url.trim_start_matches("http://"))
        .await
        .unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    // The request is complete and keep-alive, so only the header read timeout
    // for the next request can close the connection.
    let mut response = Vec::new();
    let closed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut response),
    )
    .await;
    assert!(
        closed.is_ok(),
        "idle keep-alive connection was still open after 5 s"
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
}

/// All files with a `.tmp` extension under `dir`, at any depth.
fn temp_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(temp_files(&path));
        } else if path.extension().is_some_and(|e| e == "tmp") {
            found.push(path);
        }
    }
    found
}

/// Send a multipart body with one field named `field_name`. It declares
/// `2 * limit` bytes but sends only `limit + 1`, so the server has read every
/// sent byte when it answers. Returns the status line.
async fn post_paste_over_limit(base_url: &str, field_name: &str, limit: usize) -> [u8; 12] {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(base_url.trim_start_matches("http://"))
        .await
        .unwrap();
    let part_head = format!(
        "--nullpadboundary\r\nContent-Disposition: form-data; name=\"{}\"; \
         filename=\"encrypted\"\r\nContent-Type: application/octet-stream\r\n\r\n",
        field_name
    );
    let head = format!(
        "POST /api/paste HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: multipart/form-data; boundary=nullpadboundary\r\n\
         Content-Length: {}\r\n\r\n",
        limit * 2
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(part_head.as_bytes()).await.unwrap();
    stream
        .write_all(&vec![0x5a; limit + 1 - part_head.len()])
        .await
        .unwrap();

    let mut status_line = [0u8; 12];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut status_line),
    )
    .await
    .expect("no response within 5 s")
    .unwrap();
    status_line
}

async fn test_upload_over_max_upload_bytes_returns_413() {
    const LIMIT: usize = 64 * 1024;
    let (base_url, _con, _admin_key, _admin_alias, storage) =
        spawn_test_server_configured(TestServerOverrides {
            max_upload_bytes: LIMIT,
            ..Default::default()
        })
        .await;

    let status = post_paste_over_limit(&base_url, "file", LIMIT).await;
    assert_eq!(&status, b"HTTP/1.1 413");
    assert_eq!(temp_files(&storage), Vec::<std::path::PathBuf>::new());

    // An unknown field is skipped while the next field header is read.
    let status = post_paste_over_limit(&base_url, "padding", LIMIT).await;
    assert_eq!(&status, b"HTTP/1.1 413");
}

async fn test_second_file_field_replaces_first() {
    let (base_url, _con, _admin_key, _admin_alias, storage) =
        spawn_test_server_with_storage().await;
    let client = reqwest::Client::new();
    let paste_id = reserve_id(&client, &base_url).await;
    let metadata = serde_json::json!({
        "paste_id": paste_id,
        "encrypted_metadata": general_purpose::STANDARD.encode(b"encrypted-file-metadata"),
        "paste_type": "text",
        "ttl_secs": 3600,
        "burn_after_reading": false,
        "has_pin": false,
    });
    let form = multipart::Form::new()
        .text("metadata", metadata.to_string())
        .part("file", multipart::Part::bytes(vec![0x11; 1024]))
        .part("file", multipart::Part::bytes(vec![0x22; 2048]));

    let resp = client
        .post(format!("{}/api/paste", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(temp_files(&storage), Vec::<std::path::PathBuf>::new());

    let resp = client
        .get(format!("{}/api/paste/{}", base_url, paste_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let (_meta, stored) = parse_paste_frame(&resp.bytes().await.unwrap());
    assert_eq!(stored, vec![0x22; 2048]);
}

/// Open a connection that sends the headers and one byte of a 100-byte JSON
/// body, then waits. The request holds a concurrency slot until it ends.
async fn start_stalled_request(base_url: &str) -> tokio::net::TcpStream {
    use tokio::io::AsyncWriteExt;

    let mut stream = tokio::net::TcpStream::connect(base_url.trim_start_matches("http://"))
        .await
        .unwrap();
    stream
        .write_all(
            b"POST /api/auth/challenge HTTP/1.1\r\nHost: localhost\r\n\
              Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{",
        )
        .await
        .unwrap();
    // Give the server time to route the request and take a slot.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    stream
}

async fn test_slow_request_times_out_with_408() {
    use tokio::io::AsyncReadExt;

    let (base_url, _con, _admin_key, _admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            request_timeout: std::time::Duration::from_secs(1),
            ..Default::default()
        })
        .await;
    let mut stream = start_stalled_request(&base_url).await;

    let mut response = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut buf = [0u8; 1024];
        while !response.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection closed before the response headers");
            response.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("no response within 5 s");
    let head = String::from_utf8_lossy(&response).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 408"), "got: {}", head);
    assert!(
        head.contains("x-content-type-options: nosniff"),
        "408 response lacks security headers: {}",
        head
    );
}

/// The request timeout fires after the store's first write (the reservation
/// DEL) is sent, while a paused Valkey holds it. The SET NX runs after the
/// handler is gone. The paste must still be stored in full and listed under
/// its owner.
async fn test_timeout_after_paste_id_claim_still_records_owner() {
    use redis::AsyncCommands;
    use tokio::io::AsyncWriteExt;

    let (base_url, mut con, admin_key, admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            request_timeout: std::time::Duration::from_secs(1),
            ..Default::default()
        })
        .await;
    let client = reqwest::Client::new();
    let token = admin_login(&client, &base_url, &admin_alias, &admin_key).await;

    let paste_id = reserve_id(&client, &base_url).await;
    let metadata = serde_json::json!({
        "paste_id": paste_id,
        "encrypted_metadata": general_purpose::STANDARD.encode(b"encrypted-file-metadata"),
        "paste_type": "text",
        "ttl_secs": 3600,
        "burn_after_reading": false,
        "has_pin": false,
    });
    let body = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{}\r\n\
         --b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"encrypted\"\r\n\
         Content-Type: application/octet-stream\r\n\r\ncontent\r\n--b--\r\n",
        metadata
    );
    let mut stream = tokio::net::TcpStream::connect(base_url.trim_start_matches("http://"))
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "POST /api/paste HTTP/1.1\r\nHost: localhost\r\n\
                 Authorization: Bearer {}\r\n\
                 Content-Type: multipart/form-data; boundary=b\r\n\
                 Content-Length: {}\r\n\r\n",
                token,
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    // The reservation DEL is sent at about 800 ms and held by the pause. The 1 s request
    // timeout drops the handler at 1000 ms. Writes resume at about 1150 ms,
    // inside the 500 ms Valkey response timeout of the server's connection.
    // `con` shares the server's Valkey connection, so UNPAUSE on it would queue
    // behind the held DEL.
    let mut control = redis::Client::open(get_valkey_url())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    redis::cmd("CLIENT")
        .arg("PAUSE")
        .arg(2000)
        .arg("WRITE")
        .query_async::<()>(&mut control)
        .await
        .unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(350)).await;
    redis::cmd("CLIENT")
        .arg("UNPAUSE")
        .query_async::<()>(&mut control)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let stored: bool = con.exists(format!("paste:{}", paste_id)).await.unwrap();
    assert!(stored, "SET NX never ran; the timeout landed before it");
    let listed: bool = con.sismember("user_pastes:admin", &paste_id).await.unwrap();
    assert!(listed, "paste stored but missing from user_pastes");
    let resp = client
        .get(format!("{}/api/paste/{}", base_url, paste_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

async fn test_concurrency_limit_queues_requests() {
    let (base_url, _con, _admin_key, _admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            max_concurrent_requests: 1,
            ..Default::default()
        })
        .await;
    let client = reqwest::Client::new();
    let stalled = start_stalled_request(&base_url).await;

    let queued = client
        .get(format!("{}/api/config", base_url))
        .timeout(std::time::Duration::from_secs(1))
        .send()
        .await;
    assert!(
        queued.is_err_and(|e| e.is_timeout()),
        "request was handled while the only slot was taken"
    );

    drop(stalled);
    let resp = client
        .get(format!("{}/api/config", base_url))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

async fn test_healthz_not_blocked_by_concurrency_limit() {
    let (base_url, _con, _admin_key, _admin_alias, _storage) =
        spawn_test_server_configured(TestServerOverrides {
            max_concurrent_requests: 1,
            ..Default::default()
        })
        .await;
    let _stalled = start_stalled_request(&base_url).await;

    let resp = reqwest::Client::new()
        .get(format!("{}/healthz", base_url))
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
        .expect("healthz waited for a concurrency slot");
    assert_eq!(resp.status(), 200);
}

/// Live blobs are never removed, so they keep their place in directory order.
/// With more live blobs than one cleanup cycle used to examine, orphans past
/// that point must still be reclaimed.
async fn test_cleanup_reclaims_all_orphans_beyond_cap() {
    use redis::AsyncCommands;
    let mut con = redis::Client::open(get_valkey_url())
        .unwrap()
        .get_connection_manager()
        .await
        .unwrap();
    let storage_path = storage_root().join(format!("cleanup_{}", nanoid::nanoid!(8)));
    let blob_path = |id: &str| storage_path.join(&id[..2]).join(id);

    let live_ids: Vec<String> = (0..1200).map(|_| nanoid::nanoid!(10)).collect();
    let orphan_ids: Vec<String> = (0..200).map(|_| nanoid::nanoid!(10)).collect();
    for id in live_ids.iter().chain(&orphan_ids) {
        std::fs::create_dir_all(storage_path.join(&id[..2])).unwrap();
        std::fs::write(blob_path(id), b"ciphertext").unwrap();
    }
    for id in &live_ids {
        let _: () = con
            .set_ex(format!("paste:{}", id), "1", 3600)
            .await
            .unwrap();
    }

    for _ in 0..3 {
        cleanup::cleanup_orphaned_files(&mut con, &storage_path)
            .await
            .unwrap();
    }

    let orphans_left = orphan_ids
        .iter()
        .filter(|id| blob_path(id).exists())
        .count();
    let live_missing = live_ids.iter().filter(|id| !blob_path(id).exists()).count();
    for id in &live_ids {
        let _: () = con.del(format!("paste:{}", id)).await.unwrap();
    }
    let _ = std::fs::remove_dir_all(&storage_path);

    assert_eq!(
        orphans_left, 0,
        "orphans past the per-cycle cap were not reclaimed"
    );
    assert_eq!(live_missing, 0, "cleanup deleted live blobs");
}
