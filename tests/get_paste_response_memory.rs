//! Memory regression test for the paste GET response path.
//!
//! GET /api/paste/{id} used to read the whole blob into memory, base64 encode
//! it, and serialize it again through `axum::Json`. That held about five
//! copies of the blob at once per request.
//!
//! This test runs the same steps the handler now runs:
//!   1. `storage::blob::open_blob` (opens and hashes the file in chunks)
//!   2. `routes::paste::paste_frame_response` (builds the streaming frame)
//!   3. drains the response body chunk by chunk, as hyper does
//!
//! A counting global allocator records the peak number of live heap bytes.
//! The peak above the starting point must stay at or below 1.5x the blob
//! size. A streaming response needs only one chunk buffer at a time.
//!
//! No Valkey is required.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct TrackingAlloc;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let cur = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(cur, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            if new_size > layout.size() {
                let delta = new_size - layout.size();
                let cur = CURRENT.fetch_add(delta, Ordering::SeqCst) + delta;
                PEAK.fetch_max(cur, Ordering::SeqCst);
            } else {
                let delta = layout.size() - new_size;
                CURRENT.fetch_sub(delta, Ordering::SeqCst);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL: TrackingAlloc = TrackingAlloc;

#[tokio::test]
async fn get_paste_response_peak_memory_is_bounded() {
    use futures::StreamExt;
    use nullpad::models::GetPasteResponse;
    use nullpad::routes::paste::{encode_frame_prefix, paste_frame_response};
    use nullpad::storage::blob;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::Semaphore;

    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path();
    blob::init_storage(storage_path).await.unwrap();

    // 8 MiB keeps the test fast. The old path's ratio did not depend on size.
    let blob_size: usize = 8 * 1024 * 1024;
    let id = "memtest000012";
    let content = vec![0xABu8; blob_size];
    blob::write_blob(storage_path, id, &content).await.unwrap();
    drop(content);

    let meta = GetPasteResponse {
        encrypted_metadata: Some("dGVzdC1tZXRhZGF0YS1ibG9i".to_string()),
        filename: None,
        content_type: None,
        burn_after_reading: false,
        created_at: Some(1_700_000_000),
        needs_pin: None,
    };
    let prefix_len = encode_frame_prefix(&meta).unwrap().len();
    let permits = Arc::new(Semaphore::new(1));

    // Start measuring from here.
    PEAK.store(CURRENT.load(Ordering::SeqCst), Ordering::SeqCst);
    let baseline = CURRENT.load(Ordering::SeqCst);

    // Step 1: open and hash the blob.
    let opened = blob::open_blob(storage_path, id, blob_size as u64)
        .await
        .unwrap()
        .expect("blob should exist");
    assert_eq!(opened.len, blob_size as u64);

    // Step 2: build the response exactly as get_paste does.
    let permit = permits.clone().try_acquire_owned().unwrap();
    let response = paste_frame_response(&meta, Some((opened, permit))).unwrap();

    // Step 3: drain the body one chunk at a time, dropping each chunk.
    let mut stream = response.into_body().into_data_stream();
    let mut drained: usize = 0;
    while let Some(chunk) = stream.next().await {
        drained += chunk.unwrap().len();
    }
    drop(stream);

    let peak = PEAK.load(Ordering::SeqCst);
    let peak_extra = peak.saturating_sub(baseline);
    let ratio = peak_extra as f64 / blob_size as f64;
    eprintln!(
        "blob_size={blob_size} peak_extra_bytes={peak_extra} ratio={ratio:.3}x drained={drained}"
    );

    assert_eq!(
        drained,
        prefix_len + blob_size,
        "the body must be the 4-byte length, the JSON meta, then the whole blob"
    );
    assert!(
        peak_extra as f64 <= 1.5 * blob_size as f64,
        "GET response path is not streaming: peak extra memory was {ratio:.2}x the blob size \
         ({peak_extra} bytes for a {blob_size}-byte blob), expected <=1.5x"
    );
}
