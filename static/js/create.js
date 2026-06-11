/**
 * Nullpad Create Module
 * Handles paste creation UI and encryption workflow
 *
 * URL fragment format:
 * - No PIN: #key (base64url)
 * - With PIN: #key.salt (base64url key + "." + base64url salt)
 */

(function() {
  'use strict';

  // DOM elements
  const form = document.getElementById('paste-form');
  const contentTextarea = document.getElementById('content');
  const pinInput = document.getElementById('pin');
  const burnCheckbox = document.getElementById('burn-after-reading');
  const ttlSelect = document.getElementById('ttl');
  const fileUploadArea = document.getElementById('file-upload-area');
  const fileInput = document.getElementById('file-input');
  const fileInfo = document.getElementById('file-info');
  const successPanel = document.getElementById('success-panel');
  const pasteUrlInput = document.getElementById('paste-url');
  const copyBtn = document.getElementById('copy-btn');
  const createAnotherBtn = document.getElementById('create-another-btn');
  const burnNotice = document.getElementById('burn-notice');
  const pinNotice = document.getElementById('pin-notice');
  const submitBtn = form ? form.querySelector('button[type="submit"]') : null;

  // State
  let currentFile = null;
  let clipboardDirty = false;
  let maxUploadBytes = null; // loaded from /api/config on init

  // ============================================================================
  // File Upload Handling (trusted users only - public page has no file upload)
  // ============================================================================

  function setupFileUpload() {
    if (!fileUploadArea) return;

    fileUploadArea.addEventListener('click', () => {
      fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
      }
    });

    fileUploadArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      fileUploadArea.classList.add('drag-over');
    });

    fileUploadArea.addEventListener('dragleave', () => {
      fileUploadArea.classList.remove('drag-over');
    });

    fileUploadArea.addEventListener('drop', (e) => {
      e.preventDefault();
      fileUploadArea.classList.remove('drag-over');
      if (e.dataTransfer.files.length > 0) {
        handleFile(e.dataTransfer.files[0]);
      }
    });
  }

  function handleFile(file) {
    currentFile = file;
    fileInfo.textContent = `Selected: ${file.name} (${formatFileSize(file.size)})`;
    fileInfo.classList.remove('hidden');
    contentTextarea.value = '';
    contentTextarea.disabled = true;
  }

  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  // ============================================================================
  // Form Submission
  // ============================================================================

  async function handleSubmit(e) {
    e.preventDefault();

    // Validate input
    const text = contentTextarea.value.trim();
    if (!text && !currentFile) {
      contentTextarea.focus();
      return;
    }

    // Check file size before encrypting (limit sourced from server at init)
    if (currentFile && maxUploadBytes !== null && currentFile.size > maxUploadBytes) {
      const sizeMB = (currentFile.size / (1024 * 1024)).toFixed(1);
      const limitMB = (maxUploadBytes / (1024 * 1024)).toFixed(0);
      const errEl = document.createElement('div');
      errEl.className = 'status-error';
      errEl.setAttribute('role', 'alert');
      errEl.textContent = `File too large (${sizeMB}MB). Maximum is ${limitMB}MB.`;
      form.prepend(errEl);
      setTimeout(() => errEl.remove(), 5000);
      return;
    }

    // Disable submit while processing
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Encrypting...';
      form.setAttribute('aria-busy', 'true');
    }

    try {
      // 1. Generate encryption key
      const rawKey = NullpadCrypto.generateKey();

      // 2. Derive key with PIN if provided, get salt
      // SECURITY: String keys (rawKey, encryptionKey) persist in memory until GC (JS strings are immutable)
      let encryptionKey = rawKey;
      let salt = null;
      const pin = pinInput.value.trim();
      if (pin && pin.length < 4) {
        const errEl = document.createElement('div');
        errEl.className = 'status-error';
        errEl.setAttribute('role', 'alert');
        errEl.textContent = 'PIN must be at least 4 characters.';
        form.prepend(errEl);
        setTimeout(() => errEl.remove(), 5000);
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Create Encrypted Paste';
        }
        form.setAttribute('aria-busy', 'false');
        return;
      }
      if (pin) {
        const derived = await NullpadCrypto.deriveKeyWithPin(rawKey, pin);
        encryptionKey = derived.key;
        salt = derived.salt;
      }

      // 3. Get content bytes
      let contentBytes;
      let filename;
      let contentType;

      if (currentFile) {
        contentBytes = new Uint8Array(await currentFile.arrayBuffer());
        filename = NullpadUtils.sanitizeFilename(currentFile.name);
        contentType = currentFile.type || 'application/octet-stream';
      } else {
        contentBytes = NullpadCrypto.textEncode(text);
        filename = 'paste.md';
        contentType = 'text/markdown';
      }

      // 4. Generate paste ID client-side (used as AAD for AES-GCM binding)
      const clientPasteId = NullpadCrypto.generateId();

      // Pre-flight size check: ensure the framed content will fit the top bucket.
      // contentPadTarget returns null when no bucket can hold the framed length,
      // which encrypt() would also catch — this early check avoids allocating a
      // large buffer first.
      {
        const { AES_GCM_OVERHEAD, V1_HEADER_LEN, contentPadTarget } = NullpadCrypto;
        const framedLen = contentBytes.length + V1_HEADER_LEN;
        const serverCap = (maxUploadBytes !== null ? maxUploadBytes : 52428800);
        const topBucket = serverCap - AES_GCM_OVERHEAD;
        if (contentPadTarget(framedLen) === null || framedLen >= topBucket) {
          const limitMB = ((serverCap - AES_GCM_OVERHEAD - V1_HEADER_LEN) / (1024 * 1024)).toFixed(0);
          throw new Error(`Content too large: exceeds maximum supported upload size. Maximum is ${limitMB}MB.`);
        }
      }

      // 5. Encrypt content with paste ID as AAD, padded to the content bucket ladder.
      // Bucket selection uses "strictly greater than framed length" so equal-to-bucket
      // inputs are pushed to the next bucket, preventing a no-padding side channel.
      const encrypted = await NullpadCrypto.encrypt(
        contentBytes, encryptionKey, clientPasteId, { pad: 'content' }
      );
      const encryptedBytes = NullpadCrypto.base64Decode(encrypted);

      // 6. Encrypt filename and content_type to prevent metadata leakage.
      // Padded to the next multiple of 512 strictly greater than the framed length,
      // hiding filename-length fingerprinting. Worst-case ciphertext ~1403 base64
      // bytes — well within the server's 4096-byte encrypted_metadata cap.
      const fileMetadata = JSON.stringify({ filename: filename, content_type: contentType });
      const encryptedMetadata = await NullpadCrypto.encrypt(
        NullpadCrypto.textEncode(fileMetadata), encryptionKey, clientPasteId, { pad: 'metadata' }
      );

      // 7. Compute PIN verifier for server-side validation (if PIN set)
      let pinVerifier = null;
      if (pin) {
        pinVerifier = await NullpadCrypto.computePinVerifier(encryptionKey, clientPasteId);
      }

      // 8. Prepare metadata (plaintext fields for server, encrypted blob for client)
      const metadata = JSON.stringify({
        paste_id: clientPasteId,
        encrypted_metadata: encryptedMetadata,
        paste_type: currentFile ? 'file' : 'text',
        ttl_secs: parseInt(ttlSelect.value, 10),
        burn_after_reading: burnCheckbox.checked,
        has_pin: !!pin,
        pin_verifier: pinVerifier
      });

      // 9. Build multipart request
      const formData = new FormData();
      formData.append('metadata', new Blob([metadata], { type: 'application/json' }));
      formData.append('file', new Blob([encryptedBytes], { type: 'application/octet-stream' }), 'encrypted');

      // Include auth header if logged in
      const headers = {};
      if (typeof NullpadAuth !== 'undefined') {
        const authHeader = NullpadAuth.getAuthHeader();
        if (authHeader) {
          headers['Authorization'] = authHeader;
        }
      }

      // 10. POST to API
      const response = await fetch('/api/paste', {
        method: 'POST',
        headers: headers,
        body: formData
      });

      if (response.status === 401) {
        if (typeof NullpadAuth !== 'undefined') NullpadAuth.clearSession();
        window.location.href = '/login.html';
        return;
      }

      if (!response.ok) {
        let msg;
        try {
          const err = await response.json();
          msg = err.error;
        } catch { /* non-JSON response */ }
        throw new Error(msg || 'Failed to create paste');
      }

      const result = await response.json();

      // 11. Build URL with key fragment
      const fragment = salt
        ? `${rawKey}.${NullpadCrypto.base64urlEncode(salt)}`
        : rawKey;
      const pasteUrl = `${window.location.origin}/view.html?id=${result.id}#${fragment}`;

      // Zero salt after use
      if (salt instanceof Uint8Array) {
        salt.fill(0);
      }

      showSuccess(pasteUrl, !!pin, burnCheckbox.checked);
    } catch (err) {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Encrypted Paste';
      }
      form.setAttribute('aria-busy', 'false');
      // Show error inline instead of alert
      const errEl = document.createElement('div');
      errEl.className = 'status-error';
      errEl.setAttribute('role', 'alert');
      errEl.textContent = err.message;
      form.prepend(errEl);
      setTimeout(() => errEl.remove(), 5000);
    }
  }

  // ============================================================================
  // Success Panel
  // ============================================================================

  function showSuccess(url, hasPIN, isBurn) {
    form.setAttribute('aria-busy', 'false');
    form.classList.add('hidden');
    successPanel.classList.remove('hidden');
    pasteUrlInput.value = url;

    if (isBurn) {
      burnNotice.classList.remove('hidden');
    }
    if (hasPIN) {
      pinNotice.classList.remove('hidden');
    }
  }

  function resetForm() {
    form.reset();
    pasteUrlInput.value = '';
    currentFile = null;
    if (fileInfo) fileInfo.classList.add('hidden');
    contentTextarea.disabled = false;

    successPanel.classList.add('hidden');
    form.classList.remove('hidden');

    burnNotice.classList.add('hidden');
    pinNotice.classList.add('hidden');

    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create Encrypted Paste';
    }
  }

  // ============================================================================
  // Copy to Clipboard
  // ============================================================================

  function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
      clipboardDirty = true;
      const originalText = copyBtn.textContent;
      copyBtn.textContent = 'Copied!';
      copyBtn.classList.add('btn-primary');
      copyBtn.classList.remove('btn-secondary');

      setTimeout(() => {
        copyBtn.textContent = originalText;
        copyBtn.classList.remove('btn-primary');
        copyBtn.classList.add('btn-secondary');
      }, 2000);
    }).catch(() => {});
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  async function init() {
    // Fetch server config to keep the client-side size pre-flight in sync with
    // the server limit. On failure we fall back to the 50MiB default constant
    // (same value baked into the crypto module). This is deliberate: the pre-flight
    // is best-effort UX only — the server enforces the real limit authoritatively
    // and any 413/400 rejection during upload surfaces through the existing error
    // path in handleSubmit (the !response.ok branch throws and shows an inline error).
    try {
      const res = await fetch('/api/config');
      if (res.ok) {
        const cfg = await res.json();
        if (typeof cfg.max_upload_bytes === 'number') {
          maxUploadBytes = cfg.max_upload_bytes;
        }
      }
    } catch (e) { console.warn('Failed to fetch server config:', e.message); }

    setupFileUpload();
    form.addEventListener('submit', handleSubmit);
    copyBtn.addEventListener('click', () => {
      copyToClipboard(pasteUrlInput.value);
    });
    createAnotherBtn.addEventListener('click', resetForm);

    // Clear clipboard and sensitive data on page unload
    window.addEventListener('pagehide', () => {
      if (clipboardDirty) {
        navigator.clipboard.writeText('').catch(() => {});
        clipboardDirty = false;
      }
      // Clear sensitive DOM values (paste URL contains key in fragment)
      pinInput.value = '';
      pasteUrlInput.value = '';
      currentFile = null;
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
