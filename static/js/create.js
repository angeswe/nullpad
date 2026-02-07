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

    // Check file size before encrypting (50MB default server limit)
    const MAX_UPLOAD_BYTES = 52_428_800;
    if (currentFile && currentFile.size > MAX_UPLOAD_BYTES) {
      const sizeMB = (currentFile.size / (1024 * 1024)).toFixed(1);
      const limitMB = (MAX_UPLOAD_BYTES / (1024 * 1024)).toFixed(0);
      const errEl = document.createElement('div');
      errEl.className = 'status-error';
      errEl.textContent = `File too large (${sizeMB}MB). Maximum is ${limitMB}MB.`;
      form.prepend(errEl);
      setTimeout(() => errEl.remove(), 5000);
      return;
    }

    // Disable submit while processing
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Encrypting...';
    }

    try {
      // 1. Generate encryption key
      const rawKey = NullpadCrypto.generateKey();

      // 2. Derive key with PIN if provided, get salt
      // SECURITY: String keys (rawKey, encryptionKey) persist in memory until GC (JS strings are immutable)
      let encryptionKey = rawKey;
      let salt = null;
      const pin = pinInput.value.trim();
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
        filename = currentFile.name;
        contentType = currentFile.type || 'application/octet-stream';
      } else {
        contentBytes = NullpadCrypto.textEncode(text);
        filename = 'paste.md';
        contentType = 'text/markdown';
      }

      // 4. Encrypt content
      const encrypted = await NullpadCrypto.encrypt(contentBytes, encryptionKey);
      const encryptedBytes = NullpadCrypto.base64Decode(encrypted);

      // 5. Prepare metadata
      const metadata = JSON.stringify({
        filename: filename,
        content_type: contentType,
        ttl_secs: parseInt(ttlSelect.value, 10),
        burn_after_reading: burnCheckbox.checked
      });

      // 6. Build multipart request
      const formData = new FormData();
      formData.append('metadata', new Blob([metadata], { type: 'application/json' }));
      formData.append('file', new Blob([encryptedBytes], { type: 'application/octet-stream' }), filename);

      // Include auth header if logged in
      const headers = {};
      if (typeof NullpadAuth !== 'undefined') {
        const authHeader = NullpadAuth.getAuthHeader();
        if (authHeader) {
          headers['Authorization'] = authHeader;
        }
      }

      // 7. POST to API
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
        const err = await response.json();
        throw new Error(err.error || 'Failed to create paste');
      }

      const result = await response.json();

      // 8. Build URL with key fragment
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
      // Show error inline instead of alert
      const errEl = document.createElement('div');
      errEl.className = 'status-error';
      errEl.textContent = err.message;
      form.prepend(errEl);
      setTimeout(() => errEl.remove(), 5000);
    }
  }

  // ============================================================================
  // Success Panel
  // ============================================================================

  function showSuccess(url, hasPIN, isBurn) {
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

  function init() {
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
