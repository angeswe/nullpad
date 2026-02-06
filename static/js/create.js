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
  // File Type Validation (client-side only - server can't check encrypted content)
  // ============================================================================

  // Magic bytes for common binary formats
  const BINARY_SIGNATURES = [
    { bytes: [0x89, 0x50, 0x4E, 0x47], name: 'PNG image' },
    { bytes: [0xFF, 0xD8, 0xFF], name: 'JPEG image' },
    { bytes: [0x47, 0x49, 0x46, 0x38], name: 'GIF image' },
    { bytes: [0x25, 0x50, 0x44, 0x46], name: 'PDF document' },
    { bytes: [0x50, 0x4B, 0x03, 0x04], name: 'ZIP archive' },
    { bytes: [0x50, 0x4B, 0x05, 0x06], name: 'ZIP archive (empty)' },
    { bytes: [0x1F, 0x8B], name: 'GZIP archive' },
    { bytes: [0x42, 0x5A, 0x68], name: 'BZIP2 archive' },
    { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], name: '7-Zip archive' },
    { bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], name: 'RAR archive' },
    { bytes: [0x7F, 0x45, 0x4C, 0x46], name: 'ELF executable' },
    { bytes: [0x4D, 0x5A], name: 'Windows executable' },
    { bytes: [0xCA, 0xFE, 0xBA, 0xBE], name: 'Java class file' },
    { bytes: [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20], name: 'JPEG 2000' },
    { bytes: [0x00, 0x00, 0x01, 0x00], name: 'ICO image' },
    { bytes: [0x49, 0x44, 0x33], name: 'MP3 audio' },
    { bytes: [0x66, 0x4C, 0x61, 0x43], name: 'FLAC audio' },
    { bytes: [0x4F, 0x67, 0x67, 0x53], name: 'OGG audio' },
    { bytes: [0x52, 0x49, 0x46, 0x46], name: 'RIFF (WAV/AVI)' },
    { bytes: [0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70], name: 'MP4/MOV video' },
    { bytes: [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70], name: 'MP4/MOV video' },
    { bytes: [0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70], name: 'MP4/MOV video' },
    { bytes: [0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70], name: 'MP4/MOV video' },
    { bytes: [0x1A, 0x45, 0xDF, 0xA3], name: 'WebM/MKV video' },
    { bytes: [0x38, 0x42, 0x50, 0x53], name: 'PSD image' },
    { bytes: [0x49, 0x49, 0x2A, 0x00], name: 'TIFF image' },
    { bytes: [0x4D, 0x4D, 0x00, 0x2A], name: 'TIFF image' },
    { bytes: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], name: 'MS Office document' },
  ];

  const PUBLIC_ALLOWED_EXTENSIONS = ['txt', 'md'];

  function isAuthenticated() {
    return typeof NullpadAuth !== 'undefined' && NullpadAuth.getAuthHeader() !== null;
  }

  function getFileExtension(filename) {
    const parts = filename.split('.');
    return parts.length > 1 ? parts.pop().toLowerCase() : '';
  }

  async function detectBinaryFormat(file) {
    const maxBytes = Math.max(...BINARY_SIGNATURES.map(s => s.bytes.length));
    const slice = file.slice(0, maxBytes);
    const buffer = await slice.arrayBuffer();
    const bytes = new Uint8Array(buffer);

    for (const sig of BINARY_SIGNATURES) {
      if (sig.bytes.length <= bytes.length) {
        let match = true;
        for (let i = 0; i < sig.bytes.length; i++) {
          if (bytes[i] !== sig.bytes[i]) {
            match = false;
            break;
          }
        }
        if (match) return sig.name;
      }
    }
    return null;
  }

  async function validateFileForPublic(file) {
    const ext = getFileExtension(file.name);

    // Check extension
    if (!PUBLIC_ALLOWED_EXTENSIONS.includes(ext)) {
      return { valid: false, error: `File type ".${ext}" not allowed. Public uploads accept only .txt and .md files.` };
    }

    // Check magic bytes
    const binaryFormat = await detectBinaryFormat(file);
    if (binaryFormat) {
      return { valid: false, error: `File appears to be a ${binaryFormat}, not a text file. Rename won't help - content is checked.` };
    }

    return { valid: true };
  }

  // ============================================================================
  // File Upload Handling
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

  async function handleFile(file) {
    // Clear any previous file error
    const existingError = form.querySelector('.file-error');
    if (existingError) existingError.remove();

    // Validate file type for public (unauthenticated) users
    if (!isAuthenticated()) {
      const validation = await validateFileForPublic(file);
      if (!validation.valid) {
        const errEl = document.createElement('div');
        errEl.className = 'status-error file-error';
        errEl.textContent = validation.error;
        form.prepend(errEl);
        fileInput.value = '';
        return;
      }
    }

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
    fileInfo.classList.add('hidden');
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
      // Clear PIN field
      pinInput.value = '';
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
