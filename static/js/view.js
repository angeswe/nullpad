/**
 * Nullpad View Module
 * Handles paste decryption and rendering
 */

(function() {
  'use strict';

  // DOM elements
  const burnWarning = document.getElementById('burn-warning');
  const pinPrompt = document.getElementById('pin-prompt');
  const pinForm = document.getElementById('pin-form');
  const pinInput = document.getElementById('pin');
  const loading = document.getElementById('loading');
  const errorPanel = document.getElementById('error-panel');
  const errorMessage = document.getElementById('error-message');
  const contentPanel = document.getElementById('content-panel');
  const contentDisplay = document.getElementById('content-display');
  const rawContent = document.getElementById('raw-content');
  const downloadBtn = document.getElementById('download-btn');
  const copyContentBtn = document.getElementById('copy-content-btn');
  const toggleMarkdownBtn = document.getElementById('toggle-markdown-btn');
  const burnNotice = document.getElementById('burn-notice');

  // State
  let pasteId = null;
  let encryptionKey = null;
  let encryptedData = null;
  let metadata = null;
  let decryptedBytes = null;
  let decryptedText = null;
  let showingMarkdown = false;
  let pinAttempts = 0;
  let pinBackoffUntil = 0;
  let clipboardDirty = false;
  let imageBlobUrl = null;
  let useAttemptEndpoint = false;
  let contentFetched = false;

  function sanitizeFilename(name) {
    return name
      .replace(/[/\\]/g, '_')         // strip path separators
      .replace(/[\x00-\x1f\x7f]/g, '') // strip null bytes and control chars
      .slice(0, 255)                    // truncate to 255 chars
      || 'file';                        // fallback if empty after sanitization
  }

  // ============================================================================
  // URL Parsing
  // ============================================================================

  // Salt for PIN derivation (from URL fragment)
  let pinSalt = null;

  function parseUrl() {
    // Extract paste ID from query: /view.html?id=xxxxx
    const params = new URLSearchParams(window.location.search);
    pasteId = params.get('id');

    // Key material lives only in URL fragment and in-memory variables — never persisted
    const fragment = window.location.hash.substring(1);
    const keySource = fragment || '';

    if (keySource && keySource.includes('.')) {
      const parts = keySource.split('.');
      if (parts.length !== 2 || !parts[0] || !parts[1]) {
        showError('Invalid paste URL format.');
        return false;
      }
      try {
        encryptionKey = NullpadCrypto.base64urlDecode(parts[0]);
      } catch (e) {
        showError('Invalid paste URL: corrupt key encoding.');
        return false;
      }
      try {
        pinSalt = NullpadCrypto.base64urlDecode(parts[1]);
        if (pinSalt.length !== 16) {
          showError('Invalid paste URL: bad salt.');
          return false;
        }
      } catch (e) {
        showError('Invalid paste URL: corrupt salt encoding.');
        return false;
      }
    } else {
      try {
        encryptionKey = keySource ? NullpadCrypto.base64urlDecode(keySource) : null;
      } catch (e) {
        showError('Invalid paste URL: corrupt key encoding.');
        return false;
      }
    }

    if (!pasteId || !encryptionKey) {
      showError('Invalid paste URL. Missing ID or encryption key.');
      return false;
    }

    // Validate encryption key length (must be 32 bytes for AES-256-GCM)
    if (encryptionKey.length !== 32) {
      showError('Invalid paste URL: key must be 256 bits.');
      return false;
    }

    // Validate paste ID format (nanoid: 12 chars, alphanumeric + hyphen + underscore)
    if (!/^[A-Za-z0-9_-]{12}$/.test(pasteId)) {
      showError('Invalid paste ID format.');
      return false;
    }

    // Clear key material from URL bar and browser history
    if (fragment && window.history && window.history.replaceState) {
      window.history.replaceState(null, '', window.location.pathname + window.location.search);
    }

    return true;
  }

  // ============================================================================
  // Fetch Paste
  // ============================================================================

  async function fetchPaste() {
    try {
      const response = await fetch(`/api/paste/${pasteId}`);

      if (!response.ok) {
        // Try to parse JSON error, fall back to status-based message
        let errorMessage;
        try {
          const error = await response.json();
          errorMessage = error.error;
        } catch {
          // Response wasn't JSON (proxy error, network issue, etc.)
        }
        if (!errorMessage) {
          if (response.status === 404) {
            errorMessage = 'Paste not found or has expired';
          } else if (response.status === 429) {
            errorMessage = 'Too many requests. Please wait.';
          } else {
            errorMessage = 'Server error (' + response.status + ')';
          }
        }
        throw new Error(errorMessage);
      }

      const data = await response.json();
      encryptedData = data.encrypted_content;
      metadata = {
        burn: data.burn_after_reading || false,
        filename: data.filename || null,
        mimetype: data.content_type || null,
        encrypted_metadata: data.encrypted_metadata || null
      };

      return data;
    } catch (err) {
      throw new Error(err.message || 'Failed to fetch paste');
    }
  }

  async function fetchAttempt() {
    const response = await fetch(`/api/paste/${pasteId}`, { method: 'POST' });

    if (!response.ok) {
      if (response.status === 429) {
        const retryAfter = response.headers.get('retry-after');
        const waitMsg = retryAfter ? `Wait ${retryAfter}s` : 'Please wait';
        throw new Error(`Too many attempts. ${waitMsg} before trying again.`);
      }
      let msg;
      try {
        const err = await response.json();
        msg = err.error;
      } catch { /* non-JSON */ }
      throw new Error(msg || 'Failed to fetch paste');
    }

    const data = await response.json();
    if (!data.encrypted_content) {
      throw new Error('Server returned incomplete response');
    }
    encryptedData = data.encrypted_content;
    metadata = {
      burn: data.burn_after_reading || false,
      filename: data.filename || null,
      mimetype: data.content_type || null,
      encrypted_metadata: data.encrypted_metadata || null
    };
    contentFetched = true;
    return data;
  }

  // ============================================================================
  // Decryption
  // ============================================================================

  // Minimum encrypted payload: 12-byte IV + 16-byte GCM auth tag = 28 bytes
  const MIN_ENCRYPTED_BYTES = 28;

  async function decryptPaste(pin = null) {
    try {
      // Validate encrypted data minimum length before attempting decryption
      const decoded = NullpadCrypto.base64Decode(encryptedData);
      if (decoded.length < MIN_ENCRYPTED_BYTES) {
        throw new Error('Encrypted data too short');
      }

      // Derive key with PIN if provided (pass existing salt from URL)
      let decryptionKey = encryptionKey;
      if (pin) {
        const derived = await NullpadCrypto.deriveKeyWithPin(encryptionKey, pin, pinSalt);
        decryptionKey = derived.key;
      }

      // Decrypt encrypted_metadata if present (new format: filename/content_type are encrypted)
      if (metadata.encrypted_metadata) {
        try {
          const metaBytes = await NullpadCrypto.decrypt(metadata.encrypted_metadata, decryptionKey, pasteId);
          const fileMeta = JSON.parse(new TextDecoder().decode(metaBytes));
          if (typeof fileMeta.filename === 'string') metadata.filename = fileMeta.filename;
          if (typeof fileMeta.content_type === 'string') metadata.mimetype = fileMeta.content_type;
        } catch {
          // Fallback to server-provided plaintext metadata (legacy pastes)
        }
      }

      // Try decryption with paste ID as AAD first (new format),
      // fall back to without AAD (backward compat for old pastes)
      let bytes;
      try {
        bytes = await NullpadCrypto.decrypt(encryptedData, decryptionKey, pasteId);
      } catch {
        // Fallback to non-AAD decryption (backward compat for old pastes)
        bytes = await NullpadCrypto.decrypt(encryptedData, decryptionKey);
      }

      // Store decrypted bytes for download
      decryptedBytes = bytes;

      // Try strict UTF-8 decode — throws on invalid bytes (binary files)
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        return { type: 'text', content: text, bytes: bytes };
      } catch {
        return { type: 'binary', content: null, bytes: bytes };
      }
    } catch (err) {
      throw new Error('Decryption failed. Invalid key or PIN.');
    }
  }

  // ============================================================================
  // Rendering
  // ============================================================================

  // DOMPurify is defense-in-depth; the primary mitigation for img/src injection
  // is the CSP header: `default-src 'self'; img-src 'self' data:` which blocks
  // loading external resources even if DOMPurify were bypassed.
  const purifyConfig = {
    ALLOWED_TAGS: [
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'br', 'hr',
      'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
      'em', 'strong', 'del', 's', 'a',
      'table', 'thead', 'tbody', 'tr', 'th', 'td',
      'div', 'span', 'sup', 'sub', 'details', 'summary',
      'dl', 'dt', 'dd', 'kbd', 'mark', 'abbr'
    ],
    ALLOWED_ATTR: [
      'href', 'alt', 'title', 'class',
      'align', 'colspan', 'rowspan', 'scope', 'open'
    ],
    ALLOW_DATA_ATTR: false,
    RETURN_DOM_FRAGMENT: true
  };

  // Private DOMPurify instance (avoids hook accumulation on global singleton)
  const purify = (typeof DOMPurify !== 'undefined') ? DOMPurify(window) : null;

  // One-time hook setup on private instance
  if (purify) {
    // Allow class only on <code> elements (for highlight.js syntax themes)
    purify.addHook('uponSanitizeAttribute', function(node, data) {
      if (data.attrName === 'class' && node.tagName !== 'CODE') {
        data.keepAttr = false;
      }
    });
    // Force external links to open in new tab with noopener
    purify.addHook('afterSanitizeAttributes', function(node) {
      if (node.tagName === 'A' && node.hasAttribute('href')) {
        const href = node.getAttribute('href');
        if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
          node.setAttribute('target', '_blank');
          node.setAttribute('rel', 'noopener noreferrer');
        }
      }
    });
  }

  function canRenderMarkdown() {
    return typeof marked !== 'undefined' && purify !== null;
  }

  function renderMarkdownView(text) {
    const rawHtml = marked.parse(text);
    const fragment = purify.sanitize(rawHtml, purifyConfig);
    contentDisplay.replaceChildren();
    contentDisplay.appendChild(fragment);
    contentDisplay.classList.add('markdown-body');
    contentDisplay.classList.remove('hidden');
    rawContent.classList.add('hidden');

    if (typeof hljs !== 'undefined') {
      contentDisplay.querySelectorAll('pre code').forEach((block) => {
        hljs.highlightElement(block);
      });
    }

    showingMarkdown = true;
    toggleMarkdownBtn.textContent = 'Raw';
  }

  function renderRawView(text) {
    rawContent.textContent = text;
    rawContent.classList.remove('hidden');
    contentDisplay.classList.add('hidden');
    contentDisplay.classList.remove('markdown-body');

    showingMarkdown = false;
    toggleMarkdownBtn.textContent = 'Markdown';
  }

  function toggleMarkdown() {
    if (!decryptedText) return;
    if (showingMarkdown) {
      renderRawView(decryptedText);
    } else {
      renderMarkdownView(decryptedText);
    }
  }

  function renderContent(decrypted) {
    if (decrypted.type === 'text') {
      decryptedText = decrypted.content;

      const isFileUpload = metadata.filename && metadata.filename !== 'paste.md';
      if (canRenderMarkdown()) {
        if (isFileUpload) toggleMarkdownBtn.classList.remove('hidden');
        renderMarkdownView(decrypted.content);
      } else {
        renderRawView(decrypted.content);
      }

      copyContentBtn.classList.remove('hidden');
    } else if (metadata.mimetype && metadata.mimetype.startsWith('image/')) {
      // Image file - display inline
      const blob = new Blob([decrypted.bytes], { type: metadata.mimetype });
      imageBlobUrl = URL.createObjectURL(blob);
      const img = document.createElement('img');
      img.src = imageBlobUrl;
      img.alt = metadata.filename || 'Image';
      img.style.maxWidth = '100%';
      contentDisplay.appendChild(img);
      downloadBtn.classList.remove('hidden');
    } else {
      // Binary file - show download button
      const msg = document.createElement('p');
      msg.className = 'text-muted';
      msg.textContent = 'Binary file. Click download to save.';
      contentDisplay.appendChild(msg);
      downloadBtn.classList.remove('hidden');
    }

    if (metadata.filename) {
      downloadBtn.classList.remove('hidden');
    }
  }

  // ============================================================================
  // UI State Management
  // ============================================================================

  function showError(message) {
    loading.classList.add('hidden');
    loading.setAttribute('aria-busy', 'false');
    pinPrompt.classList.add('hidden');
    errorPanel.classList.remove('hidden');
    errorMessage.textContent = message;
  }

  function showPinPrompt() {
    loading.classList.add('hidden');
    loading.setAttribute('aria-busy', 'false');
    pinPrompt.classList.remove('hidden');
  }

  function showContent(decrypted) {
    loading.classList.add('hidden');
    loading.setAttribute('aria-busy', 'false');
    pinPrompt.classList.add('hidden');
    contentPanel.classList.remove('hidden');

    renderContent(decrypted);

    if (metadata.burn) {
      burnNotice.classList.remove('hidden');
    }
  }

  // ============================================================================
  // Event Handlers
  // ============================================================================

  async function handlePinSubmit(e) {
    e.preventDefault();

    const pin = pinInput.value.trim();
    if (!pin) return;

    // Enforce exponential backoff on failed PIN attempts
    const now = Date.now();
    if (now < pinBackoffUntil) {
      const waitSecs = Math.ceil((pinBackoffUntil - now) / 1000);
      let errEl = pinPrompt.querySelector('.pin-error');
      if (!errEl) {
        errEl = document.createElement('div');
        errEl.className = 'pin-error status-error';
        errEl.setAttribute('role', 'alert');
        pinForm.parentNode.insertBefore(errEl, pinForm);
      }
      errEl.textContent = `Too many attempts. Wait ${waitSecs}s before trying again.`;
      return;
    }

    try {
      // Fetch content from server if PIN-gated and not yet fetched
      if (useAttemptEndpoint && !contentFetched) {
        try {
          await fetchAttempt();
        } catch (fetchErr) {
          // Server-side error (429, 404, etc.) — show directly, don't count as PIN attempt
          let errEl = pinPrompt.querySelector('.pin-error');
          if (!errEl) {
            errEl = document.createElement('div');
            errEl.className = 'pin-error status-error';
            errEl.setAttribute('role', 'alert');
            pinForm.parentNode.insertBefore(errEl, pinForm);
          }
          errEl.textContent = fetchErr.message;
          return;
        }
      }

      const decrypted = await decryptPaste(pin);
      showContent(decrypted);
    } catch (err) {
      pinAttempts++;
      // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s max
      const delaySecs = Math.min(Math.pow(2, pinAttempts - 1), 30);
      pinBackoffUntil = Date.now() + delaySecs * 1000;

      // Show burn warning — paste is gone server-side but ciphertext is in memory
      if (metadata.burn && contentFetched) {
        let warnEl = pinPrompt.querySelector('.pin-burn-warning');
        if (!warnEl) {
          warnEl = document.createElement('div');
          warnEl.className = 'pin-burn-warning status-error';
          warnEl.setAttribute('role', 'alert');
          pinForm.parentNode.insertBefore(warnEl, pinForm);
        }
        warnEl.textContent = 'Wrong PIN. This paste is one-time — if you close this page, it will be gone forever.';
      }

      let errEl = pinPrompt.querySelector('.pin-error');
      if (!errEl) {
        errEl = document.createElement('div');
        errEl.className = 'pin-error status-error';
        errEl.setAttribute('role', 'alert');
        pinForm.parentNode.insertBefore(errEl, pinForm);
      }
      const remainingSecs = Math.ceil((pinBackoffUntil - Date.now()) / 1000);
      errEl.textContent = pinAttempts >= 3
        ? `Invalid PIN. Wait ${remainingSecs}s before next attempt.`
        : 'Invalid PIN. Please try again.';
      pinInput.value = '';
      pinInput.focus();
    }
  }

  function handleDownload() {
    if (!decryptedBytes || !metadata.filename) return;

    // Create blob and download
    const blob = new Blob([decryptedBytes], { type: metadata.mimetype || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = sanitizeFilename(metadata.filename);
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleCopyContent() {
    // Copy visible content to clipboard
    const textToCopy = rawContent.classList.contains('hidden')
      ? contentDisplay.textContent
      : rawContent.textContent;

    navigator.clipboard.writeText(textToCopy).then(() => {
      clipboardDirty = true;
      const originalText = copyContentBtn.textContent;
      copyContentBtn.textContent = 'Copied!';

      setTimeout(() => {
        copyContentBtn.textContent = originalText;
      }, 2000);
    }).catch(() => {
      alert('Failed to copy content.');
    });
  }

  // ============================================================================
  // Main Flow
  // ============================================================================

  async function loadPaste() {
    // Parse URL
    if (!parseUrl()) return;

    // Show burn warning if this is a burn-after-reading paste
    // (we don't know yet, will check after fetch)

    try {
      // Fetch encrypted paste
      const data = await fetchPaste();

      // Server-side PIN gating: content withheld until POST attempt
      if (data.needs_pin) {
        useAttemptEndpoint = true;
        metadata = { burn: data.burn_after_reading || false };
        if (metadata.burn) {
          burnWarning.classList.remove('hidden');
        }
        showPinPrompt();
        return;
      }

      // Show burn warning if applicable
      if (metadata.burn) {
        burnWarning.classList.remove('hidden');
      }

      // If salt is present in URL, we know it's PIN-protected
      if (pinSalt) {
        showPinPrompt();
      } else {
        // Try to decrypt without PIN first
        try {
          const decrypted = await decryptPaste();
          showContent(decrypted);
        } catch (err) {
          // Decryption failed - probably needs PIN
          showPinPrompt();
        }
      }
    } catch (err) {
      showError(err.message);
    }
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  function clearSensitiveData() {
    // SECURITY: String references (decryptedText, sessionStorage copies) cannot be wiped from JS heap
    // Revoke image blob URL to free decrypted image from memory
    if (imageBlobUrl) {
      URL.revokeObjectURL(imageBlobUrl);
      imageBlobUrl = null;
    }
    // Zero out Uint8Array buffers
    if (decryptedBytes instanceof Uint8Array) {
      decryptedBytes.fill(0);
    }
    if (encryptionKey instanceof Uint8Array) {
      encryptionKey.fill(0);
    }
    if (pinSalt instanceof Uint8Array) {
      pinSalt.fill(0);
    }
    // Null out references to sensitive data
    decryptedBytes = null;
    decryptedText = null;
    encryptionKey = null;
    encryptedData = null;
    pinSalt = null;
    metadata = null;
    useAttemptEndpoint = false;
    contentFetched = false;
    pinAttempts = 0;
    pinBackoffUntil = 0;
    // Best-effort clipboard clear (may fail without user gesture)
    if (clipboardDirty && navigator.clipboard) {
      navigator.clipboard.writeText('').catch(() => {});
      clipboardDirty = false;
    }
  }

  function init() {
    // Set up event listeners
    pinForm.addEventListener('submit', handlePinSubmit);
    downloadBtn.addEventListener('click', handleDownload);
    copyContentBtn.addEventListener('click', handleCopyContent);
    toggleMarkdownBtn.addEventListener('click', toggleMarkdown);

    // Zero sensitive data on page unload
    window.addEventListener('pagehide', clearSensitiveData);

    // Load paste
    loadPaste();
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
