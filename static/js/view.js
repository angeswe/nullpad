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
  const burnNotice = document.getElementById('burn-notice');

  // State
  let pasteId = null;
  let encryptionKey = null;
  let encryptedData = null;
  let metadata = null;
  let decryptedBytes = null;
  let pinAttempts = 0;
  let pinBackoffUntil = 0;
  let clipboardDirty = false;

  // ============================================================================
  // URL Parsing
  // ============================================================================

  // Salt for PIN derivation (from URL fragment)
  let pinSalt = null;

  function parseUrl() {
    // Extract paste ID from query: /view.html?id=xxxxx
    const params = new URLSearchParams(window.location.search);
    pasteId = params.get('id');

    // Extract encryption key (and optional salt) from fragment
    // Format: #key or #key.salt
    const fragment = window.location.hash.substring(1);
    if (fragment && fragment.includes('.')) {
      const parts = fragment.split('.');
      if (parts.length !== 2 || !parts[0] || !parts[1]) {
        showError('Invalid paste URL format.');
        return false;
      }
      encryptionKey = parts[0];
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
      encryptionKey = fragment || null;
    }

    if (!pasteId || !encryptionKey) {
      showError('Invalid paste URL. Missing ID or encryption key.');
      return false;
    }

    // Validate paste ID format (nanoid: 12 chars, alphanumeric + hyphen + underscore)
    if (!/^[A-Za-z0-9_-]{12}$/.test(pasteId)) {
      showError('Invalid paste ID format.');
      return false;
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
        const error = await response.json();
        throw new Error(error.error || 'Failed to fetch paste');
      }

      const data = await response.json();
      encryptedData = data.encrypted_content;
      metadata = {
        burn: data.burn_after_reading || false,
        filename: data.filename || null,
        mimetype: data.content_type || null
      };

      return data;
    } catch (err) {
      throw new Error('Failed to fetch paste: ' + err.message);
    }
  }

  // ============================================================================
  // Decryption
  // ============================================================================

  async function decryptPaste(pin = null) {
    try {
      // Derive key with PIN if provided (pass existing salt from URL)
      let decryptionKey = encryptionKey;
      if (pin) {
        const derived = await NullpadCrypto.deriveKeyWithPin(encryptionKey, pin, pinSalt);
        decryptionKey = derived.key;
      }

      // Decrypt content
      const bytes = await NullpadCrypto.decrypt(encryptedData, decryptionKey);

      // Store decrypted bytes for download
      decryptedBytes = bytes;

      // TODO: Determine if content is text or binary based on metadata
      // For now, try to decode as text
      try {
        const text = NullpadCrypto.textDecode(bytes);
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

  function renderContent(decrypted) {
    if (decrypted.type === 'text') {
      // Check if it's markdown (based on filename or content)
      const isMarkdown = metadata.filename?.endsWith('.md') ||
                        metadata.mimetype === 'text/markdown';

      if (isMarkdown && typeof marked !== 'undefined' && typeof DOMPurify !== 'undefined') {
        // Render markdown, then sanitize with DOMPurify using strict allowlist
        const rawHtml = marked.parse(decrypted.content);
        const purifyConfig = {
          ALLOWED_TAGS: [
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'br', 'hr',
            'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
            'em', 'strong', 'del', 's', 'a', 'img',
            'table', 'thead', 'tbody', 'tr', 'th', 'td',
            'div', 'span', 'sup', 'sub', 'details', 'summary',
            'dl', 'dt', 'dd', 'kbd', 'mark', 'abbr'
          ],
          ALLOWED_ATTR: [
            'href', 'src', 'alt', 'title', 'class',
            'align', 'colspan', 'rowspan', 'scope', 'open'
          ],
          ALLOW_DATA_ATTR: false
        };
        // DOMPurify.sanitize() returns safe HTML — this is the intended usage pattern
        contentDisplay.innerHTML = DOMPurify.sanitize(rawHtml, purifyConfig);
        contentDisplay.classList.add('markdown-body');

        // Highlight code blocks
        if (typeof hljs !== 'undefined') {
          contentDisplay.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightElement(block);
          });
        }
      } else {
        // Fall back to plain text if DOMPurify not available (safe default)
        // Render as plain text
        rawContent.textContent = decrypted.content;
        rawContent.classList.remove('hidden');
        contentDisplay.classList.add('hidden');
      }

      // Show copy button
      copyContentBtn.classList.remove('hidden');
    } else {
      // Binary file - show download button
      const msg = document.createElement('p');
      msg.className = 'text-muted';
      msg.textContent = 'Binary file. Click download to save.';
      contentDisplay.appendChild(msg);
      downloadBtn.classList.remove('hidden');
    }

    // Show download button if filename exists
    if (metadata.filename) {
      downloadBtn.classList.remove('hidden');
    }
  }

  // ============================================================================
  // UI State Management
  // ============================================================================

  function showError(message) {
    loading.classList.add('hidden');
    pinPrompt.classList.add('hidden');
    errorPanel.classList.remove('hidden');
    errorMessage.textContent = message;
  }

  function showPinPrompt() {
    loading.classList.add('hidden');
    pinPrompt.classList.remove('hidden');
  }

  function showContent(decrypted) {
    loading.classList.add('hidden');
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
      let errEl = pinPrompt.querySelector('.status-error');
      if (!errEl) {
        errEl = document.createElement('div');
        errEl.className = 'status-error';
        pinForm.parentNode.insertBefore(errEl, pinForm);
      }
      errEl.textContent = `Too many attempts. Wait ${waitSecs}s before trying again.`;
      return;
    }

    try {
      const decrypted = await decryptPaste(pin);
      showContent(decrypted);
    } catch (err) {
      pinAttempts++;
      // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s max
      const delaySecs = Math.min(Math.pow(2, pinAttempts - 1), 30);
      pinBackoffUntil = Date.now() + delaySecs * 1000;

      let errEl = pinPrompt.querySelector('.status-error');
      if (!errEl) {
        errEl = document.createElement('div');
        errEl.className = 'status-error';
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
    a.download = metadata.filename;
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
      await fetchPaste();

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
    // Zero out Uint8Array buffers
    if (decryptedBytes instanceof Uint8Array) {
      decryptedBytes.fill(0);
    }
    if (pinSalt instanceof Uint8Array) {
      pinSalt.fill(0);
    }
    // Null out references to sensitive data
    decryptedBytes = null;
    encryptionKey = null;
    encryptedData = null;
    pinSalt = null;
    metadata = null;
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
