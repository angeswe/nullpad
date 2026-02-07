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

  // ============================================================================
  // URL Parsing
  // ============================================================================

  // Salt for PIN derivation (from URL fragment)
  let pinSalt = null;

  function parseUrl() {
    // Extract paste ID from query: /view.html?id=xxxxx
    const params = new URLSearchParams(window.location.search);
    pasteId = params.get('id');

    // Try URL fragment first, fall back to sessionStorage (survives reload)
    const fragment = window.location.hash.substring(1);
    const storageKey = pasteId ? 'np_' + pasteId : null;
    const keySource = fragment || (storageKey && sessionStorage.getItem(storageKey)) || '';

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

    // Stash key material in sessionStorage so reloads work within same tab
    if (storageKey && keySource) {
      try { sessionStorage.setItem(storageKey, keySource); } catch (e) { /* quota or private mode */ }
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

  const purifyConfig = {
    ALLOWED_TAGS: [
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'br', 'hr',
      'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
      'em', 'strong', 'del', 's', 'a',
      'table', 'thead', 'tbody', 'tr', 'th', 'td',
      'div', 'span', 'sup', 'sub', 'details', 'summary',
      'dl', 'dt', 'dd', 'kbd', 'mark', 'abbr', 'img'
    ],
    ALLOWED_ATTR: [
      'href', 'src', 'alt', 'title', 'class',
      'align', 'colspan', 'rowspan', 'scope', 'open'
    ],
    ALLOW_DATA_ATTR: false,
    RETURN_DOM_FRAGMENT: true
  };

  function canRenderMarkdown() {
    return typeof marked !== 'undefined' && typeof DOMPurify !== 'undefined';
  }

  function renderMarkdownView(text) {
    const rawHtml = marked.parse(text);
    // Allow class only on <code> elements (for highlight.js syntax themes)
    DOMPurify.addHook('uponSanitizeAttribute', function(node, data) {
      if (data.attrName === 'class' && node.tagName !== 'CODE') {
        data.keepAttr = false;
      }
    });
    // Force external links to open in new tab with noopener
    DOMPurify.addHook('afterSanitizeAttributes', function(node) {
      if (node.tagName === 'A' && node.hasAttribute('href')) {
        const href = node.getAttribute('href');
        if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
          node.setAttribute('target', '_blank');
          node.setAttribute('rel', 'noopener noreferrer');
        }
      }
    });
    try {
      const fragment = DOMPurify.sanitize(rawHtml, purifyConfig);
      contentDisplay.replaceChildren();
      contentDisplay.appendChild(fragment);
    } finally {
      DOMPurify.removeAllHooks();
    }
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
      const img = document.createElement('img');
      img.src = URL.createObjectURL(blob);
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
