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

  // ============================================================================
  // URL Parsing
  // ============================================================================

  function parseUrl() {
    // Extract paste ID from pathname: /view.html?id=xxxxx or /p/xxxxx
    const params = new URLSearchParams(window.location.search);
    pasteId = params.get('id');

    // Extract encryption key from fragment: #key
    const fragment = window.location.hash.substring(1);
    encryptionKey = fragment || null;

    if (!pasteId || !encryptionKey) {
      showError('Invalid paste URL. Missing ID or encryption key.');
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
      encryptedData = data.content;
      metadata = {
        burn: data.burn || false,
        filename: data.filename || null,
        mimetype: data.mimetype || null
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
      // Derive key with PIN if provided
      let decryptionKey = encryptionKey;
      if (pin) {
        decryptionKey = await NullpadCrypto.deriveKeyWithPin(encryptionKey, pin);
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

      if (isMarkdown && typeof marked !== 'undefined') {
        // Render as markdown (marked.js is safe from XSS)
        const html = marked.parse(decrypted.content);
        contentDisplay.innerHTML = html;
        contentDisplay.classList.add('markdown-body');

        // Highlight code blocks
        if (typeof hljs !== 'undefined') {
          contentDisplay.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightElement(block);
          });
        }
      } else {
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

    try {
      const decrypted = await decryptPaste(pin);
      showContent(decrypted);
    } catch (err) {
      alert('Invalid PIN. Please try again.');
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
      const originalText = copyContentBtn.textContent;
      copyContentBtn.textContent = 'Copied!';

      setTimeout(() => {
        copyContentBtn.textContent = originalText;
      }, 2000);
    }).catch(err => {
      console.error('Failed to copy:', err);
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

      // Try to decrypt without PIN first
      try {
        const decrypted = await decryptPaste();
        showContent(decrypted);
      } catch (err) {
        // Decryption failed - probably needs PIN
        showPinPrompt();
      }
    } catch (err) {
      showError(err.message);
    }
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  function init() {
    // Set up event listeners
    pinForm.addEventListener('submit', handlePinSubmit);
    downloadBtn.addEventListener('click', handleDownload);
    copyContentBtn.addEventListener('click', handleCopyContent);

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
