/**
 * Nullpad Create Module
 * Handles paste creation UI and encryption workflow
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

  // State
  let currentFile = null;

  // ============================================================================
  // File Upload Handling
  // ============================================================================

  function setupFileUpload() {
    // Click to browse
    fileUploadArea.addEventListener('click', () => {
      fileInput.click();
    });

    // File selected via browse
    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
      }
    });

    // Drag and drop
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
    // TODO: Implement file type validation for public vs trusted mode
    // For public: only .md and .txt
    // For trusted: any file type

    currentFile = file;

    // Show file info
    fileInfo.textContent = `Selected: ${file.name} (${formatFileSize(file.size)})`;
    fileInfo.classList.remove('hidden');

    // Clear textarea when file is selected
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

    // TODO: Implement paste creation flow
    // 1. Generate encryption key using NullpadCrypto.generateKey()
    // 2. If PIN provided, derive new key with NullpadCrypto.deriveKeyWithPin()
    // 3. Get content (either from textarea or currentFile)
    // 4. Encrypt content using NullpadCrypto.encrypt()
    // 5. Prepare request payload with metadata (burn, ttl, etc.)
    // 6. POST to /api/paste with Authorization header if authenticated
    // 7. On success, construct URL with key fragment and show success panel

    console.log('TODO: Implement paste creation');
    console.log('Content:', contentTextarea.value);
    console.log('File:', currentFile);
    console.log('PIN:', pinInput.value);
    console.log('Burn:', burnCheckbox.checked);
    console.log('TTL:', ttlSelect.value);
  }

  // ============================================================================
  // Success Panel
  // ============================================================================

  function showSuccess(url, hasPIN, isBurn) {
    // Hide form, show success panel
    form.classList.add('hidden');
    successPanel.classList.remove('hidden');

    // Set URL
    pasteUrlInput.value = url;

    // Show notices
    if (isBurn) {
      burnNotice.classList.remove('hidden');
    }
    if (hasPIN) {
      pinNotice.classList.remove('hidden');
    }
  }

  function resetForm() {
    // Reset form state
    form.reset();
    currentFile = null;
    fileInfo.classList.add('hidden');
    contentTextarea.disabled = false;

    // Hide success, show form
    successPanel.classList.add('hidden');
    form.classList.remove('hidden');

    // Hide notices
    burnNotice.classList.add('hidden');
    pinNotice.classList.add('hidden');
  }

  // ============================================================================
  // Copy to Clipboard
  // ============================================================================

  function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
      const originalText = copyBtn.textContent;
      copyBtn.textContent = 'Copied!';
      copyBtn.classList.add('btn-primary');
      copyBtn.classList.remove('btn-secondary');

      setTimeout(() => {
        copyBtn.textContent = originalText;
        copyBtn.classList.remove('btn-primary');
        copyBtn.classList.add('btn-secondary');
      }, 2000);
    }).catch(err => {
      console.error('Failed to copy:', err);
      alert('Failed to copy URL. Please copy manually.');
    });
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  function init() {
    setupFileUpload();

    // Form submission
    form.addEventListener('submit', handleSubmit);

    // Copy button
    copyBtn.addEventListener('click', () => {
      copyToClipboard(pasteUrlInput.value);
    });

    // Create another button
    createAnotherBtn.addEventListener('click', resetForm);
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
