/**
 * Nullpad Invite Module
 * Handles user registration with invite token
 */

(function() {
  'use strict';

  // DOM elements
  const invalidInvite = document.getElementById('invalid-invite');
  const registerForm = document.getElementById('register-form');
  const aliasInput = document.getElementById('alias');
  const secretInput = document.getElementById('secret');
  const secretConfirmInput = document.getElementById('secret-confirm');
  const errorDiv = document.getElementById('error-message');
  const registerText = document.getElementById('register-text');
  const registerSpinner = document.getElementById('register-spinner');
  const submitBtn = registerForm.querySelector('button[type="submit"]');
  const successPanel = document.getElementById('success-panel');

  // State
  let inviteToken = null;

  // ============================================================================
  // URL Parsing
  // ============================================================================

  function parseInviteToken() {
    const params = new URLSearchParams(window.location.search);
    inviteToken = params.get('token');

    if (!inviteToken) {
      // No invite token in URL
      registerForm.classList.add('hidden');
      invalidInvite.classList.remove('hidden');
      return false;
    }

    return true;
  }

  // ============================================================================
  // Form Handling
  // ============================================================================

  async function handleRegister(e) {
    e.preventDefault();

    const alias = aliasInput.value.trim();
    const secret = secretInput.value;
    const secretConfirm = secretConfirmInput.value;

    // Validation
    if (!alias || !secret || !secretConfirm) {
      showError('Please fill in all fields.');
      return;
    }

    if (secret !== secretConfirm) {
      showError('Secrets do not match. Please try again.');
      secretConfirmInput.value = '';
      secretConfirmInput.focus();
      return;
    }

    if (secret.length < 8) {
      showError('Secret must be at least 8 characters long.');
      return;
    }

    // Clear previous errors
    hideError();

    // Show loading state
    setLoading(true);

    try {
      // Derive keypair from secret and alias
      const keypair = await NullpadAuth.deriveKeypair(secret, alias);

      // Register with server
      await NullpadAuth.register(inviteToken, alias, keypair.publicKey);

      // Success - show success panel
      registerForm.classList.add('hidden');
      successPanel.classList.remove('hidden');
    } catch (err) {
      setLoading(false);
      showError(err.message || 'Registration failed. Please try again.');
    }
  }

  // ============================================================================
  // UI State
  // ============================================================================

  function setLoading(isLoading) {
    submitBtn.disabled = isLoading;
    if (isLoading) {
      registerText.classList.add('hidden');
      registerSpinner.classList.remove('hidden');
    } else {
      registerText.classList.remove('hidden');
      registerSpinner.classList.add('hidden');
    }
  }

  function showError(message) {
    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
  }

  function hideError() {
    errorDiv.classList.add('hidden');
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  function init() {
    // Parse invite token from URL
    if (!parseInviteToken()) {
      return;
    }

    // Set up form submission
    registerForm.addEventListener('submit', handleRegister);
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
