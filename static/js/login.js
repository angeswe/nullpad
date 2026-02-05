/**
 * Nullpad Login Module
 * Handles user authentication via Ed25519 challenge-response
 */

(function() {
  'use strict';

  // DOM elements
  const loginForm = document.getElementById('login-form');
  const aliasInput = document.getElementById('alias');
  const secretInput = document.getElementById('secret');
  const errorDiv = document.getElementById('error-message');
  const loginText = document.getElementById('login-text');
  const loginSpinner = document.getElementById('login-spinner');
  const submitBtn = loginForm.querySelector('button[type="submit"]');

  // ============================================================================
  // Form Handling
  // ============================================================================

  async function handleLogin(e) {
    e.preventDefault();

    const alias = aliasInput.value.trim();
    const secret = secretInput.value;

    if (!alias || !secret) {
      showError('Please enter both alias and secret.');
      return;
    }

    // Clear previous errors
    hideError();

    // Show loading state
    setLoading(true);

    try {
      // Perform login using NullpadAuth
      const { token, role } = await NullpadAuth.login(secret, alias);

      // Success - redirect based on role
      if (role === 'admin') {
        window.location.href = '/admin.html';
      } else {
        window.location.href = '/trusted.html';
      }
    } catch (err) {
      setLoading(false);
      showError(err.message || 'Login failed. Please check your credentials.');
    }
  }

  // ============================================================================
  // UI State
  // ============================================================================

  function setLoading(isLoading) {
    submitBtn.disabled = isLoading;
    if (isLoading) {
      loginText.classList.add('hidden');
      loginSpinner.classList.remove('hidden');
    } else {
      loginText.classList.remove('hidden');
      loginSpinner.classList.add('hidden');
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
    // Check if already logged in
    const session = NullpadAuth.getSession();
    if (session) {
      // Already logged in - redirect based on role
      if (session.role === 'admin') {
        window.location.href = '/admin.html';
      } else {
        window.location.href = '/trusted.html';
      }
      return;
    }

    // Set up form submission
    loginForm.addEventListener('submit', handleLogin);
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
