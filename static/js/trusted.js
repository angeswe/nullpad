/**
 * Nullpad Trusted Upload Module
 * Authenticated user paste creation (any file type allowed)
 */

(function() {
  'use strict';

  // DOM elements
  const logoutBtn = document.getElementById('logout-btn');
  const userInfo = document.getElementById('user-info');
  const adminLink = document.getElementById('admin-link');

  // ============================================================================
  // Authentication Check
  // ============================================================================

  function checkAuth() {
    const session = NullpadAuth.getSession();

    if (!session) {
      // Not logged in - redirect to login
      window.location.href = '/login.html';
      return null;
    }

    // Show user info
    userInfo.textContent = `(${session.role})`;

    // Show admin link if user is admin
    if (session.role === 'admin') {
      adminLink.classList.remove('hidden');
    }

    return session;
  }

  // ============================================================================
  // Logout
  // ============================================================================

  function handleLogout() {
    NullpadAuth.clearSession();
    window.location.href = '/';
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  function init() {
    // Check authentication
    const session = checkAuth();
    if (!session) return;

    // Set up logout button
    logoutBtn.addEventListener('click', handleLogout);

    // Paste creation logic is handled by create.js (loaded before this script).
    // create.js already includes the Authorization header via NullpadAuth.getAuthHeader().
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
