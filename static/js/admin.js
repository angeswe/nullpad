/**
 * Nullpad Admin Dashboard Module
 * Manages users, invites, and system statistics
 */

(function() {
  'use strict';

  // DOM elements
  const logoutBtn = document.getElementById('logout-btn');
  const statUsers = document.getElementById('stat-users');
  const statPastes = document.getElementById('stat-pastes');
  const statInvites = document.getElementById('stat-invites');
  const createInviteBtn = document.getElementById('create-invite-btn');
  const inviteSuccess = document.getElementById('invite-success');
  const inviteUrl = document.getElementById('invite-url');
  const copyInviteBtn = document.getElementById('copy-invite-btn');
  const invitesList = document.getElementById('invites-list');
  const usersList = document.getElementById('users-list');
  const deletePasteForm = document.getElementById('delete-paste-form');
  const pasteIdInput = document.getElementById('paste-id');
  const pasteDeleteSuccess = document.getElementById('paste-delete-success');
  const pasteDeleteError = document.getElementById('paste-delete-error');
  const errorMessage = document.getElementById('error-message');

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

    if (session.role !== 'admin') {
      // Not an admin - redirect to trusted upload
      window.location.href = '/trusted.html';
      return null;
    }

    return session;
  }

  // ============================================================================
  // API Requests
  // ============================================================================

  async function apiRequest(url, options = {}) {
    const authHeader = NullpadAuth.getAuthHeader();
    if (!authHeader) {
      throw new Error('Not authenticated');
    }

    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': authHeader
      }
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Request failed');
    }

    return await response.json();
  }

  // ============================================================================
  // DOM Helpers
  // ============================================================================

  function clearElement(element) {
    while (element.firstChild) {
      element.removeChild(element.firstChild);
    }
  }

  // ============================================================================
  // Statistics
  // ============================================================================

  async function loadStats() {
    try {
      // TODO: Implement stats API endpoints or derive from existing data
      // For now, we'll update stats when loading users and invites

      // Load users and invites to get counts
      const [users, invites] = await Promise.all([
        apiRequest('/api/users'),
        apiRequest('/api/invites')
      ]);

      statUsers.textContent = Array.isArray(users) ? users.length : 0;
      statInvites.textContent = Array.isArray(invites) ? invites.length : 0;

      // Paste count requires separate tracking or estimation
      statPastes.textContent = '?';
    } catch (err) {
      // Stats load failure is non-critical, ignore silently
    }
  }

  // ============================================================================
  // Invites Management
  // ============================================================================

  async function createInvite() {
    try {
      const result = await apiRequest('/api/invites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });

      // Show success message with invite URL
      const url = `${window.location.origin}/invite.html?token=${result.token}`;
      inviteUrl.value = url;
      inviteSuccess.classList.remove('hidden');

      // Reload invites list
      await loadInvites();

      // Update stats
      await loadStats();
    } catch (err) {
      showError('Failed to create invite: ' + err.message);
    }
  }

  async function loadInvites() {
    try {
      const result = await apiRequest('/api/invites');
      const invites = Array.isArray(result) ? result : [];

      // Clear existing rows
      clearElement(invitesList);

      if (invites.length === 0) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 4;
        cell.className = 'text-center text-muted';
        cell.textContent = 'No pending invites';
        row.appendChild(cell);
        invitesList.appendChild(row);
        return;
      }

      // Build table rows safely
      invites.forEach(invite => {
        const row = document.createElement('tr');

        // Token cell
        const tokenCell = document.createElement('td');
        const tokenCode = document.createElement('code');
        tokenCode.textContent = invite.token;
        tokenCell.appendChild(tokenCode);
        row.appendChild(tokenCell);

        // Created cell
        const createdCell = document.createElement('td');
        createdCell.textContent = new Date(invite.created_at * 1000).toLocaleString();
        row.appendChild(createdCell);

        // Expires cell
        const expiresCell = document.createElement('td');
        expiresCell.textContent = new Date(invite.expires_at * 1000).toLocaleString();
        row.appendChild(expiresCell);

        // Actions cell
        const actionsCell = document.createElement('td');
        const revokeBtn = document.createElement('button');
        revokeBtn.className = 'btn btn-danger btn-small';
        revokeBtn.textContent = 'Revoke';
        revokeBtn.addEventListener('click', () => revokeInvite(invite.token));
        actionsCell.appendChild(revokeBtn);
        row.appendChild(actionsCell);

        invitesList.appendChild(row);
      });
    } catch (err) {
      clearElement(invitesList);
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 4;
      cell.className = 'text-center text-error';
      cell.textContent = 'Failed to load invites';
      row.appendChild(cell);
      invitesList.appendChild(row);
      // Error displayed in table UI
    }
  }

  async function revokeInvite(token) {
    if (!confirm('Are you sure you want to revoke this invite?')) {
      return;
    }

    try {
      await apiRequest(`/api/invites/${token}`, {
        method: 'DELETE'
      });

      // Reload invites list
      await loadInvites();

      // Update stats
      await loadStats();
    } catch (err) {
      showError('Failed to revoke invite: ' + err.message);
    }
  }

  // ============================================================================
  // Users Management
  // ============================================================================

  async function loadUsers() {
    try {
      const result = await apiRequest('/api/users');
      const users = Array.isArray(result) ? result : [];

      // Clear existing rows
      clearElement(usersList);

      if (users.length === 0) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 4;
        cell.className = 'text-center text-muted';
        cell.textContent = 'No users found';
        row.appendChild(cell);
        usersList.appendChild(row);
        return;
      }

      // Build table rows safely
      users.forEach(user => {
        const row = document.createElement('tr');

        // Alias cell
        const aliasCell = document.createElement('td');
        const aliasStrong = document.createElement('strong');
        aliasStrong.textContent = user.alias;
        aliasCell.appendChild(aliasStrong);
        row.appendChild(aliasCell);

        // User ID cell
        const idCell = document.createElement('td');
        const idCode = document.createElement('code');
        idCode.textContent = user.id;
        idCell.appendChild(idCode);
        row.appendChild(idCell);

        // Public key cell
        const pubkeyCell = document.createElement('td');
        const pubkeyCode = document.createElement('code');
        pubkeyCode.className = 'text-muted';
        pubkeyCode.style.fontSize = '0.75em';
        pubkeyCode.textContent = user.pubkey ? user.pubkey.substring(0, 32) + '...' : 'N/A';
        pubkeyCell.appendChild(pubkeyCode);
        row.appendChild(pubkeyCell);

        // Actions cell
        const actionsCell = document.createElement('td');
        if (user.alias !== 'admin') {
          const revokeBtn = document.createElement('button');
          revokeBtn.className = 'btn btn-danger btn-small';
          revokeBtn.textContent = 'Revoke';
          revokeBtn.addEventListener('click', () => revokeUser(user.id, user.alias));
          actionsCell.appendChild(revokeBtn);
        } else {
          const protectedSpan = document.createElement('span');
          protectedSpan.className = 'text-muted';
          protectedSpan.textContent = 'Protected';
          actionsCell.appendChild(protectedSpan);
        }
        row.appendChild(actionsCell);

        usersList.appendChild(row);
      });
    } catch (err) {
      clearElement(usersList);
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 4;
      cell.className = 'text-center text-error';
      cell.textContent = 'Failed to load users';
      row.appendChild(cell);
      usersList.appendChild(row);
      // Error displayed in table UI
    }
  }

  async function revokeUser(userId, alias) {
    if (!confirm(`Are you sure you want to revoke user "${alias}"? This will delete all their pastes and kill their sessions.`)) {
      return;
    }

    try {
      await apiRequest(`/api/users/${userId}`, {
        method: 'DELETE'
      });

      // Reload users list
      await loadUsers();

      // Update stats
      await loadStats();
    } catch (err) {
      showError('Failed to revoke user: ' + err.message);
    }
  }

  // ============================================================================
  // Paste Management
  // ============================================================================

  async function handleDeletePaste(e) {
    e.preventDefault();

    const pasteId = pasteIdInput.value.trim();
    if (!pasteId) return;

    // Hide previous messages
    pasteDeleteSuccess.classList.add('hidden');
    pasteDeleteError.classList.add('hidden');

    try {
      await apiRequest(`/api/paste/${pasteId}`, {
        method: 'DELETE'
      });

      // Show success
      pasteDeleteSuccess.classList.remove('hidden');
      pasteIdInput.value = '';
    } catch (err) {
      // Show error
      pasteDeleteError.textContent = 'Failed to delete paste: ' + err.message;
      pasteDeleteError.classList.remove('hidden');
    }
  }

  // ============================================================================
  // Copy to Clipboard
  // ============================================================================

  function copyInviteUrl() {
    navigator.clipboard.writeText(inviteUrl.value).then(() => {
      const originalText = copyInviteBtn.textContent;
      copyInviteBtn.textContent = 'Copied!';

      setTimeout(() => {
        copyInviteBtn.textContent = originalText;
      }, 2000);
    }).catch(() => {
      alert('Failed to copy URL. Please copy manually.');
    });
  }

  // ============================================================================
  // Logout
  // ============================================================================

  function handleLogout() {
    NullpadAuth.clearSession();
    window.location.href = '/';
  }

  // ============================================================================
  // Error Display
  // ============================================================================

  function showError(message) {
    errorMessage.textContent = message;
    errorMessage.classList.remove('hidden');

    setTimeout(() => {
      errorMessage.classList.add('hidden');
    }, 5000);
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  async function init() {
    // Check authentication
    const session = checkAuth();
    if (!session) return;

    // Set up event listeners
    logoutBtn.addEventListener('click', handleLogout);
    createInviteBtn.addEventListener('click', createInvite);
    copyInviteBtn.addEventListener('click', copyInviteUrl);
    deletePasteForm.addEventListener('submit', handleDeletePaste);

    // Load initial data
    try {
      await Promise.all([
        loadStats(),
        loadInvites(),
        loadUsers()
      ]);
    } catch (err) {
      showError('Failed to load dashboard data: ' + err.message);
    }
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
