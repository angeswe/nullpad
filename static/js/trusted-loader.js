// Loads the auth-gated trusted dashboard app as an external script.
// The browser attaches the np_session cookie automatically on same-origin
// script loads, and the server validates it (same check as Bearer auth).
// An external <script src> is required because the CSP forbids inline
// scripts, so fetching the code and injecting it inline would be blocked.
(function() {
  var token = sessionStorage.getItem('nullpad_session_token');
  if (!token) { window.location.href = '/login.html'; return; }
  var s = document.createElement('script');
  s.src = '/js/trusted.js';
  s.onerror = function() {
    console.error('trusted-loader: failed to load /js/trusted.js (session may have expired)');
    window.location.href = '/login.html';
  };
  document.body.appendChild(s);
})();
