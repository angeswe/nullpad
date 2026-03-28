(function() {
  var token = sessionStorage.getItem('nullpad_session_token');
  if (!token) { window.location.href = '/login.html'; return; }
  fetch('/js/admin.js', { headers: { 'Authorization': 'Bearer ' + token } })
    .then(function(r) {
      if (!r.ok) { console.error('admin-loader: fetch failed', r.status); window.location.href = '/login.html'; return; }
      return r.text();
    })
    .then(function(code) {
      if (code) { var s = document.createElement('script'); s.textContent = code; document.body.appendChild(s); }
    })
    .catch(function(e) { console.error('admin-loader:', e); window.location.href = '/login.html'; });
})();
