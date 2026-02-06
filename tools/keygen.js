'use strict';

function uint8ArrayToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function b64urlDecode(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function generateKeypair() {
  if (!crypto.subtle) {
    const msg = 'Web Crypto API not available. This page must be served over HTTPS or localhost (file:// is not supported). Run: python3 -m http.server 8080 --directory tools/';
    document.getElementById('pubkeyField').value = msg;
    document.getElementById('secretkeyField').value = '';
    return;
  }

  try {
    const keypair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify']
    );

    const jwk = await crypto.subtle.exportKey('jwk', keypair.privateKey);

    // jwk.x = public key (base64url), jwk.d = private seed (base64url)
    const publicKeyB64 = uint8ArrayToBase64(b64urlDecode(jwk.x));
    const secretKeyB64 = uint8ArrayToBase64(b64urlDecode(jwk.d));

    document.getElementById('pubkeyField').value = publicKeyB64;
    document.getElementById('secretkeyField').value = secretKeyB64;
  } catch (err) {
    const msg = err.name === 'NotSupportedError'
      ? 'Ed25519 is not supported in this browser. Use Chrome 113+, Firefox 130+, or Safari 17+. Alternatively, generate keys with: openssl genpkey -algorithm ED25519 -out key.pem'
      : 'Failed to generate keypair: ' + err.message;
    document.getElementById('pubkeyField').value = msg;
    document.getElementById('secretkeyField').value = '';
  }
}

function copyToClipboard(fieldId, buttonElement) {
  const field = document.getElementById(fieldId);
  const text = field.value;

  navigator.clipboard.writeText(text).then(() => {
    const originalText = buttonElement.textContent;
    buttonElement.textContent = 'Copied!';
    buttonElement.classList.add('copied');

    setTimeout(() => {
      buttonElement.textContent = originalText;
      buttonElement.classList.remove('copied');
    }, 2000);
  });
}

function init() {
  document.getElementById('generateBtn').addEventListener('click', generateKeypair);

  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      const fieldId = this.dataset.target;
      copyToClipboard(fieldId, this);
    });
  });

  generateKeypair();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
