/**
 * Nullpad Authentication Module
 * Ed25519 challenge-response authentication using Web Crypto API
 * Uses Argon2id (via hash-wasm) for key derivation, native crypto.subtle for Ed25519
 */

(function() {
  'use strict';

  // Session storage keys
  const SESSION_TOKEN_KEY = 'nullpad_session_token';
  const SESSION_ROLE_KEY = 'nullpad_session_role';

  // Base64 helpers
  function b64Encode(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function b64Decode(str) {
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function b64urlEncode(bytes) {
    return b64Encode(bytes)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  function b64urlDecode(str) {
    let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    return b64Decode(b64);
  }

  /**
   * Import an Ed25519 private key from a 32-byte seed via JWK
   * @param {Uint8Array} seed - 32-byte Ed25519 seed
   * @returns {Promise<CryptoKey>} Ed25519 private key
   */
  async function importPrivateKeyFromSeed(seed) {
    // To import a seed as Ed25519 via JWK, we need both the private key (d)
    // and public key (x). We first import via PKCS8 to let the browser
    // compute the public key, then re-export as JWK.
    //
    // PKCS8 ASN.1 structure for Ed25519 (RFC 8410):
    // SEQUENCE {
    //   INTEGER 0 (version)
    //   SEQUENCE { OID 1.3.101.112 (Ed25519) }
    //   OCTET STRING { OCTET STRING { seed } }
    // }
    const pkcs8 = new Uint8Array(16 + seed.length);
    pkcs8.set([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
      0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    ], 0);
    pkcs8.set(seed, 16);

    try {
      return await crypto.subtle.importKey(
        'pkcs8',
        pkcs8,
        { name: 'Ed25519' },
        true,
        ['sign']
      );
    } finally {
      pkcs8.fill(0);
    }
  }

  /**
   * Derive Ed25519 seed from user secret and alias using Argon2id
   * @param {string} secret - User's secret password
   * @param {string} alias - User's alias (used as salt)
   * @returns {Promise<Uint8Array>} 32-byte seed (caller must zero after use)
   */
  async function deriveSeed(secret, alias) {
    // SECURITY: String params (secret, alias) cannot be zeroed from memory (JS strings are immutable)
    const encoder = new TextEncoder();

    // Argon2id requires salt >= 8 bytes. Pad short aliases with fixed suffix.
    const salt = alias.length >= 8 ? alias : alias + '\0'.repeat(8 - alias.length);

    let hash;
    try {
      hash = await hashwasm.argon2id({
        password: encoder.encode(secret),
        salt: encoder.encode(salt),
        parallelism: 1,
        iterations: 2,
        memorySize: 19456,
        hashLength: 32,
        outputType: 'binary'
      });
    } catch (e) {
      throw new Error('Argon2id failed: ' + e.message);
    }

    return new Uint8Array(hash);
  }

  /**
   * Derive Ed25519 private key only (for login - no JWK export needed)
   * @param {string} secret - User's secret password
   * @param {string} alias - User's alias (used as salt)
   * @returns {Promise<CryptoKey>} Ed25519 private key
   */
  async function derivePrivateKey(secret, alias) {
    const seed = await deriveSeed(secret, alias);
    try {
      return await importPrivateKeyFromSeed(seed);
    } catch (e) {
      throw new Error('Ed25519 PKCS8 import failed: ' + e.message);
    } finally {
      seed.fill(0);
    }
  }

  /**
   * Derive Ed25519 keypair from user secret and alias (for registration/keygen)
   * Uses Argon2id with alias as salt (portability vs stronger salt tradeoff)
   * @param {string} secret - User's secret password
   * @param {string} alias - User's alias (used as salt)
   * @returns {Promise<{publicKey: string, privateKey: CryptoKey}>}
   */
  async function deriveKeypair(secret, alias) {
    const seed = await deriveSeed(secret, alias);

    try {
      let privateKey;
      try {
        privateKey = await importPrivateKeyFromSeed(seed);
      } catch (e) {
        throw new Error('Ed25519 PKCS8 import failed: ' + e.message + '. Your browser may not support Ed25519 PKCS8 import.');
      }

      // Use TweetNaCl for public key derivation (works in all browsers)
      if (typeof nacl === 'undefined' || !nacl.sign) {
        throw new Error('TweetNaCl not loaded. Cannot derive public key.');
      }
      const naclKeypair = nacl.sign.keyPair.fromSeed(seed);
      const pubKeyBytes = naclKeypair.publicKey;

      return {
        publicKey: b64Encode(pubKeyBytes),
        privateKey: privateKey
      };
    } finally {
      seed.fill(0);
    }
  }

  /**
   * Sign a challenge nonce with Ed25519 private key
   * @param {string} nonce - Base64-encoded nonce from server
   * @param {CryptoKey} privateKey - Ed25519 private CryptoKey
   * @returns {Promise<string>} Base64-encoded signature
   */
  async function signChallenge(nonce, privateKey) {
    const nonceBytes = b64Decode(nonce);

    const signature = await crypto.subtle.sign(
      { name: 'Ed25519' },
      privateKey,
      nonceBytes
    );

    return b64Encode(new Uint8Array(signature));
  }

  /**
   * Save session to sessionStorage
   * @param {string} token - Session token
   * @param {string} role - User role (admin/trusted)
   */
  function saveSession(token, role) {
    sessionStorage.setItem(SESSION_TOKEN_KEY, token);
    sessionStorage.setItem(SESSION_ROLE_KEY, role);
  }

  /**
   * Get session from sessionStorage
   * @returns {{token: string, role: string}|null}
   */
  function getSession() {
    const token = sessionStorage.getItem(SESSION_TOKEN_KEY);
    const role = sessionStorage.getItem(SESSION_ROLE_KEY);
    if (token && role) return { token, role };
    return null;
  }

  /**
   * Clear session from sessionStorage
   */
  async function clearSession() {
    const token = sessionStorage.getItem(SESSION_TOKEN_KEY);
    if (token) {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` }
        });
      } catch (_) {
        // Best-effort server-side invalidation
      }
    }
    sessionStorage.removeItem(SESSION_TOKEN_KEY);
    sessionStorage.removeItem(SESSION_ROLE_KEY);
  }

  /**
   * Get Authorization header value
   * @returns {string|null} Bearer token string or null
   */
  function getAuthHeader() {
    const session = getSession();
    return session ? `Bearer ${session.token}` : null;
  }

  /**
   * Request authentication challenge from server
   * @param {string} alias - User alias
   * @returns {Promise<{nonce: string}>}
   */
  async function requestChallenge(alias) {
    const response = await fetch('/api/auth/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alias })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to request challenge');
    }

    return await response.json();
  }

  /**
   * Submit signed challenge for verification
   * @param {string} alias - User alias
   * @param {string} signature - Base64-encoded signature
   * @returns {Promise<{token: string, role: string}>}
   */
  async function submitVerification(alias, signature) {
    const response = await fetch('/api/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alias, signature })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Authentication failed');
    }

    return await response.json();
  }

  /**
   * Register new user with invite token
   * @param {string} inviteToken - Invite token
   * @param {string} alias - Desired alias
   * @param {string} pubkey - Base64-encoded Ed25519 public key
   * @returns {Promise<Object>}
   */
  async function register(inviteToken, alias, pubkey) {
    const response = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: inviteToken, alias, pubkey })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Registration failed');
    }

    return await response.json();
  }

  /**
   * Complete login flow
   * @param {string} secret - User secret
   * @param {string} alias - User alias
   * @returns {Promise<{token: string, role: string}>}
   */
  async function login(secret, alias) {
    const privateKey = await derivePrivateKey(secret, alias);
    const { nonce } = await requestChallenge(alias);
    const signature = await signChallenge(nonce, privateKey);
    const { token, role } = await submitVerification(alias, signature);
    saveSession(token, role);
    return { token, role };
  }

  // Export to global object
  window.NullpadAuth = {
    deriveKeypair,
    signChallenge,
    login,
    saveSession,
    getSession,
    clearSession,
    getAuthHeader,
    requestChallenge,
    submitVerification,
    register
  };

})();
