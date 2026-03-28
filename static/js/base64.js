/**
 * Nullpad Base64 Utilities
 * Shared base64/base64url encode/decode helpers used by crypto.js and auth.js.
 */

(function() {
  'use strict';

  /**
   * Encode Uint8Array to standard base64 string
   * @param {Uint8Array} bytes
   * @returns {string}
   */
  function base64Encode(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Decode standard base64 string to Uint8Array
   * @param {string} str
   * @returns {Uint8Array}
   */
  function base64Decode(str) {
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Encode Uint8Array to URL-safe base64 string (no padding, - and _ instead of + and /)
   * @param {Uint8Array} bytes
   * @returns {string}
   */
  function base64urlEncode(bytes) {
    return base64Encode(bytes)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Decode URL-safe base64 string to Uint8Array
   * @param {string} str
   * @returns {Uint8Array}
   */
  function base64urlDecode(str) {
    let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    return base64Decode(b64);
  }

  const NullpadBase64 = Object.freeze({
    base64Encode,
    base64Decode,
    base64urlEncode,
    base64urlDecode
  });

  Object.defineProperty(window, 'NullpadBase64', {
    value: NullpadBase64,
    writable: false,
    configurable: false
  });

})();
