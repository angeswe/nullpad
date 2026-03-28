/**
 * Nullpad Utility Functions
 * Shared helpers used across multiple page modules.
 */

(function() {
  'use strict';

  /**
   * Sanitize a filename for safe use in Content-Disposition headers and download attributes.
   * Strips path separators, null bytes, and control characters; truncates to 255 chars.
   * @param {string} name
   * @returns {string}
   */
  function sanitizeFilename(name) {
    return name
      .replace(/[/\\]/g, '_')         // strip path separators
      .replace(/[\x00-\x1f\x7f]/g, '') // strip null bytes and control chars
      .slice(0, 255)                    // truncate to 255 chars
      || 'file';                        // fallback if empty after sanitization
  }

  const NullpadUtils = Object.freeze({
    sanitizeFilename
  });

  Object.defineProperty(window, 'NullpadUtils', {
    value: NullpadUtils,
    writable: false,
    configurable: false
  });

})();
