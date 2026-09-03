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

  /**
   * Whether text content opens in the rendered-markdown view. The creator's
   * choice travels as the content type inside the encrypted metadata: the
   * Markdown types (text/markdown, and text/x-markdown from some browsers)
   * open rendered, anything else opens raw. A missing type is a paste from
   * before this option existed; those always rendered.
   * @param {string|null|undefined} mimetype
   * @returns {boolean}
   */
  function shouldRenderMarkdown(mimetype) {
    if (!mimetype) return true;
    const type = mimetype.split(';')[0].trim().toLowerCase();
    return type === 'text/markdown' || type === 'text/x-markdown';
  }

  /**
   * Content type to store for an uploaded file. Browsers report an empty type
   * for extensions missing from the OS mime database (notably .md on Windows),
   * which would make Markdown files open raw; recognise those by extension.
   * @param {string} name - file name
   * @param {string} browserType - File.type as reported by the browser
   * @returns {string}
   */
  function contentTypeForFile(name, browserType) {
    if (browserType) return browserType;
    return /\.(md|markdown)$/i.test(name) ? 'text/markdown' : 'application/octet-stream';
  }

  /**
   * Content type that makes a text paste open in the chosen view. Inverse of
   * shouldRenderMarkdown: keep the two in step.
   * @param {'markdown'|'raw'} mode - value of the "Display as" select
   * @returns {string}
   */
  function contentTypeForRenderMode(mode) {
    return mode === 'raw' ? 'text/plain' : 'text/markdown';
  }

  const NullpadUtils = Object.freeze({
    sanitizeFilename,
    shouldRenderMarkdown,
    contentTypeForFile,
    contentTypeForRenderMode
  });

  Object.defineProperty(window, 'NullpadUtils', {
    value: NullpadUtils,
    writable: false,
    configurable: false
  });

})();
