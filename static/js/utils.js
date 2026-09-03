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

  /**
   * Whether to offer the Share button for a freshly created paste.
   * Needs the Web Share API (absent in desktop Firefox and over plain http).
   * Also withheld for a burn-after-reading paste without a PIN: share sheets
   * (iOS at least) may load the link to build a preview, and the first load
   * of such a paste is the one that burns it. A PIN-protected burn paste
   * survives that load because the first request only asks for the PIN.
   * @param {Navigator} nav - the page's navigator, injected for testability
   * @param {{burnAfterReading: boolean, hasPin: boolean}} paste
   * @returns {boolean}
   */
  function canOfferShare(nav, { burnAfterReading, hasPin }) {
    if (typeof nav.share !== 'function') return false;
    return !burnAfterReading || hasPin;
  }

  /**
   * Hand a URL to the OS share sheet. Only the URL goes in the payload; the
   * caller must never add paste content or the PIN. Must be called
   * synchronously from a user gesture, or the browser rejects; an async
   * function still invokes share() before its first await, so that holds.
   * Dismissing the sheet is a user choice, not a failure: it resolves
   * 'cancelled' so the caller can tell it from a completed share. Every other
   * error, including a synchronous throw from share() or an empty URL (which
   * the sheet would resolve to the current page), surfaces as a rejection.
   * @param {Navigator} nav - the page's navigator, injected for testability
   * @param {string} url - full paste URL including the key fragment
   * @returns {Promise<'shared'|'cancelled'>}
   */
  async function shareUrl(nav, url) {
    if (!url) throw new TypeError('shareUrl: empty URL');
    try {
      await nav.share({ url });
      return 'shared';
    } catch (err) {
      // AbortError also covers "no share targets on this device"; the outcome
      // for the user is the same (nothing happened, Copy is beside the button).
      if (err && err.name === 'AbortError') return 'cancelled';
      throw err;
    }
  }

  const NullpadUtils = Object.freeze({
    sanitizeFilename,
    shouldRenderMarkdown,
    contentTypeForFile,
    contentTypeForRenderMode,
    canOfferShare,
    shareUrl
  });

  Object.defineProperty(window, 'NullpadUtils', {
    value: NullpadUtils,
    writable: false,
    configurable: false
  });

})();
