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
   * See pasteViewUrl for why paste metadata no longer needs to factor in here.
   * @param {Navigator} nav - the page's navigator, injected for testability
   * @returns {boolean}
   */
  function canOfferShare(nav) {
    return typeof nav.share === 'function';
  }

  /**
   * Build the URL for a freshly created paste. Appends a non-secret `burn=1`
   * query hint when the paste is burn-after-reading and has no PIN, so
   * view.js can gate its fetch behind a click (see hasBurnHint) instead of
   * firing on page load, where a link-preview fetch would burn the paste
   * before the recipient opens it. PIN-protected burn pastes don't need the
   * hint: the first GET only returns `needs_pin`, so a preview load can't
   * burn them. The key material stays in the fragment, untouched.
   * @param {string} origin - window.location.origin
   * @param {string} id - paste ID returned by the server
   * @param {string} fragment - key material for the URL fragment (key, or key.salt)
   * @param {{burnAfterReading: boolean, hasPin: boolean}} paste
   * @returns {string}
   */
  function pasteViewUrl(origin, id, fragment, { burnAfterReading, hasPin }) {
    const burnHint = burnAfterReading && !hasPin ? '&burn=1' : '';
    return `${origin}/view.html?id=${id}${burnHint}#${fragment}`;
  }

  /**
   * Whether a view.html URL carries the burn reveal hint set by pasteViewUrl.
   * Only the literal value `1` counts, matching what pasteViewUrl emits.
   * @param {string} search - window.location.search, with or without the leading "?"
   * @returns {boolean}
   */
  function hasBurnHint(search) {
    return new URLSearchParams(search).get('burn') === '1';
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
    shareUrl,
    pasteViewUrl,
    hasBurnHint
  });

  Object.defineProperty(window, 'NullpadUtils', {
    value: NullpadUtils,
    writable: false,
    configurable: false
  });

})();
