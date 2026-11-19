// Source-level and wiring tests for the burn-after-reading reveal gate:
// static/view.html's #burn-reveal panel and static/js/view.js's fetch gating.
// See NullpadUtils.pasteViewUrl for why burn-without-PIN links carry the hint.
// Run with: node --test tests/js/*.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadNullpadUtils, loadViewJs } = require('./view-harness.js');

const ROOT = path.join(__dirname, '..', '..');

// The <div> element opening at `start` in `html`, found by tracking div
// nesting (mirrors the helper in share-button.test.js).
function divAt(html, start, what) {
  assert.notEqual(start, -1, `no ${what}`);
  const divTag = /<div\b|<\/div>/g;
  divTag.lastIndex = start;
  let depth = 0;
  for (let m = divTag.exec(html); m; m = divTag.exec(html)) {
    depth += m[0] === '</div>' ? -1 : 1;
    if (depth === 0) return html.slice(start, m.index + m[0].length);
  }
  assert.fail(`unclosed ${what}`);
}

test('static/view.html has a hidden burn-reveal panel containing the Reveal button', () => {
  const html = fs.readFileSync(path.join(ROOT, 'static', 'view.html'), 'utf8');
  const panel = divAt(html, html.indexOf('<div id="burn-reveal"'), 'burn-reveal panel');
  const openTag = panel.match(/^<div[^>]*>/)[0];
  const classes = (openTag.match(/\bclass="([^"]*)"/) || ['', ''])[1].split(/\s+/);
  assert.ok(classes.includes('hidden'), 'burn-reveal panel must start hidden');
  assert.match(panel, /id="reveal-btn"/, 'burn-reveal panel must contain the Reveal button');
});

// ============================================================================
// Wiring: view.js must not fetch the paste before the burn hint is revealed
// ============================================================================

test('view.js does not request the paste on load when the URL carries the burn hint', () => {
  const { fetchCalls } = loadViewJs({ search: '?id=abcdefghijkl&burn=1', hash: '#key' });
  assert.equal(fetchCalls.length, 0);
});

test('view.js requests the paste after the Reveal button is clicked', () => {
  const { elements, fetchCalls } = loadViewJs({ search: '?id=abcdefghijkl&burn=1', hash: '#key' });
  assert.equal(fetchCalls.length, 0);
  const clickListeners = elements['reveal-btn']._listeners.click || [];
  assert.equal(clickListeners.length, 1, 'expected exactly one click listener on the Reveal button');
  clickListeners[0].handler();
  assert.equal(fetchCalls.length, 1);
  assert.match(fetchCalls[0].url, /\/api\/paste\/abcdefghijkl/);
});

test('view.js requests the paste on load when the URL has no burn hint', () => {
  const { fetchCalls } = loadViewJs({ search: '?id=abcdefghijkl', hash: '#key' });
  assert.equal(fetchCalls.length, 1);
  assert.match(fetchCalls[0].url, /\/api\/paste\/abcdefghijkl/);
});

// ============================================================================
// Wiring: the key fragment must stay in the URL bar until a burn-hinted
// paste is actually revealed, so a tab discarded while idle on the reveal
// gate can be reloaded from the still-intact address bar instead of erroring
// with a missing key.
// ============================================================================

test('view.js keeps the key fragment in the URL until the paste is revealed', () => {
  const { elements, historyCalls } = loadViewJs({
    search: '?id=abcdefghijkl&burn=1',
    hash: '#key',
    pathname: '/view.html'
  });

  assert.equal(historyCalls.length, 0, 'must not strip the fragment before Reveal is clicked');

  const clickListeners = elements['reveal-btn']._listeners.click || [];
  assert.equal(clickListeners.length, 1, 'expected exactly one click listener on the Reveal button');
  clickListeners[0].handler();

  assert.equal(historyCalls.length, 1);
  assert.deepEqual(historyCalls[0], [null, '', '/view.html?id=abcdefghijkl&burn=1']);
});

test('view.js strips the key fragment from the URL on load when there is no burn hint', () => {
  const { historyCalls } = loadViewJs({
    search: '?id=abcdefghijkl',
    hash: '#key',
    pathname: '/view.html'
  });

  assert.equal(historyCalls.length, 1);
  assert.deepEqual(historyCalls[0], [null, '', '/view.html?id=abcdefghijkl']);
});

// ============================================================================
// Wiring: a history.replaceState failure (SecurityError from browser
// history-mutation rate limiting, a hardened browser/extension blocking the
// History API, etc.) while stripping the fragment must not abort the fetch —
// failing to strip the fragment is non-fatal to viewing the paste, unlike a
// silent hang on the loading spinner.
// ============================================================================

test('view.js still fetches the paste when stripping the fragment throws (no burn hint)', async () => {
  const thrown = new Error('SecurityError: history mutation rate limit exceeded');
  const { elements, fetchCalls, consoleCalls } = loadViewJs(
    { search: '?id=abcdefghijkl', hash: '#key', pathname: '/view.html' },
    { history: { replaceState() { throw thrown; } } }
  );

  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(fetchCalls.length, 1, 'a failed replaceState must not block the paste fetch');
  assert.match(fetchCalls[0].url, /\/api\/paste\/abcdefghijkl/);
  assert.equal(
    elements['error-message'].textContent,
    '',
    'a failed replaceState is non-fatal and must not show the error panel'
  );
  const loggedErrors = [...consoleCalls.warn, ...consoleCalls.error].flat();
  assert.ok(
    loggedErrors.includes(thrown),
    'the caught replaceState error must be passed to console.warn or console.error'
  );
});

test('view.js still fetches the paste when stripping the fragment throws (burn hint, after Reveal)', async () => {
  const thrown = new Error('SecurityError: history mutation rate limit exceeded');
  const { elements, fetchCalls, consoleCalls } = loadViewJs(
    { search: '?id=abcdefghijkl&burn=1', hash: '#key', pathname: '/view.html' },
    { history: { replaceState() { throw thrown; } } }
  );

  assert.equal(fetchCalls.length, 0);
  const clickListeners = elements['reveal-btn']._listeners.click || [];
  assert.equal(clickListeners.length, 1, 'expected exactly one click listener on the Reveal button');
  clickListeners[0].handler();

  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(fetchCalls.length, 1, 'a failed replaceState must not block the paste fetch');
  assert.match(fetchCalls[0].url, /\/api\/paste\/abcdefghijkl/);
  assert.equal(
    elements['error-message'].textContent,
    '',
    'a failed replaceState is non-fatal and must not show the error panel'
  );
  const loggedErrors = [...consoleCalls.warn, ...consoleCalls.error].flat();
  assert.ok(
    loggedErrors.includes(thrown),
    'the caught replaceState error must be passed to console.warn or console.error'
  );
});

// ============================================================================
// Wiring: a NullpadUtils load failure (e.g. an SRI-hash mismatch on
// utils.js) while reading the burn hint must surface as a visible error
// instead of hanging on the loading spinner forever.
// ============================================================================

test('view.js shows an error instead of hanging when reading the burn hint throws', async () => {
  const brokenNullpadUtils = {
    hasBurnHint() { throw new Error('NullpadUtils failed to load'); }
  };
  const { elements, fetchCalls } = loadViewJs(
    { search: '?id=abcdefghijkl&burn=1', hash: '#key' },
    { NullpadUtils: brokenNullpadUtils }
  );

  // Let any promise rejection from the load flow settle before asserting.
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(fetchCalls.length, 0, 'must not fetch when the burn hint could not be read');
  assert.notEqual(
    elements['error-message'].textContent,
    '',
    'the error panel must be populated instead of leaving the user on a silent spinner'
  );
});

test('view.js logs the underlying error to console when reading the burn hint throws', async () => {
  const thrown = new Error('NullpadUtils failed to load');
  const brokenNullpadUtils = {
    hasBurnHint() { throw thrown; }
  };
  const { consoleCalls } = loadViewJs(
    { search: '?id=abcdefghijkl&burn=1', hash: '#key' },
    { NullpadUtils: brokenNullpadUtils }
  );

  await new Promise((resolve) => setImmediate(resolve));

  // Every other catch in view.js that swallows a real error behind a generic
  // user-facing message logs the caught error first (see the
  // encrypted-metadata fallback and the decrypt-failure catch) so the real
  // cause survives in devtools. This catch must follow the same convention
  // instead of discarding the error with no trace.
  const loggedErrors = [...consoleCalls.warn, ...consoleCalls.error].flat();
  assert.ok(
    loggedErrors.includes(thrown),
    'the caught error must be passed to console.warn or console.error'
  );
});

// ============================================================================
// Wiring: an exception while rendering decrypted content is a render error,
// not a decryption failure, and must never count as a wrong PIN.
// ============================================================================

const RENDER_ERROR = 'Failed to render paste content. Open the original link again to retry.';
const DECRYPT_ERROR = 'Decryption failed. Invalid key or PIN.';

// Fetch responses whose body is the parsed frame itself; parsePasteFrame is
// stubbed to return it unchanged.
function frameResponse(meta, content) {
  return { ok: true, status: 200, arrayBuffer: async () => ({ meta, content }) };
}

// The raw view throws, so rendering the decrypted text fails.
function loadDecryptableView(location, responses) {
  const utils = { ...loadNullpadUtils(), parsePasteFrame: (frame) => frame };
  const crypto = {
    base64urlDecode: () => new Uint8Array(32),
    deriveKeyWithPin: async () => ({ key: 'derived-key' }),
    computePinVerifier: async () => 'verifier',
    decrypt: async () => new TextEncoder().encode('hello')
  };
  const view = loadViewJs(location, {
    NullpadUtils: utils,
    NullpadCrypto: crypto,
    fetch: async () => responses.shift()
  });
  Object.defineProperty(view.elements['raw-content'], 'textContent', {
    set() { throw new Error('render boom'); }
  });
  return view;
}

test('render error in no-PIN flow is reported as a render error, not a decrypt failure', async () => {
  const { elements } = loadDecryptableView(
    { search: '?id=abcdefghijkl', hash: '#key' },
    [frameResponse({}, new Uint8Array(64))]
  );

  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(elements['error-message'].textContent, RENDER_ERROR);
  assert.notEqual(elements['error-message'].textContent, DECRYPT_ERROR);
  assert.ok(
    elements['pin-prompt'].classList.contains('hidden'),
    'a render error must not fall back to the PIN prompt'
  );
});

test('render error in PIN flow does not count as a wrong PIN', async () => {
  const { elements, createdElements } = loadDecryptableView(
    { search: '?id=abcdefghijkl', hash: '#key' },
    [
      frameResponse({ needs_pin: true }, new Uint8Array(0)),
      frameResponse({}, new Uint8Array(64))
    ]
  );

  await new Promise((resolve) => setImmediate(resolve));
  elements.pin.value = '1234';
  await elements['pin-form']._listeners.submit[0].handler({ preventDefault() {} });

  const pinMessages = createdElements.map((el) => el.textContent).join('\n');
  assert.doesNotMatch(pinMessages, /Invalid PIN|Wrong PIN|Too many attempts/);
  assert.equal(elements['error-message'].textContent, RENDER_ERROR);
});

test('render failure on a burn paste says the paste was already consumed', async () => {
  const { elements } = loadDecryptableView(
    { search: '?id=abcdefghijkl', hash: '#key' },
    [frameResponse({ burn_after_reading: true }, new Uint8Array(64))]
  );

  await new Promise((resolve) => setImmediate(resolve));

  assert.match(elements['error-message'].textContent, /already been consumed/);
  assert.doesNotMatch(elements['error-message'].textContent, /reload/i);
});
