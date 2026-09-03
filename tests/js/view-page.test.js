// Source-level and wiring tests for the burn-after-reading reveal gate:
// static/view.html's #burn-reveal panel and static/js/view.js's fetch gating.
// See NullpadUtils.pasteViewUrl for why burn-without-PIN links carry the hint.
// Run with: node --test tests/js/*.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

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

function loadNullpadUtils() {
  const src = fs.readFileSync(path.join(ROOT, 'static', 'js', 'utils.js'), 'utf8');
  const sandbox = { window: {}, URLSearchParams };
  vm.runInNewContext(src, sandbox);
  return sandbox.window.NullpadUtils;
}

// Minimal fake DOM element: classList (add/remove/toggle/contains),
// addEventListener (recorded, not dispatched), and the handful of other
// properties view.js touches at module load or inside loadPaste/fetchAndShow.
function makeElement() {
  const classes = new Set();
  const listeners = {};
  return {
    classList: {
      add: (...c) => c.forEach((x) => classes.add(x)),
      remove: (...c) => c.forEach((x) => classes.delete(x)),
      toggle(c, force) {
        const next = force === undefined ? !classes.has(c) : force;
        next ? classes.add(c) : classes.delete(c);
      },
      contains: (c) => classes.has(c)
    },
    addEventListener(type, handler, opts) {
      (listeners[type] = listeners[type] || []).push({ handler, opts });
    },
    removeEventListener() {},
    setAttribute() {},
    getAttribute: () => null,
    hasAttribute: () => false,
    querySelector: () => null,
    querySelectorAll: () => [],
    appendChild() {},
    replaceChildren() {},
    parentNode: { insertBefore() {} },
    style: {},
    _text: '',
    get textContent() { return this._text; },
    set textContent(v) { this._text = v; },
    _value: '',
    get value() { return this._value; },
    set value(v) { this._value = v; },
    focus() {},
    click() {},
    _listeners: listeners
  };
}

// Loads static/js/view.js into a fresh vm context with a fake DOM and a
// fetch stub that never resolves — these tests only need to observe whether
// fetch was called, not exercise the decrypt path.
function loadViewJs(locationOverrides, sandboxOverrides) {
  const elementIds = [
    'burn-warning', 'pin-prompt', 'pin-form', 'pin', 'loading',
    'error-panel', 'error-message', 'content-panel', 'content-display',
    'raw-content', 'download-btn', 'copy-content-btn', 'toggle-raw-btn',
    'burn-notice', 'burn-reveal', 'reveal-btn'
  ];
  const elements = {};
  elementIds.forEach((id) => { elements[id] = makeElement(); });

  const docListeners = {};
  let readyState = 'loading';
  const document = {
    get readyState() { return readyState; },
    getElementById: (id) => elements[id] || null,
    addEventListener(type, handler) {
      (docListeners[type] = docListeners[type] || []).push(handler);
    },
    removeEventListener() {}
  };

  const fetchCalls = [];
  function fetch(url, opts) {
    fetchCalls.push({ url, opts });
    return new Promise(() => {}); // never resolves; tests only check the call
  }

  const historyCalls = [];
  const window = {
    location: Object.assign({ search: '', hash: '', pathname: '/view.html' }, locationOverrides),
    history: (sandboxOverrides && sandboxOverrides.history) ||
      { replaceState: (...args) => historyCalls.push(args) },
    addEventListener() {},
    removeEventListener() {}
  };

  const NullpadCrypto = {
    base64urlDecode: () => new Uint8Array(32)
  };

  // Records every console.warn/error call so tests can assert the real
  // underlying error is logged, not just swallowed behind a generic message.
  const consoleCalls = { warn: [], error: [], log: [] };
  const sandbox = {
    window,
    document,
    fetch,
    NullpadCrypto,
    NullpadUtils: (sandboxOverrides && sandboxOverrides.NullpadUtils) || loadNullpadUtils(),
    URLSearchParams,
    console: {
      warn: (...args) => consoleCalls.warn.push(args),
      error: (...args) => consoleCalls.error.push(args),
      log: (...args) => consoleCalls.log.push(args)
    }
  };

  const src = fs.readFileSync(path.join(ROOT, 'static', 'js', 'view.js'), 'utf8');
  vm.runInNewContext(src, sandbox);

  // Flip readyState and fire the DOMContentLoaded handler view.js registered
  // (document.readyState was 'loading' when the script ran, so it deferred
  // init() to this event instead of calling it immediately).
  readyState = 'complete';
  (docListeners.DOMContentLoaded || []).forEach((h) => h());

  return { elements, fetchCalls, consoleCalls, historyCalls };
}

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
