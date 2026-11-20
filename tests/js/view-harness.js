// Shared harness for loading static/js/view.js into a vm context with a fake DOM.

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..', '..');

function loadRealCrypto() {
  const sandbox = { window: {}, crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array, btoa, atob };
  sandbox.window = sandbox;
  for (const file of ['base64.js', 'crypto.js']) {
    vm.runInNewContext(fs.readFileSync(path.join(ROOT, 'static', 'js', file), 'utf8'), sandbox);
  }
  return sandbox.NullpadCrypto;
}

function loadNullpadUtils(consoleImpl = console) {
  const src = fs.readFileSync(path.join(ROOT, 'static', 'js', 'utils.js'), 'utf8');
  const sandbox = { window: {}, URLSearchParams, console: consoleImpl };
  vm.runInNewContext(src, sandbox);
  return sandbox.window.NullpadUtils;
}

// Minimal fake DOM element: classList (add/remove/toggle/contains),
// addEventListener (recorded, not dispatched), children (appendChild /
// replaceChildren), and the other properties view.js touches at module load
// or inside loadPaste/fetchAndShow.
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
    children: [],
    appendChild(child) { this.children.push(child); },
    replaceChildren(...nodes) { this.children = nodes; },
    _listeners: listeners
  };
}

// Loads static/js/view.js into a fresh vm context with a fake DOM. By default
// fetch is a stub that records each call and never resolves, for tests that
// only check whether fetch was called. Tests that exercise the decrypt path
// pass their own fetch (and NullpadCrypto/NullpadUtils) in sandboxOverrides.
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
  const createdElements = [];
  let readyState = 'loading';
  const document = {
    get readyState() { return readyState; },
    getElementById: (id) => elements[id] || null,
    createElement() {
      const el = makeElement();
      createdElements.push(el);
      return el;
    },
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
  const reloadCalls = [];
  const windowListeners = {};
  const window = {
    location: Object.assign(
      { search: '', hash: '', pathname: '/view.html', reload: () => reloadCalls.push(true) },
      locationOverrides
    ),
    history: (sandboxOverrides && sandboxOverrides.history) ||
      { replaceState: (...args) => historyCalls.push(args) },
    addEventListener(type, handler) {
      (windowListeners[type] = windowListeners[type] || []).push(handler);
    },
    removeEventListener() {}
  };

  const NullpadCrypto = (sandboxOverrides && sandboxOverrides.NullpadCrypto) || {
    base64urlDecode: () => new Uint8Array(32)
  };

  // Records every console.warn/error call so tests can assert the real
  // underlying error is logged, not just swallowed behind a generic message.
  const consoleCalls = { warn: [], error: [], log: [] };
  const sandbox = {
    window,
    document,
    fetch: (sandboxOverrides && sandboxOverrides.fetch) || fetch,
    NullpadCrypto,
    TextDecoder,
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

  return { elements, createdElements, fetchCalls, consoleCalls, historyCalls, windowListeners, reloadCalls };
}

module.exports = { loadNullpadUtils, loadRealCrypto, loadViewJs, makeElement };
