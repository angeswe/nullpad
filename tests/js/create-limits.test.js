// create.js takes its size limit from /api/config and tells the user when it
// could not, so a limit it shows may be a guess.
// Run with: node --test tests/js/*.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { loadNullpadUtils, loadRealCrypto, makeElement } = require('./view-harness.js');

const MiB = 1024 * 1024;
const LIMITS_NOTICE = 'Could not load server limits; size limits shown may be inaccurate. Reload to retry.';

function jsonResponse(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

// Loads static/js/create.js with a fake DOM. configResponse is what fetch('/api/config')
// resolves to, or an Error for it to reject with. Other fetches never resolve.
async function loadCreateJs(configResponse, { loggedIn = false } = {}) {
  const ids = [
    'paste-form', 'content', 'pin', 'burn-after-reading', 'ttl', 'render-mode',
    'file-upload-area', 'file-input', 'file-info', 'success-panel', 'paste-url',
    'copy-btn', 'share-btn', 'create-another-btn', 'burn-notice', 'pin-notice'
  ];
  const elements = {};
  ids.forEach((id) => { elements[id] = makeElement(); });
  const prepended = [];
  elements['paste-form'].prepend = (el) => prepended.push(el);

  const fetchCalls = [];
  function fetch(url) {
    fetchCalls.push(url);
    if (url !== '/api/config') return new Promise(() => {});
    return configResponse instanceof Error ? Promise.reject(configResponse) : Promise.resolve(configResponse);
  }

  const warnings = [];
  const fakeConsole = { warn: (...args) => warnings.push(args), error() {}, log() {} };
  const sandbox = {
    window: { location: { origin: 'https://nullpad.test' }, addEventListener() {} },
    document: {
      readyState: 'complete',
      getElementById: (id) => elements[id] || null,
      createElement: () => makeElement(),
      addEventListener() {}
    },
    fetch,
    navigator: {},
    setTimeout() {},
    console: fakeConsole,
    NullpadCrypto: loadRealCrypto(),
    NullpadUtils: loadNullpadUtils(fakeConsole)
  };
  if (loggedIn) sandbox.NullpadAuth = { getAuthHeader: () => 'Bearer token' };

  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'static', 'js', 'create.js'), 'utf8');
  vm.runInNewContext(src, sandbox);
  await settle();
  return { elements, prepended, fetchCalls, warnings };
}

function settle() {
  return new Promise((resolve) => setImmediate(resolve));
}

function submit(page) {
  page.elements['paste-form']._listeners.submit[0].handler({ preventDefault() {} });
  return settle();
}

function submitText(page, length) {
  page.elements.content.value = 'a'.repeat(length);
  return submit(page);
}

function messages(page, className) {
  return page.prepended.filter((el) => el.className === className).map((el) => el.textContent);
}

const VALID_CONFIG = { max_upload_bytes: 10 * MiB, anon_max_bytes: 100000 };

test('a network error on /api/config shows a notice that the size limits may be inaccurate', async () => {
  const page = await loadCreateJs(new Error('NetworkError'));
  assert.deepEqual(messages(page, 'status-warning'), [LIMITS_NOTICE]);
  assert.ok(page.warnings.some((args) => args.includes('NetworkError')), 'the fetch error must be logged');
});

test('an HTTP error from /api/config logs the status and shows the notice', async () => {
  const page = await loadCreateJs(jsonResponse({}, 502));
  assert.deepEqual(messages(page, 'status-warning'), [LIMITS_NOTICE]);
  assert.ok(page.warnings.some((args) => args.includes(502)), 'the HTTP status must be logged');
});

test('a non-JSON /api/config body logs the parse error and shows the notice', async () => {
  const page = await loadCreateJs({ ok: true, status: 200, json: async () => { throw new SyntaxError('Unexpected token <'); } });
  assert.deepEqual(messages(page, 'status-warning'), [LIMITS_NOTICE]);
  assert.ok(page.warnings.some((args) => args.includes('Unexpected token <')), 'the parse error must be logged');
});

test('an invalid cap in /api/config shows the notice', async () => {
  const page = await loadCreateJs(jsonResponse({ max_upload_bytes: 10 * MiB, anon_max_bytes: '100000' }));
  assert.deepEqual(messages(page, 'status-warning'), [LIMITS_NOTICE]);
});

test('a valid /api/config shows no notice', async () => {
  const page = await loadCreateJs(jsonResponse(VALID_CONFIG));
  assert.deepEqual(messages(page, 'status-warning'), []);
});

test('text over the server cap is refused with its size and the cap from /api/config', async () => {
  const page = await loadCreateJs(jsonResponse(VALID_CONFIG));
  await submitText(page, 200000);
  assert.deepEqual(messages(page, 'status-error'), ['Content too large (195.31 KB). Maximum is 97.62 KB.']);
  assert.ok(!page.fetchCalls.includes('/api/paste/reserve'));
});

test('text over the default anonymous cap but under the server cap goes on to reserve a paste ID', async () => {
  const page = await loadCreateJs(jsonResponse({ max_upload_bytes: 10 * MiB, anon_max_bytes: MiB }));
  await submitText(page, 300000);
  assert.deepEqual(messages(page, 'status-error'), []);
  assert.ok(page.fetchCalls.includes('/api/paste/reserve'));
});

test('a file over the cap is refused with the same message as text', async () => {
  const page = await loadCreateJs(jsonResponse({ max_upload_bytes: MiB, anon_max_bytes: 100000 }), { loggedIn: true });
  page.elements['file-input']._listeners.change[0].handler({ target: { files: [{ name: 'big.bin', type: '', size: 2 * MiB }] } });
  await submit(page);
  assert.deepEqual(messages(page, 'status-error'), ['Content too large (2.00 MB). Maximum is 1023.97 KB.']);
});

test('a size error after a failed /api/config says the limits may be inaccurate', async () => {
  const page = await loadCreateJs(new Error('NetworkError'));
  await submitText(page, 300000);
  assert.deepEqual(messages(page, 'status-error'), [`Content too large (292.97 KB). Maximum is 255.99 KB. ${LIMITS_NOTICE}`]);
});
