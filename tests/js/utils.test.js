// Unit tests for static/js/utils.js (NullpadUtils).
// Run with: node --test tests/js/*.test.js
// (an explicit glob: Node 22 rejects a bare directory, and an unmatched
// pattern fails loudly instead of passing with zero tests)
//
// utils.js is a browser IIFE that attaches NullpadUtils to `window`, so it is
// evaluated inside a vm context with a stub window object.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadNullpadUtils() {
  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'static', 'js', 'utils.js'), 'utf8');
  const window = {};
  vm.runInNewContext(src, { window });
  return window.NullpadUtils;
}

const {
  shouldRenderMarkdown,
  contentTypeForFile,
  contentTypeForRenderMode,
  canOfferShare,
  shareUrl
} = loadNullpadUtils();

test('shouldRenderMarkdown returns true for text/markdown', () => {
  assert.equal(shouldRenderMarkdown('text/markdown'), true);
});

test('shouldRenderMarkdown returns true for text/markdown with a charset parameter', () => {
  assert.equal(shouldRenderMarkdown('text/markdown; charset=utf-8'), true);
});

test('shouldRenderMarkdown returns true for text/x-markdown', () => {
  assert.equal(shouldRenderMarkdown('text/x-markdown'), true);
});

test('shouldRenderMarkdown returns false for text/plain', () => {
  assert.equal(shouldRenderMarkdown('text/plain'), false);
});

test('shouldRenderMarkdown returns false for application/octet-stream', () => {
  assert.equal(shouldRenderMarkdown('application/octet-stream'), false);
});

test('shouldRenderMarkdown returns false when "markdown" only appears in a parameter', () => {
  assert.equal(shouldRenderMarkdown('text/plain; note=markdown'), false);
});

test('shouldRenderMarkdown returns true for null mimetype (legacy paste without metadata)', () => {
  assert.equal(shouldRenderMarkdown(null), true);
});

test('shouldRenderMarkdown returns true for undefined mimetype', () => {
  assert.equal(shouldRenderMarkdown(undefined), true);
});

test('shouldRenderMarkdown returns true for empty string (treated as missing)', () => {
  assert.equal(shouldRenderMarkdown(''), true);
});

test('shouldRenderMarkdown is case-insensitive', () => {
  assert.equal(shouldRenderMarkdown('TEXT/MARKDOWN'), true);
});

test('contentTypeForFile keeps the browser-reported type when present', () => {
  assert.equal(contentTypeForFile('notes.md', 'text/plain'), 'text/plain');
});

test('contentTypeForFile infers text/markdown for .md when the browser reports no type', () => {
  assert.equal(contentTypeForFile('README.md', ''), 'text/markdown');
});

test('contentTypeForFile infers text/markdown for .markdown regardless of case', () => {
  assert.equal(contentTypeForFile('notes.MARKDOWN', ''), 'text/markdown');
});

test('contentTypeForFile falls back to application/octet-stream for other untyped files', () => {
  assert.equal(contentTypeForFile('.env', ''), 'application/octet-stream');
});

test('contentTypeForRenderMode maps raw to text/plain', () => {
  assert.equal(contentTypeForRenderMode('raw'), 'text/plain');
});

test('contentTypeForRenderMode maps markdown to text/markdown', () => {
  assert.equal(contentTypeForRenderMode('markdown'), 'text/markdown');
});

test('a raw text paste round-trips to the raw view', () => {
  assert.equal(shouldRenderMarkdown(contentTypeForRenderMode('raw')), false);
});

test('a markdown text paste round-trips to the rendered view', () => {
  assert.equal(shouldRenderMarkdown(contentTypeForRenderMode('markdown')), true);
});

// Web Share API helpers. `nav` is injected so the tests can stand in for the
// browser's navigator without a DOM.

const PASTE_URL = 'https://example.test/view.html?id=abc#key';
const PLAIN_PASTE = { burnAfterReading: false, hasPin: false };

test('canOfferShare returns false when the browser has no Web Share API', () => {
  assert.equal(canOfferShare({}, PLAIN_PASTE), false);
});

test('canOfferShare returns true for a plain paste when navigator.share is a function', () => {
  assert.equal(canOfferShare({ share() {} }, PLAIN_PASTE), true);
});

test('canOfferShare returns false for a burn-after-reading paste without a PIN', () => {
  // A share-sheet link preview may load the page, and that first load burns it.
  assert.equal(canOfferShare({ share() {} }, { burnAfterReading: true, hasPin: false }), false);
});

test('canOfferShare returns true for a burn-after-reading paste with a PIN', () => {
  assert.equal(canOfferShare({ share() {} }, { burnAfterReading: true, hasPin: true }), true);
});

test('shareUrl passes only the URL to the share sheet', async () => {
  let payload;
  const nav = { share(data) { payload = data; return Promise.resolve(); } };
  await shareUrl(nav, PASTE_URL);
  // Spread copies the payload out of the vm realm so prototypes compare equal.
  assert.deepEqual({ ...payload }, { url: PASTE_URL });
});

test('shareUrl calls share with navigator as this', async () => {
  let receiver;
  const nav = { share() { receiver = this; return Promise.resolve(); } };
  await shareUrl(nav, PASTE_URL);
  assert.equal(receiver, nav);
});

test('shareUrl resolves "shared" when the share sheet completes', async () => {
  const nav = { share() { return Promise.resolve(); } };
  assert.equal(await shareUrl(nav, PASTE_URL), 'shared');
});

test('shareUrl resolves "cancelled" when the user dismisses the share sheet', async () => {
  const abort = new Error('Share canceled');
  abort.name = 'AbortError';
  const nav = { share() { return Promise.reject(abort); } };
  assert.equal(await shareUrl(nav, PASTE_URL), 'cancelled');
});

test('shareUrl rejects with the original error for any other share failure', async () => {
  const denied = new Error('Must be handling a user gesture');
  denied.name = 'NotAllowedError';
  const nav = { share() { return Promise.reject(denied); } };
  await assert.rejects(shareUrl(nav, PASTE_URL), (err) => err === denied);
});

test('shareUrl rejects instead of throwing when share throws synchronously', async () => {
  const thrown = new Error('Share already in progress');
  thrown.name = 'InvalidStateError';
  const nav = { share() { throw thrown; } };
  // Call first, then assert on the promise: passing a thunk would let
  // assert.rejects turn a synchronous throw into a rejection and hide the bug.
  let pending;
  assert.doesNotThrow(() => { pending = shareUrl(nav, PASTE_URL); });
  await assert.rejects(pending, (err) => err === thrown);
});

test('shareUrl rethrows a non-Error rejection unchanged', async () => {
  for (const reason of [undefined, 'nope']) {
    const nav = { share() { return Promise.reject(reason); } };
    await assert.rejects(shareUrl(nav, PASTE_URL), (err) => err === reason);
  }
});

test('shareUrl rejects an empty URL without calling share', async () => {
  let calls = 0;
  const nav = { share() { calls += 1; return Promise.resolve(); } };
  // Name check, not instanceof: the error is the vm realm's TypeError.
  await assert.rejects(shareUrl(nav, ''), (err) => err.name === 'TypeError');
  assert.equal(calls, 0);
});
