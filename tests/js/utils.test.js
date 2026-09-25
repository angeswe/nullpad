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
  // URLSearchParams is a WHATWG global, not part of the ECMAScript globals a
  // fresh vm context gets by default, but hasBurnHint (like view.js's own
  // parseUrl) relies on it — pass Node's implementation through.
  // TextDecoder is also a WHATWG global; parsePasteFrame uses it.
  vm.runInNewContext(src, { window, URLSearchParams, TextDecoder });
  return window.NullpadUtils;
}

const {
  shouldRenderMarkdown,
  contentTypeForFile,
  contentTypeForRenderMode,
  canOfferShare,
  shareUrl,
  pasteViewUrl,
  hasBurnHint,
  parsePasteFrame
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

test('canOfferShare returns false when the browser has no Web Share API', () => {
  assert.equal(canOfferShare({}), false);
});

test('canOfferShare returns true when navigator.share is a function', () => {
  assert.equal(canOfferShare({ share() {} }), true);
});

test('pasteViewUrl builds origin/view.html?id=<id>#<fragment> for a plain paste', () => {
  assert.equal(
    pasteViewUrl('https://example.test', 'abc123', 'key.salt', { burnAfterReading: false, hasPin: false }),
    'https://example.test/view.html?id=abc123#key.salt'
  );
});

test('pasteViewUrl appends &burn=1 before the fragment for a burn-after-reading paste without a PIN', () => {
  assert.equal(
    pasteViewUrl('https://example.test', 'abc123', 'key.salt', { burnAfterReading: true, hasPin: false }),
    'https://example.test/view.html?id=abc123&burn=1#key.salt'
  );
});

test('pasteViewUrl omits the burn hint for a burn-after-reading paste with a PIN', () => {
  assert.equal(
    pasteViewUrl('https://example.test', 'abc123', 'key.salt', { burnAfterReading: true, hasPin: true }),
    'https://example.test/view.html?id=abc123#key.salt'
  );
});

test('pasteViewUrl omits the burn hint for a PIN paste that does not burn', () => {
  assert.equal(
    pasteViewUrl('https://example.test', 'abc123', 'key.salt', { burnAfterReading: false, hasPin: true }),
    'https://example.test/view.html?id=abc123#key.salt'
  );
});

test('hasBurnHint returns true for ?id=abc&burn=1', () => {
  assert.equal(hasBurnHint('?id=abc&burn=1'), true);
});

test('hasBurnHint returns false when burn is absent', () => {
  assert.equal(hasBurnHint('?id=abc'), false);
});

test('hasBurnHint returns false for burn=0 or burn=true (only the literal 1 counts)', () => {
  assert.equal(hasBurnHint('?id=abc&burn=0'), false);
  assert.equal(hasBurnHint('?id=abc&burn=true'), false);
});

test('hasBurnHint accepts a search string without the leading question mark', () => {
  assert.equal(hasBurnHint('id=abc&burn=1'), true);
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

// ============================================================================
// parsePasteFrame: u32 big-endian JSON length, JSON meta, then ciphertext
// ============================================================================

// Build a paste frame the way the server does.
function buildPasteFrame(meta, content) {
  const json = new TextEncoder().encode(JSON.stringify(meta));
  const buf = new ArrayBuffer(4 + json.length + content.length);
  new DataView(buf).setUint32(0, json.length, false);
  new Uint8Array(buf, 4, json.length).set(json);
  new Uint8Array(buf, 4 + json.length).set(content);
  return buf;
}

test('parsePasteFrame returns meta and content', () => {
  const content = new Uint8Array([1, 2, 3, 250, 0, 255]);
  const frame = buildPasteFrame(
    { encrypted_metadata: 'bWV0YQ', burn_after_reading: true, created_at: 1700000000 },
    content
  );
  const parsed = parsePasteFrame(frame);
  assert.equal(parsed.meta.encrypted_metadata, 'bWV0YQ');
  assert.equal(parsed.meta.burn_after_reading, true);
  assert.equal(parsed.meta.created_at, 1700000000);
  // Compare as plain arrays: the Uint8Array comes from the vm realm.
  assert.deepEqual(Array.from(parsed.content), Array.from(content));
});

test('parsePasteFrame throws on truncated frame', () => {
  const frame = buildPasteFrame({ needs_pin: true }, new Uint8Array(0));
  // Cut the JSON short: the length prefix now claims more bytes than exist.
  const truncated = frame.slice(0, frame.byteLength - 2);
  assert.throws(() => parsePasteFrame(truncated), (err) => /paste frame/i.test(err.message));
});

test('parsePasteFrame throws on buffer shorter than 4 bytes', () => {
  assert.throws(() => parsePasteFrame(new ArrayBuffer(3)), (err) => /paste frame/i.test(err.message));
});

test('parsePasteFrame keeps the JSON parse error', () => {
  const badJson = '{"needs_pin": tru';
  let syntaxError;
  try {
    JSON.parse(badJson);
  } catch (err) {
    syntaxError = err;
  }
  const json = new TextEncoder().encode(badJson);
  const frame = new ArrayBuffer(4 + json.length);
  new DataView(frame).setUint32(0, json.length, false);
  new Uint8Array(frame, 4).set(json);

  assert.throws(() => parsePasteFrame(frame), (err) => {
    assert.ok(
      err.message.includes(syntaxError.message),
      `message should contain "${syntaxError.message}", got "${err.message}"`
    );
    // The cause comes from the vm realm, so check its name, not instanceof.
    assert.equal(err.cause && err.cause.name, 'SyntaxError');
    return true;
  });
});
