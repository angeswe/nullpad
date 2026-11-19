// Paste IDs come from the server (POST /api/paste/reserve), never from the browser.
// Run with: node --test tests/js/*.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadNullpadUtils, loadRealCrypto } = require('./view-harness.js');

const { reservePasteId } = loadNullpadUtils();

function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

test('reservePasteId calls /api/paste/reserve with method POST and nothing else', async () => {
  const calls = [];
  await reservePasteId(async (...args) => {
    calls.push(args);
    return jsonResponse(200, { id: 'abcdefghijkl' });
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].length, 2);
  const [url, init] = calls[0];
  // `init` was created inside the vm context; the spread copies it into this realm.
  assert.deepEqual([url, { ...init }], ['/api/paste/reserve', { method: 'POST' }]);
});

test('reservePasteId returns the id the server sent', async () => {
  const id = await reservePasteId(async () => jsonResponse(200, { id: 'abcdefghijkl' }));
  assert.equal(id, 'abcdefghijkl');
});

test('reservePasteId rejects an id that is not 12 nanoid characters', async () => {
  await assert.rejects(
    reservePasteId(async () => jsonResponse(200, { id: 'abc&burn=1#x' }))
  );
});

test('reservePasteId throws the server error text on a non-2xx response', async () => {
  await assert.rejects(
    reservePasteId(async () => jsonResponse(429, { error: 'Too many requests' })),
    { message: 'Too many requests' }
  );
});

test('crypto.js exports no generateId', () => {
  assert.equal(loadRealCrypto().generateId, undefined);
});

test('create.js takes its paste ID from reservePasteId', () => {
  const src = fs.readFileSync(
    path.join(__dirname, '..', '..', 'static', 'js', 'create.js'), 'utf8'
  );
  assert.ok(src.includes('NullpadUtils.reservePasteId('));
  assert.ok(!src.includes('generateId'));
});
