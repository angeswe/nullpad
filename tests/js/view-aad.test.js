// view.js must bind ciphertext to its paste ID: content encrypted without the
// paste ID as AAD, or under another paste ID, must not decrypt.
// Run with: node --test tests/js/*.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { loadNullpadUtils, loadViewJs } = require('./view-harness.js');

const ROOT = path.join(__dirname, '..', '..');
const PASTE_ID = 'abcdefghijkl';

function loadRealCrypto() {
  const sandbox = { window: {}, crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array, btoa, atob };
  sandbox.window = sandbox;
  for (const file of ['base64.js', 'crypto.js']) {
    vm.runInNewContext(fs.readFileSync(path.join(ROOT, 'static', 'js', file), 'utf8'), sandbox);
  }
  return sandbox.NullpadCrypto;
}

async function viewPasteEncryptedWith(aad) {
  const NullpadCrypto = loadRealCrypto();
  const key = NullpadCrypto.generateKey();
  const content = NullpadCrypto.base64Decode(await NullpadCrypto.encrypt('hello', key, aad));
  const view = loadViewJs(
    { search: `?id=${PASTE_ID}`, hash: `#${key}` },
    {
      NullpadCrypto,
      NullpadUtils: { ...loadNullpadUtils(), parsePasteFrame: (frame) => frame },
      fetch: async () => ({ ok: true, status: 200, arrayBuffer: async () => ({ meta: {}, content }) })
    }
  );
  await new Promise((resolve) => setTimeout(resolve, 50));
  return view;
}

function assertDecryptFailure({ elements, consoleCalls }) {
  assert.ok(!elements['pin-prompt'].classList.contains('hidden'), 'a decrypt failure must fall back to the PIN prompt');
  const failure = consoleCalls.error.find((args) => args[0] === 'Paste decryption failed:');
  assert.ok(failure, 'the decrypt failure must be logged');
  assert.equal(failure[1].name, 'OperationError');
}

test('paste encrypted with its own ID as AAD decrypts', async () => {
  const { elements, consoleCalls } = await viewPasteEncryptedWith(PASTE_ID);
  assert.deepEqual(consoleCalls.error, []);
  assert.ok(elements['pin-prompt'].classList.contains('hidden'), 'content must be shown, not the PIN prompt');
});

test('paste encrypted without AAD is reported as a decrypt failure', async () => {
  assertDecryptFailure(await viewPasteEncryptedWith(undefined));
});

test('paste encrypted under a different paste ID is reported as a decrypt failure', async () => {
  assertDecryptFailure(await viewPasteEncryptedWith('zyxwvutsrqpo'));
});
