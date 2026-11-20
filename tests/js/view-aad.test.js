// view.js must bind ciphertext to its paste ID: content encrypted without the
// paste ID as AAD, or under another paste ID, must not decrypt.
// Run with: node --test tests/js/*.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadNullpadUtils, loadRealCrypto, loadViewJs } = require('./view-harness.js');

const PASTE_ID = 'abcdefghijkl';

async function viewPasteEncryptedWith(aad) {
  const NullpadCrypto = loadRealCrypto();
  const key = NullpadCrypto.generateKey();
  const content = await NullpadCrypto.encryptBytes('hello', key, aad, { pad: 'content', maxBlobBytes: 52428800 });
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
