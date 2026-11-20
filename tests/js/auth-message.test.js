// Unit tests for the signed login message built by static/js/auth.js.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const JS_DIR = path.join(__dirname, '..', '..', 'static', 'js');

function loadAuth() {
  const sandbox = { crypto: globalThis.crypto, TextEncoder, Uint8Array, btoa, atob };
  sandbox.window = sandbox;
  for (const file of ['base64.js', 'auth.js']) {
    vm.runInNewContext(fs.readFileSync(path.join(JS_DIR, file), 'utf8'), sandbox);
  }
  return sandbox.NullpadAuth;
}

test('authMessage binds purpose, origin, alias and nonce', () => {
  const auth = loadAuth();
  const nonce = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';

  const message = auth.authMessage('https://paste.example', 'alice', nonce);

  const expected = Buffer.from(
    'nullpad-auth-v1|https://paste.example|alice|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
    'utf8'
  );
  assert.deepEqual(Buffer.from(message), expected);
});
