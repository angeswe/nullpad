// Unit tests for static/js/auth.js (NullpadAuth.login).
// auth.js is a browser IIFE, so it runs in a vm context with stub fetch,
// sessionStorage and hash-wasm, and Node's real Web Crypto for Ed25519.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const JS_DIR = path.join(__dirname, '..', '..', 'static', 'js');

function loadAuth(fetchStub) {
  const store = new Map();
  const sandbox = {
    crypto: globalThis.crypto,
    TextEncoder,
    Uint8Array,
    btoa,
    atob,
    fetch: fetchStub,
    hashwasm: { argon2id: async () => new Uint8Array(32).fill(7) },
    sessionStorage: {
      setItem: (k, v) => store.set(k, v),
      getItem: (k) => store.get(k) ?? null,
      removeItem: (k) => store.delete(k),
    },
  };
  sandbox.window = sandbox;
  for (const file of ['base64.js', 'auth.js']) {
    vm.runInNewContext(fs.readFileSync(path.join(JS_DIR, file), 'utf8'), sandbox);
  }
  return sandbox.NullpadAuth;
}

function jsonResponse(body) {
  return { ok: true, json: async () => body };
}

test('login sends the challenge id from /api/auth/challenge to /api/auth/verify', async () => {
  const challengeId = '0123456789abcdef0123456789abcdef';
  const requests = [];
  const auth = loadAuth(async (url, init) => {
    requests.push({ url, body: JSON.parse(init.body) });
    if (url === '/api/auth/challenge') {
      return jsonResponse({ challenge_id: challengeId, nonce: btoa('n'.repeat(32)) });
    }
    return jsonResponse({ token: 'tok', role: 'trusted' });
  });

  await auth.login('secret', 'alice');

  const verify = requests.find((r) => r.url === '/api/auth/verify');
  assert.equal(verify.body.alias, 'alice');
  assert.equal(verify.body.challenge_id, challengeId);
});
