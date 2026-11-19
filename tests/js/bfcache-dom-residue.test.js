// pagehide must clear decrypted plaintext from the DOM, and a page restored
// from the back-forward cache must reload, so Back cannot repaint a paste
// (including a burned one) after the user leaves the page.
// Run with: node --test tests/js/*.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadViewJs } = require('./view-harness.js');

const SECRET = 'TOP-SECRET-PLAINTEXT-1234567890';

function loadDecryptedView() {
  return loadViewJs({ search: '?id=abcdefghijkl', hash: '#key' }, {
    fetch: () => Promise.resolve({ ok: true, arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)) }),
    NullpadCrypto: {
      base64urlDecode: () => new Uint8Array(32),
      decrypt: () => Promise.resolve(new TextEncoder().encode(SECRET))
    },
    NullpadUtils: {
      hasBurnHint: () => false,
      shouldRenderMarkdown: () => false,
      parsePasteFrame: () => ({ meta: { burn_after_reading: false }, content: new Uint8Array(32) })
    }
  });
}

async function settle() {
  for (let i = 0; i < 3; i++) await new Promise((resolve) => setImmediate(resolve));
}

function getSingleListener(windowListeners, type) {
  const handlers = windowListeners[type] || [];
  assert.equal(handlers.length, 1, `expected exactly one ${type} listener`);
  return handlers[0];
}

function firePagehide(windowListeners) {
  getSingleListener(windowListeners, 'pagehide')();
}

test('view.js clears rendered plaintext from the DOM on pagehide (bfcache-safe)', async () => {
  const { elements, windowListeners } = loadDecryptedView();
  await settle();
  assert.equal(elements['raw-content'].textContent, SECRET,
    'precondition failed: decrypted plaintext never reached #raw-content');

  firePagehide(windowListeners);

  assert.equal(elements['raw-content'].textContent, '');
});

test('view.js pagehide empties #content-display and hides #content-panel', async () => {
  const { elements, windowListeners } = loadDecryptedView();
  await settle();
  elements['content-display'].appendChild({ textContent: SECRET });
  assert.equal(elements['content-panel'].classList.contains('hidden'), false,
    'precondition failed: #content-panel was never shown');

  firePagehide(windowListeners);

  assert.equal(elements['content-display'].children.length, 0);
  assert.equal(elements['content-panel'].classList.contains('hidden'), true);
});

test('view.js registers one pageshow handler that reloads only when persisted', async () => {
  const { windowListeners, reloadCalls } = loadDecryptedView();
  await settle();
  const onPageshow = getSingleListener(windowListeners, 'pageshow');

  onPageshow({ persisted: false });
  assert.equal(reloadCalls.length, 0);

  onPageshow({ persisted: true });
  assert.equal(reloadCalls.length, 1);
});
