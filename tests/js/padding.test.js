// encrypt() pads framed plaintext to a fixed size so the ciphertext length hides
// the content length; decrypt() must return the exact original bytes.
// Run with: node --test tests/js/*.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadRealCrypto } = require('./view-harness.js');

const AES_GCM_OVERHEAD = 28;
const MiB = 1024 * 1024;
const DEFAULT_MAX_UPLOAD_BYTES = 50 * MiB;

const NullpadCrypto = loadRealCrypto();

function randomBytes(size) {
  const bytes = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 65536) {
    crypto.getRandomValues(bytes.subarray(offset, Math.min(offset + 65536, size)));
  }
  return bytes;
}

function assertSameBytes(actual, expected) {
  assert.equal(actual.length, expected.length);
  assert.ok(Buffer.from(actual.buffer, actual.byteOffset, actual.length).equals(Buffer.from(expected)), 'decrypted bytes differ from the original');
}

async function rawDecrypt(blob, key) {
  const cryptoKey = await crypto.subtle.importKey('raw', NullpadCrypto.base64urlDecode(key), 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(0, 12) }, cryptoKey, blob.subarray(12)));
}

async function rawEncrypt(plaintext, key) {
  const cryptoKey = await crypto.subtle.importKey('raw', NullpadCrypto.base64urlDecode(key), 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext));
  const blob = new Uint8Array(12 + ciphertext.length);
  blob.set(iv, 0);
  blob.set(ciphertext, 12);
  return blob;
}

for (const [size, bucket] of [
  [0, 1024],
  [1, 1024],
  [1023, 4096],
  [1024, 4096],
  [1025, 4096],
  [MiB, 4 * MiB]
]) {
  test(`content of ${size} bytes encrypts to ${bucket} + 28 bytes and decrypts to the same bytes`, async () => {
    const key = NullpadCrypto.generateKey();
    const original = randomBytes(size);
    const blob = NullpadCrypto.base64Decode(await NullpadCrypto.encrypt(original, key, 'abcdefghijkl', { pad: 'content', maxBlobBytes: DEFAULT_MAX_UPLOAD_BYTES }));
    assert.equal(blob.length, bucket + AES_GCM_OVERHEAD);
    assertSameBytes(await NullpadCrypto.decrypt(blob, key, 'abcdefghijkl'), original);
  });
}

test('content of 50 MiB is rejected before encryption because it exceeds the top bucket', async () => {
  await assert.rejects(
    NullpadCrypto.encrypt(new Uint8Array(50 * MiB), NullpadCrypto.generateKey(), 'abcdefghijkl', { pad: 'content', maxBlobBytes: DEFAULT_MAX_UPLOAD_BYTES }),
    { message: 'Content too large: exceeds maximum supported upload size.' }
  );
});

for (const metadata of ['', 'a', '{"filename":"report.pdf","mime":"application/pdf"}']) {
  test(`metadata of ${metadata.length} chars encrypts to 512 + 28 bytes and decrypts to the same text`, async () => {
    const key = NullpadCrypto.generateKey();
    const encrypted = await NullpadCrypto.encrypt(metadata, key, 'abcdefghijkl', { pad: 'metadata' });
    assert.equal(NullpadCrypto.base64Decode(encrypted).length, 512 + AES_GCM_OVERHEAD);
    assert.equal(new TextDecoder().decode(await NullpadCrypto.decrypt(encrypted, key, 'abcdefghijkl')), metadata);
  });
}

test('v1 plaintext is version byte 0x01, little-endian length, data, then zero padding', async () => {
  const key = NullpadCrypto.generateKey();
  const original = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const blob = NullpadCrypto.base64Decode(await NullpadCrypto.encrypt(original, key, undefined, { pad: 'content', maxBlobBytes: DEFAULT_MAX_UPLOAD_BYTES }));
  const plaintext = await rawDecrypt(blob, key);
  assert.equal(plaintext.length, 1024);
  assert.equal(plaintext[0], 0x01);
  assert.equal(new DataView(plaintext.buffer).getUint32(1, true), original.length);
  assertSameBytes(plaintext.subarray(5, 9), original);
  assert.ok(plaintext.subarray(9).every((byte) => byte === 0), 'padding must be zero bytes');
});

test('v0 legacy plaintext without a version byte is returned unchanged', async () => {
  const key = NullpadCrypto.generateKey();
  const legacy = new TextEncoder().encode('legacy paste');
  assertSameBytes(await NullpadCrypto.decrypt(await rawEncrypt(legacy, key), key), legacy);
});

test('v0 legacy plaintext starting with 0x01 and a length larger than the body is returned unchanged', async () => {
  const key = NullpadCrypto.generateKey();
  const legacy = new Uint8Array([0x01, 0xff, 0x00, 0x00, 0x00, 0x41, 0x42]);
  assertSameBytes(await NullpadCrypto.decrypt(await rawEncrypt(legacy, key), key), legacy);
});

test('v0 legacy plaintext starting with 0x01 and a length within the body is truncated as if it were v1', async () => {
  const key = NullpadCrypto.generateKey();
  const legacy = new Uint8Array([0x01, 0x01, 0x00, 0x00, 0x00, 0x41, 0x42]);
  assertSameBytes(await NullpadCrypto.decrypt(await rawEncrypt(legacy, key), key), new Uint8Array([0x41]));
});

test('contentPadTarget clamps the bucket to the cap', () => {
  assert.equal(NullpadCrypto.contentPadTarget(5 * MiB + 5, 10 * MiB), 10 * MiB - 28);
});

test('contentPadTarget keeps ladder buckets below the cap', () => {
  assert.equal(NullpadCrypto.contentPadTarget(100, 10 * MiB), 1024);
  assert.equal(NullpadCrypto.contentPadTarget(70000, 262172), 262144);
  assert.equal(NullpadCrypto.contentPadTarget(262143, 262172), 262144);
});

test('contentPadTarget returns null at cap - 28 and above', () => {
  assert.equal(NullpadCrypto.contentPadTarget(262144, 262172), null);
  assert.equal(NullpadCrypto.contentPadTarget(10 * MiB - 28, 10 * MiB), null);
  assert.equal(NullpadCrypto.contentPadTarget(10 * MiB - 29, 10 * MiB), 10 * MiB - 28);
});

test('contentPadTarget rejects a cap that is not an integer from 34 to 2^32 - 1', () => {
  for (const cap of [undefined, 33, 1.5, 2 ** 32]) {
    assert.throws(() => NullpadCrypto.contentPadTarget(100, cap), { name: 'TypeError' });
  }
});

test('maxContentBytes is the largest content contentPadTarget still accepts', () => {
  for (const cap of [34, DEFAULT_MAX_UPLOAD_BYTES]) {
    const max = NullpadCrypto.maxContentBytes(cap);
    assert.equal(NullpadCrypto.contentPadTarget(max + 5, cap), cap - AES_GCM_OVERHEAD);
    assert.equal(NullpadCrypto.contentPadTarget(max + 6, cap), null);
  }
  assert.equal(NullpadCrypto.maxContentBytes(34), 0);
});

test('content under a non-default cap encrypts to exactly the cap', async () => {
  const key = NullpadCrypto.generateKey();
  const original = randomBytes(70000);
  const blob = NullpadCrypto.base64Decode(await NullpadCrypto.encrypt(original, key, 'abcdefghijkl', { pad: 'content', maxBlobBytes: 100000 }));
  assert.equal(blob.length, 100000);
  assertSameBytes(await NullpadCrypto.decrypt(blob, key, 'abcdefghijkl'), original);
});

test('encrypt with pad content and no maxBlobBytes throws TypeError', async () => {
  await assert.rejects(
    NullpadCrypto.encrypt(new Uint8Array(10), NullpadCrypto.generateKey(), 'abcdefghijkl', { pad: 'content' }),
    { name: 'TypeError' }
  );
});

test('create.js contains no literal 52428800', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'static', 'js', 'create.js'), 'utf8');
  assert.ok(!src.includes('52428800'), 'create.js hard-codes 52428800; the cap must come from the server');
});
