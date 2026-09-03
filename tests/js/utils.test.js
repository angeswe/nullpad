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

const { shouldRenderMarkdown, contentTypeForFile, contentTypeForRenderMode } = loadNullpadUtils();

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
