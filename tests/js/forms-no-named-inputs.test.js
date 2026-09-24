// Guards against a native form submit putting secrets in the URL.
// Run with: node --test tests/js/*.test.js
//
// Every nullpad form submits through fetch() in JS. A native submit can still
// happen: Enter pressed before the JS listener is attached, JS disabled, or a
// script that fails to load or fails its SRI check. The browser default is a
// GET to the same URL, and every field with a `name` attribute goes into the
// query string, where proxies log it and browser history keeps it.
//
// The CSP `form-action 'none'` (src/middleware.rs) blocks the submit. These
// tests are the second guard: fields without a `name` are never submitted, and
// method="post" keeps form data out of the URL if a page loses the CSP rule.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.join(__dirname, '..', '..');
const HTML_DIRS = ['static', 'protected'];

// The attribute part of an opening tag. Quoted values may contain '>'.
const TAG_ATTRS = String.raw`((?:[^>"']|"[^"]*"|'[^']*')*)`;
// The lookahead stops `<form` from matching a longer tag name such as `<form-x`.
const FORM_OPEN_RE = new RegExp(String.raw`<form(?=[\s/>])` + TAG_ATTRS + '>', 'gi');
const FORM_CLOSE_RE = /<\/form\s*>/gi;
const FIELD_OPEN_RE = new RegExp(
  String.raw`<(input|textarea|select)(?=[\s/>])` + TAG_ATTRS + '>',
  'gi'
);
// One attribute: a name, then an optional double-quoted, single-quoted or
// unquoted value. Matching whole attribute names means `data-name=` is read as
// the attribute `data-name`, not `name`.
const ATTR_RE = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

// Returns a Map of lower-cased attribute name to value. When an attribute
// repeats, the first one wins, as in the HTML parser.
function parseAttrs(attrText) {
  const attrs = new Map();
  for (const m of attrText.matchAll(ATTR_RE)) {
    const name = m[1].toLowerCase();
    if (!attrs.has(name)) {
      attrs.set(name, m[2] ?? m[3] ?? m[4] ?? '');
    }
  }
  return attrs;
}

function listHtmlFiles() {
  const files = [];
  for (const dir of HTML_DIRS) {
    for (const entry of fs.readdirSync(path.join(REPO_ROOT, dir), { withFileTypes: true })) {
      if (entry.isFile() && /\.html$/i.test(entry.name)) {
        files.push(path.join(dir, entry.name));
      }
    }
  }
  return files.sort();
}

// Returns one record per <form>: its file, id, opening tag, attributes, and the
// input/textarea/select opening tags between it and the next </form>.
function collectForms() {
  const forms = [];
  for (const file of listHtmlFiles()) {
    // A commented-out form is never rendered, so it cannot be submitted.
    const html = fs
      .readFileSync(path.join(REPO_ROOT, file), 'utf8')
      .replace(/<!--[\s\S]*?-->/g, '');
    for (const open of html.matchAll(FORM_OPEN_RE)) {
      const bodyStart = open.index + open[0].length;
      FORM_CLOSE_RE.lastIndex = bodyStart;
      const close = FORM_CLOSE_RE.exec(html);
      const body = html.slice(bodyStart, close ? close.index : html.length);
      const attrs = parseAttrs(open[1]);
      forms.push({
        file,
        id: attrs.get('id') ?? '(no id)',
        tag: open[0],
        attrs,
        fields: [...body.matchAll(FIELD_OPEN_RE)].map((m) => ({
          tag: m[1].toLowerCase(),
          attrs: parseAttrs(m[2]),
        })),
      });
    }
  }
  return forms;
}

const forms = collectForms();

test('finds every form in static/ and protected/ HTML', () => {
  const found = forms.map((f) => `${f.file} form#${f.id}`).join(', ');
  assert.ok(
    forms.length >= 6,
    `expected at least 6 <form> elements, found ${forms.length}: ${found || 'none'}`
  );
});

test('no form contains an input, textarea or select with a name attribute', () => {
  const violations = [];
  for (const form of forms) {
    for (const field of form.fields) {
      if (field.attrs.has('name')) {
        violations.push(
          `${form.file} form#${form.id}: <${field.tag}> name="${field.attrs.get('name')}"`
        );
      }
    }
  }
  assert.deepEqual(
    violations,
    [],
    `a native submit puts named fields in the URL:\n  ${violations.join('\n  ')}`
  );
});

test('every form declares method="post"', () => {
  const violations = forms
    .filter((form) => (form.attrs.get('method') ?? '').toLowerCase() !== 'post')
    .map((form) => `${form.file} form#${form.id}: ${form.tag}`);
  assert.deepEqual(
    violations,
    [],
    `forms without method="post" submit as GET:\n  ${violations.join('\n  ')}`
  );
});
