// The public and trusted create pages duplicate the success-panel markup, so
// both must carry the Share button. It starts hidden; create.js reveals it per
// paste when the browser has the Web Share API.
// Run with: node --test tests/js/*.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const CREATE_PAGES = ['static/index.html', 'protected/trusted.html'];

// The <div> element opening at `start` in `html`, found by tracking div nesting.
function divAt(html, start, what) {
  assert.notEqual(start, -1, `no ${what}`);
  const divTag = /<div\b|<\/div>/g;
  divTag.lastIndex = start;
  let depth = 0;
  for (let m = divTag.exec(html); m; m = divTag.exec(html)) {
    depth += m[0] === '</div>' ? -1 : 1;
    if (depth === 0) return html.slice(start, m.index + m[0].length);
  }
  assert.fail(`unclosed ${what}`);
}

function successPanel(page) {
  const html = fs.readFileSync(path.join(ROOT, page), 'utf8');
  return divAt(html, html.indexOf('<div id="success-panel"'), `success panel in ${page}`);
}

test('the success panel markup is identical on both create pages', () => {
  assert.equal(successPanel(CREATE_PAGES[0]), successPanel(CREATE_PAGES[1]));
});

for (const page of CREATE_PAGES) {
  test(`${page} offers a Share button beside Copy that starts hidden`, () => {
    const panel = successPanel(page);
    const wrapper = divAt(panel, panel.indexOf('<div class="copy-wrapper"'), `copy wrapper in ${page}`);
    const buttonTag = (id) => (wrapper.match(new RegExp(`<button\\b[^>]*\\bid="${id}"[^>]*>`)) || [])[0];
    const shareTag = buttonTag('share-btn');
    assert.ok(shareTag, `no share button in the copy wrapper of ${page}`);
    const copyTag = buttonTag('copy-btn');
    assert.ok(copyTag, `no copy button beside Share in ${page}`);
    for (const button of [shareTag, copyTag]) {
      assert.match(button, /\btype="button"/, `buttons in ${page} must not submit a form`);
    }
    const classes = (shareTag.match(/\bclass="([^"]*)"/) || ['', ''])[1].split(/\s+/);
    assert.ok(classes.includes('hidden'), `share button in ${page} must start hidden`);
  });
}
