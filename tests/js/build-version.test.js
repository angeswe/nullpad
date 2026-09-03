// Tests for the footer build version: every page links the stamped version
// to its GitHub commit, and tools/stamp-build-version.sh fills in the
// placeholders the way the Dockerfiles rely on.
// Run with: node --test tests/js/*.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..', '..');
const PAGE_DIRS = ['static', 'protected'];
const REPO_URL = 'https://github.com/angeswe/nullpad';
const SCRIPT = path.join('tools', 'stamp-build-version.sh');
const FULL_SHA = 'a4cee7e1b2c3d4e5f60718293a4b5c6d7e8f9012';

function footerLink(href, text) {
  return `<a class="build-version" href="${href}" target="_blank" rel="noopener">${text}</a>`;
}

// Top-level HTML pages under static/ and protected/, as repo-relative paths.
function pages(root) {
  return PAGE_DIRS.flatMap((dir) =>
    fs
      .readdirSync(path.join(root, dir))
      .filter((name) => name.endsWith('.html'))
      .map((name) => path.join(dir, name))
  );
}

// Run `fn` against a throwaway copy of the pages and the stamping script, so
// the script (which edits files in place) never touches the real tree.
function withScratchTree(fn) {
  const tree = fs.mkdtempSync(path.join(os.tmpdir(), 'nullpad-stamp-'));
  try {
    for (const file of [...pages(ROOT), SCRIPT]) {
      fs.mkdirSync(path.join(tree, path.dirname(file)), { recursive: true });
      fs.copyFileSync(path.join(ROOT, file), path.join(tree, file));
    }
    return fn(tree);
  } finally {
    fs.rmSync(tree, { recursive: true, force: true });
  }
}

function stamp(tree, args) {
  return execFileSync('bash', [path.join(tree, SCRIPT), ...args], { stdio: 'pipe' });
}

function readPages(tree) {
  return pages(tree).map((page) => fs.readFileSync(path.join(tree, page), 'utf8'));
}

function assertEveryPageStamped(version, href) {
  withScratchTree((tree) => {
    stamp(tree, [version]);
    for (const page of pages(tree)) {
      const html = fs.readFileSync(path.join(tree, page), 'utf8');
      assert.ok(html.includes(footerLink(href, version)), `${page} was not stamped with ${href}`);
      assert.ok(!html.includes('__BUILD_'), `${page} still contains a build placeholder`);
    }
  });
}

// assert.throws validator: the script exited 1 and explained why on stderr.
// Asserting inside keeps the status and stderr in the failure message.
function stampFailure(pattern) {
  return (err) => {
    assert.equal(err.status, 1, `unexpected exit status; stderr: ${err.stderr}`);
    assert.match(String(err.stderr), pattern);
    return true;
  };
}

// The script must exit 1 with a stderr message matching `pattern` and leave
// every page exactly as `prepare` (if any) left it.
function assertStampRejects(args, pattern, prepare = () => {}) {
  withScratchTree((tree) => {
    prepare(tree);
    const before = readPages(tree);
    assert.throws(() => stamp(tree, args), stampFailure(pattern));
    assert.deepEqual(readPages(tree), before, 'pages must be untouched when stamping is rejected');
  });
}

test('every page footer links the build version placeholder to the commit URL placeholder', () => {
  const found = pages(ROOT);
  assert.ok(found.length > 0, 'expected at least one HTML page');
  for (const page of found) {
    const html = fs.readFileSync(path.join(ROOT, page), 'utf8');
    assert.ok(
      html.includes(footerLink('__BUILD_COMMIT_URL__', '__BUILD_VERSION__')),
      `${page} is missing the linked build version footer`
    );
    // Keeps the footer GitHub link, the script and this test pointing at one repo.
    assert.ok(
      html.includes(`<a href="${REPO_URL}" target="_blank" rel="noopener">GitHub</a>`),
      `${page} footer GitHub link does not point at ${REPO_URL}`
    );
  }
});

test('stamp-build-version.sh links a short commit SHA to its GitHub commit on every page', () => {
  assertEveryPageStamped('a4cee7e', `${REPO_URL}/commit/a4cee7e`);
});

test('stamp-build-version.sh links a full-length commit SHA to its GitHub commit', () => {
  assertEveryPageStamped(FULL_SHA, `${REPO_URL}/commit/${FULL_SHA}`);
});

test('stamp-build-version.sh links the dev version to the repository', () => {
  assertEveryPageStamped('dev', REPO_URL);
});

test('stamp-build-version.sh fails when no version is given', () => {
  assertStampRejects([], /usage: .*stamp-build-version\.sh <version>/);
});

test('stamp-build-version.sh rejects a version that is neither a commit SHA nor dev', () => {
  assertStampRejects(['v1.2.3'], /neither a commit SHA/);
});

test('stamp-build-version.sh rejects a version with sed and HTML metacharacters', () => {
  assertStampRejects(['1&<b>2'], /neither a commit SHA/);
});

test('stamp-build-version.sh fails when a page has already been stamped', () => {
  assertStampRejects(['a4cee7e'], /has no build placeholders to stamp/, (tree) => stamp(tree, ['a4cee7e']));
});

test('stamp-build-version.sh fails when a placeholder survives stamping', () => {
  withScratchTree((tree) => {
    fs.writeFileSync(
      path.join(tree, 'static', 'stray.html'),
      `${footerLink('__BUILD_COMMIT_URL__', '__BUILD_VERSION__')}\n<p>__BUILD_NUMBER__</p>\n`
    );
    assert.throws(() => stamp(tree, ['a4cee7e']), stampFailure(/placeholders remain in: static\/stray\.html/));
  });
});

test('stamp-build-version.sh fails when a page in a subdirectory still holds a placeholder', () => {
  withScratchTree((tree) => {
    fs.mkdirSync(path.join(tree, 'static', 'sub'));
    fs.writeFileSync(
      path.join(tree, 'static', 'sub', 'page.html'),
      `${footerLink('__BUILD_COMMIT_URL__', '__BUILD_VERSION__')}\n`
    );
    assert.throws(() => stamp(tree, ['a4cee7e']), stampFailure(/placeholders remain in: static\/sub\/page\.html/));
  });
});
