// Regression tests for tools/verify-vendor.sh and tools/update-sri.sh: both
// must find a <script> tag's src="/js/..." attribute regardless of where it
// sits among the tag's other attributes (e.g. "<script defer src=...>"),
// not just when src is the first attribute in the tag.
// Run with: node --test tests/js/*.test.js

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..', '..');
const VERIFY_SCRIPT = path.join('tools', 'verify-vendor.sh');
const UPDATE_SCRIPT = path.join('tools', 'update-sri.sh');
const SCRIPT_TAGS_PL = path.join('tools', 'lib', 'script-tags.pl');

// The scripts `cd` to their own parent directory, so a scratch tree needs
// the same tools/<name> layout as the real repo. The shared tag parser is
// always copied in too, since both scripts under test now shell out to it.
// Other tools (sync-licenses.sh etc.) are not needed because SRI_ONLY=1
// skips every section but the SRI attribute check.
function withScratchTree(fn) {
  const tree = fs.mkdtempSync(path.join(os.tmpdir(), 'nullpad-vendor-sri-'));
  try {
    for (const script of [VERIFY_SCRIPT, UPDATE_SCRIPT, SCRIPT_TAGS_PL]) {
      fs.mkdirSync(path.join(tree, path.dirname(script)), { recursive: true });
      fs.copyFileSync(path.join(ROOT, script), path.join(tree, script));
    }
    return fn(tree);
  } finally {
    fs.rmSync(tree, { recursive: true, force: true });
  }
}

function sriHash(content) {
  return 'sha384-' + crypto.createHash('sha384').update(content).digest('base64');
}

// Writes a fixture static dir (named to prove the STATIC_DIR override works
// rather than relying on the script's "static" default) containing one HTML
// page and one referenced JS file.
function writeFixture(tree, html, jsContent) {
  const staticDir = path.join(tree, 'webroot');
  fs.mkdirSync(path.join(staticDir, 'js'), { recursive: true });
  fs.writeFileSync(path.join(staticDir, 'index.html'), html);
  fs.writeFileSync(path.join(staticDir, 'js', 'x.js'), jsContent);
  return staticDir;
}

function runVerify(tree) {
  return execFileSync('bash', [path.join(tree, VERIFY_SCRIPT)], {
    cwd: tree,
    stdio: 'pipe',
    env: { ...process.env, SRI_ONLY: '1', STATIC_DIR: 'webroot' }
  });
}

function runVerifyExpectFailure(tree) {
  try {
    runVerify(tree);
    assert.fail('expected verify-vendor.sh to exit non-zero');
  } catch (err) {
    assert.equal(err.status, 1, `unexpected exit status; stdout: ${err.stdout}`);
    return String(err.stdout);
  }
}

function runUpdateSri(tree) {
  execFileSync('bash', [path.join(tree, UPDATE_SCRIPT)], {
    cwd: tree,
    stdio: 'pipe',
    env: { ...process.env, STATIC_DIR: 'webroot' }
  });
}

test('verify-vendor.sh rejects a script tag with an attribute before src and no integrity', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("x");\n';
    writeFixture(tree, '<script defer src="/js/x.js"></script>\n', jsContent);
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /missing integrity attribute/);
    assert.match(stdout, /\/js\/x\.js/);
  });
});

test('verify-vendor.sh accepts an attribute-first script tag with a correct integrity hash', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("x");\n';
    const hash = sriHash(jsContent);
    writeFixture(
      tree,
      `<script src="/js/x.js" integrity="${hash}" crossorigin="anonymous"></script>\n`,
      jsContent
    );
    const stdout = runVerify(tree).toString();
    assert.match(stdout, /All checks passed/);
  });
});

test('verify-vendor.sh rejects a defer-first script tag even when other attributes are present after src', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("y");\n';
    writeFixture(tree, '<script defer src="/js/x.js" async></script>\n', jsContent);
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /missing integrity attribute/);
  });
});

test('update-sri.sh rewrites the integrity attribute on a defer-first script tag', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("x");\n';
    const hash = sriHash(jsContent);
    const staticDir = writeFixture(tree, '<script defer src="/js/x.js"></script>\n', jsContent);
    runUpdateSri(tree);
    const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
    assert.ok(html.includes(`integrity="${hash}"`), `expected updated integrity hash in: ${html}`);
    assert.ok(html.includes('crossorigin="anonymous"'), `expected crossorigin attribute in: ${html}`);
    assert.ok(html.includes('defer'), `expected the defer attribute to survive rewriting: ${html}`);
    assert.ok(html.includes('src="/js/x.js"'), `expected src attribute preserved: ${html}`);
  });
});

test('update-sri.sh replaces a stale integrity attribute on a defer-first tag rather than duplicating it', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("z");\n';
    const hash = sriHash(jsContent);
    const staticDir = writeFixture(
      tree,
      '<script defer src="/js/x.js" integrity="sha384-stale" crossorigin="anonymous"></script>\n',
      jsContent
    );
    runUpdateSri(tree);
    const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
    assert.ok(html.includes(`integrity="${hash}"`), `expected refreshed integrity hash in: ${html}`);
    assert.ok(!html.includes('sha384-stale'), `stale hash should have been replaced: ${html}`);
    const integrityCount = (html.match(/integrity=/g) || []).length;
    assert.equal(integrityCount, 1, `expected exactly one integrity attribute in: ${html}`);
  });
});

// --- Single-quoted src and multi-line tags (quote-style / line-span blind spots) ---

test('verify-vendor.sh rejects a single-quoted script src with no integrity attribute', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("single-quote");\n';
    writeFixture(tree, "<script src='/js/x.js'></script>\n", jsContent);
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /missing integrity attribute/);
    assert.match(stdout, /\/js\/x\.js/);
  });
});

test('verify-vendor.sh rejects a script tag whose attributes span multiple lines with no integrity attribute', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("multiline");\n';
    writeFixture(tree, '<script\n  defer\n  src="/js/x.js"\n></script>\n', jsContent);
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /missing integrity attribute/);
    assert.match(stdout, /\/js\/x\.js/);
  });
});

test('update-sri.sh rewrites a single-quoted script tag', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("single-quote");\n';
    const hash = sriHash(jsContent);
    const staticDir = writeFixture(tree, "<script src='/js/x.js'></script>\n", jsContent);
    runUpdateSri(tree);
    const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
    assert.ok(html.includes(`integrity="${hash}"`), `expected updated integrity hash in: ${html}`);
    assert.ok(html.includes('crossorigin="anonymous"'), `expected crossorigin attribute in: ${html}`);
  });
});

test('update-sri.sh rewrites a script tag whose attributes span multiple lines', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("multiline");\n';
    const hash = sriHash(jsContent);
    const staticDir = writeFixture(tree, '<script\n  defer\n  src="/js/x.js"\n></script>\n', jsContent);
    runUpdateSri(tree);
    const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
    assert.ok(html.includes(`integrity="${hash}"`), `expected updated integrity hash in: ${html}`);
    assert.ok(html.includes('crossorigin="anonymous"'), `expected crossorigin attribute in: ${html}`);
    assert.ok(html.includes('defer'), `expected the defer attribute to survive rewriting: ${html}`);
  });
});

// --- Upstream verification: registry is the trust anchor, not versions.json ---
//
// A malicious PR could edit versions.json's tarball/dist_integrity/tarball_path
// together so they are self-consistent while pointing at an attacker-hosted
// tarball. These fields must never be trusted on their own: the tarball host
// is checked against registry.npmjs.org BEFORE any network call is made, so
// this is fully offline/hermetic (a stub `curl` on PATH proves zero network
// calls happen for the malicious entry).
function writeFakeCurlThatFails(tree) {
  const binDir = path.join(tree, 'fakebin');
  fs.mkdirSync(binDir, { recursive: true });
  const logPath = path.join(tree, 'curl-invocations.log');
  const curlPath = path.join(binDir, 'curl');
  fs.writeFileSync(
    curlPath,
    '#!/bin/bash\necho "$@" >> "' + logPath + '"\nexit 1\n'
  );
  fs.chmodSync(curlPath, 0o755);
  return { binDir, logPath };
}

// The fixture uses 'purify.min.js' / 'dompurify' because verify-vendor.sh
// now hard-codes a filename -> registry_package pin, and only real vendored
// filenames are pinned. Passing a made-up filename would fail on "no pinned
// registry_package" before ever reaching the check under test.
const PINNED_FILE = 'purify.min.js';
const PINNED_PACKAGE = 'dompurify';

function writeFullFixtureTree(tree, manifestEntry) {
  // A minimal but complete tree for a non-SRI_ONLY run: vendor dir + JS
  // file + versions.json + a no-op sync-licenses.sh (so the license-table
  // sync check trivially passes) + tools/verify-vendor.sh + the shared tag
  // parser (unused by this section, but harmless to have present).
  fs.mkdirSync(path.join(tree, 'tools', 'lib'), { recursive: true });
  fs.copyFileSync(path.join(ROOT, VERIFY_SCRIPT), path.join(tree, VERIFY_SCRIPT));
  fs.copyFileSync(path.join(ROOT, SCRIPT_TAGS_PL), path.join(tree, SCRIPT_TAGS_PL));
  fs.writeFileSync(path.join(tree, 'tools', 'sync-licenses.sh'), '#!/bin/bash\nexit 0\n');
  fs.chmodSync(path.join(tree, 'tools', 'sync-licenses.sh'), 0o755);

  const staticDir = path.join(tree, 'static', 'js', 'vendor');
  fs.mkdirSync(staticDir, { recursive: true });
  const jsContent = 'console.log("vendor");\n';
  fs.writeFileSync(path.join(staticDir, PINNED_FILE), jsContent);
  fs.writeFileSync(path.join(tree, 'static', 'info.html'), '<html></html>\n');

  const sha384 = sriHash(jsContent).replace('sha384-', '');
  const manifest = {
    [PINNED_FILE]: {
      package: manifestEntry.package || PINNED_PACKAGE,
      version: manifestEntry.version || '1.0.0',
      license: 'MIT',
      url: 'https://example.com',
      sha384: `sha384-${sha384}`,
      registry_package: manifestEntry.registry_package || PINNED_PACKAGE,
      tarball: manifestEntry.tarball,
      tarball_path: manifestEntry.tarball_path || `package/${PINNED_FILE}`,
      dist_integrity: manifestEntry.dist_integrity || 'sha512-deadbeef'
    }
  };
  fs.writeFileSync(
    path.join(staticDir, 'versions.json'),
    JSON.stringify(manifest, null, 2)
  );
}

test('verify-vendor.sh (VENDOR_VERIFY_UPSTREAM=1) rejects a non-registry tarball host before any network call', () => {
  withScratchTree((tree) => {
    writeFullFixtureTree(tree, { tarball: 'https://example.com/x.tgz' });
    const { binDir, logPath } = writeFakeCurlThatFails(tree);

    let threw = false;
    let stdout = '';
    try {
      stdout = execFileSync('bash', [path.join(tree, VERIFY_SCRIPT)], {
        cwd: tree,
        stdio: 'pipe',
        env: {
          ...process.env,
          PATH: `${binDir}:${process.env.PATH}`,
          VENDOR_VERIFY_UPSTREAM: '1'
        }
      }).toString();
    } catch (err) {
      threw = true;
      stdout = String(err.stdout);
      assert.equal(err.status, 1, `unexpected exit status; stdout: ${stdout}`);
    }

    assert.ok(threw, `expected verify-vendor.sh to exit non-zero; stdout: ${stdout}`);
    assert.match(stdout, /not registry\.npmjs\.org/);
    assert.ok(
      !fs.existsSync(logPath),
      'expected zero curl invocations for a non-registry tarball host, but fake curl was called'
    );
  });
});

test('verify-vendor.sh (VENDOR_VERIFY_UPSTREAM=1) fails before any network call when registry_package is not the pinned package for that file', () => {
  withScratchTree((tree) => {
    // A real registry.npmjs.org tarball host so the ONLY thing wrong with
    // this entry is the pin mismatch; if the pin check did not run first,
    // this would sail through to a real curl call.
    writeFullFixtureTree(tree, {
      registry_package: 'not-dompurify',
      tarball: `https://registry.npmjs.org/not-dompurify/-/not-dompurify-1.0.0.tgz`
    });
    const { binDir, logPath } = writeFakeCurlThatFails(tree);

    let threw = false;
    let stdout = '';
    try {
      stdout = execFileSync('bash', [path.join(tree, VERIFY_SCRIPT)], {
        cwd: tree,
        stdio: 'pipe',
        env: {
          ...process.env,
          PATH: `${binDir}:${process.env.PATH}`,
          VENDOR_VERIFY_UPSTREAM: '1'
        }
      }).toString();
    } catch (err) {
      threw = true;
      stdout = String(err.stdout);
      assert.equal(err.status, 1, `unexpected exit status; stdout: ${stdout}`);
    }

    assert.ok(threw, `expected verify-vendor.sh to exit non-zero; stdout: ${stdout}`);
    assert.match(stdout, /does not match pinned package/);
    assert.ok(
      !fs.existsSync(logPath),
      'expected zero curl invocations for a pin mismatch, but fake curl was called'
    );
  });
});

// --- Attribute values containing '>' (grammar-correct tag parsing) ---

test("verify rejects a /js/ tag with no integrity when an earlier attribute value contains '>'", () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("gt");\n';
    writeFixture(tree, '<script data-note="a>b" src="/js/x.js"></script>\n', jsContent);
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /missing integrity attribute/);
    assert.match(stdout, /\/js\/x\.js/);
  });
});

test('update-sri rewrites a tag whose earlier attribute value contains \'>\' and leaves a commented-out tag untouched', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("gt");\n';
    const hash = sriHash(jsContent);
    const html =
      '<!-- <script data-note="a>b" src="/js/x.js"></script> -->\n' +
      '<script data-note="a>b" src="/js/x.js"></script>\n';
    const staticDir = writeFixture(tree, html, jsContent);
    runUpdateSri(tree);
    const rewritten = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
    assert.ok(
      rewritten.includes(`<!-- <script data-note="a>b" src="/js/x.js"></script> -->`),
      `expected commented-out tag left untouched: ${rewritten}`
    );
    assert.ok(
      rewritten.includes(`data-note="a>b" src="/js/x.js" integrity="${hash}" crossorigin="anonymous">`),
      `expected the real tag rewritten with its other attribute preserved: ${rewritten}`
    );
    const integrityCount = (rewritten.match(/integrity=/g) || []).length;
    assert.equal(integrityCount, 1, `expected only the non-commented tag to gain integrity: ${rewritten}`);
  });
});

// --- Commented-out tags must never be seen ---

test('verify ignores a commented-out script tag', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("commented");\n';
    const hash = sriHash(jsContent);
    const html =
      '<!-- <script src="/js/x.js"></script> -->\n' +
      `<script src="/js/x.js" integrity="${hash}" crossorigin="anonymous"></script>\n`;
    writeFixture(tree, html, jsContent);
    const stdout = runVerify(tree).toString();
    assert.match(stdout, /All checks passed/);
  });
});

// --- Whitespace inside quoted src (browsers trim it; the check must too) ---

test('verify rejects src with leading whitespace inside quotes', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("ws");\n';
    writeFixture(tree, '<script src=" /js/x.js"></script>\n', jsContent);
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /missing integrity attribute/);
    assert.match(stdout, /\/js\/x\.js/);
  });
});

// --- Multi-line attribute lists must preserve every other attribute ---

test('update-sri rewrites a tag with a multi-line attribute list and preserves the other attributes', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("multiline");\n';
    const hash = sriHash(jsContent);
    const html = '<script\n  defer\n  data-x="1"\n  src="/js/x.js"\n  async\n></script>\n';
    const staticDir = writeFixture(tree, html, jsContent);
    runUpdateSri(tree);
    const rewritten = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
    assert.ok(rewritten.includes(`integrity="${hash}"`), `expected updated integrity hash in: ${rewritten}`);
    assert.ok(rewritten.includes('crossorigin="anonymous"'), `expected crossorigin attribute in: ${rewritten}`);
    assert.ok(rewritten.includes('defer'), `expected defer preserved: ${rewritten}`);
    assert.ok(rewritten.includes('data-x="1"'), `expected data-x preserved: ${rewritten}`);
    assert.ok(rewritten.includes('async'), `expected async preserved: ${rewritten}`);
  });
});

// --- Structural failures: no HTML, unreadable HTML, zero /js/ tags ---

test('verify fails when STATIC_DIR has no html files', () => {
  withScratchTree((tree) => {
    const staticDir = path.join(tree, 'webroot');
    fs.mkdirSync(path.join(staticDir, 'js'), { recursive: true });
    let threw = false;
    let stdout = '';
    try {
      runVerify(tree);
    } catch (err) {
      threw = true;
      stdout = String(err.stdout);
      assert.equal(err.status, 1, `unexpected exit status; stdout: ${stdout}`);
    }
    assert.ok(threw, `expected verify-vendor.sh to exit non-zero; stdout: ${stdout}`);
    assert.match(stdout, /no html files/i);
  });
});

test('verify fails when an html file is unreadable', (t) => {
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    t.skip('running as root: chmod 000 does not block reads, skipping');
    return;
  }
  withScratchTree((tree) => {
    const jsContent = 'console.log("unreadable");\n';
    const staticDir = writeFixture(tree, '<script src="/js/x.js"></script>\n', jsContent);
    const htmlPath = path.join(staticDir, 'index.html');
    fs.chmodSync(htmlPath, 0o000);
    try {
      let threw = false;
      let stdout = '';
      try {
        runVerify(tree);
      } catch (err) {
        threw = true;
        stdout = String(err.stdout) + String(err.stderr);
        assert.equal(err.status, 1, `unexpected exit status; stdout: ${stdout}`);
      }
      assert.ok(threw, `expected verify-vendor.sh to exit non-zero; stdout: ${stdout}`);
      assert.match(stdout, /cannot read/i);
    } finally {
      fs.chmodSync(htmlPath, 0o644);
    }
  });
});

test('verify fails when zero site-relative script tags are found across all html', () => {
  withScratchTree((tree) => {
    const staticDir = path.join(tree, 'webroot');
    fs.mkdirSync(path.join(staticDir, 'js'), { recursive: true });
    fs.writeFileSync(path.join(staticDir, 'index.html'), '<html><body>no scripts here</body></html>\n');
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /zero site-relative script tags found/i);
  });
});

// --- Path confinement: a site-relative src must not escape the static dir ---
//
// Confinement is checked against STATIC_DIR itself, not specifically
// STATIC_DIR/js: a src like "/js/../secret.js" resolves to
// "<STATIC_DIR>/secret.js", which is still inside the static tree, so it is
// no longer treated as an escape. Only a src that resolves OUTSIDE
// STATIC_DIR (e.g. "/../secret.js") is an escape.

test('verify rejects a src that escapes the static dir via ..', () => {
  withScratchTree((tree) => {
    const staticDir = path.join(tree, 'webroot');
    fs.mkdirSync(path.join(staticDir, 'js'), { recursive: true });
    const secretContent = 'secret-off-tree-content\n';
    // Lives outside webroot/ entirely (a sibling of the static dir).
    fs.writeFileSync(path.join(tree, 'secret.js'), secretContent);
    const hash = sriHash(secretContent);
    fs.writeFileSync(
      path.join(staticDir, 'index.html'),
      `<script src="/../secret.js" integrity="${hash}"></script>\n`
    );
    const stdout = runVerifyExpectFailure(tree);
    assert.doesNotMatch(stdout, /\bOK\b.*secret\.js/);
    assert.match(stdout, /secret\.js/);
  });
});

test('update-sri refuses a src that escapes the static dir via ..', () => {
  withScratchTree((tree) => {
    const staticDir = path.join(tree, 'webroot');
    fs.mkdirSync(path.join(staticDir, 'js'), { recursive: true });
    const secretContent = 'secret-off-tree-content\n';
    fs.writeFileSync(path.join(tree, 'secret.js'), secretContent);
    const originalHtml = '<script src="/../secret.js"></script>\n';
    fs.writeFileSync(path.join(staticDir, 'index.html'), originalHtml);

    let threw = false;
    try {
      runUpdateSri(tree);
    } catch (err) {
      threw = true;
      assert.notEqual(err.status, 0, `expected update-sri.sh to exit non-zero; stderr: ${err.stderr}`);
    }
    assert.ok(threw, 'expected update-sri.sh to exit non-zero for a path-escaping src');

    const htmlAfter = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
    assert.equal(htmlAfter, originalHtml, 'expected the HTML file to be left unchanged');
  });
});

// --- Site-relative rule now applies to every leading-slash src, not just /js/ ---

test('verify rejects /jsx/../js/x.js with no integrity', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("traversal");\n';
    writeFixture(tree, '<script src="/jsx/../js/x.js"></script>\n', jsContent);
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /missing integrity attribute/);
    assert.match(stdout, /\/jsx\/\.\.\/js\/x\.js/);
  });
});

test('verify accepts /jsx/../js/x.js with correct integrity', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("traversal-ok");\n';
    const hash = sriHash(jsContent);
    writeFixture(
      tree,
      `<script src="/jsx/../js/x.js" integrity="${hash}" crossorigin="anonymous"></script>\n`,
      jsContent
    );
    const stdout = runVerify(tree).toString();
    assert.match(stdout, /All checks passed/);
  });
});

test('verify rejects a site-relative script outside /js/ with no integrity', () => {
  withScratchTree((tree) => {
    const staticDir = path.join(tree, 'webroot');
    fs.mkdirSync(path.join(staticDir, 'other'), { recursive: true });
    const jsContent = 'console.log("other");\n';
    fs.writeFileSync(path.join(staticDir, 'other', 'x.js'), jsContent);
    fs.writeFileSync(path.join(staticDir, 'index.html'), '<script src="/other/x.js"></script>\n');
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /missing integrity attribute/);
    assert.match(stdout, /\/other\/x\.js/);
  });
});

test('verify rejects a protocol-relative or absolute-URL script src', () => {
  withScratchTree((tree) => {
    const staticDir = path.join(tree, 'webroot');
    fs.mkdirSync(path.join(staticDir, 'js'), { recursive: true });
    fs.writeFileSync(path.join(staticDir, 'index.html'), '<script src="//cdn.example/x.js"></script>\n');
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /cdn\.example/);
    assert.match(stdout, /not allowed under script-src 'self'|protocol-relative/i);
  });
});

test('update-sri rewrites /jsx/../js/x.js and a site-relative non-/js/ tag', () => {
  withScratchTree((tree) => {
    const staticDir = path.join(tree, 'webroot');
    fs.mkdirSync(path.join(staticDir, 'js'), { recursive: true });
    fs.mkdirSync(path.join(staticDir, 'other'), { recursive: true });
    const jsContentA = 'console.log("a");\n';
    const jsContentB = 'console.log("b");\n';
    fs.writeFileSync(path.join(staticDir, 'js', 'x.js'), jsContentA);
    fs.writeFileSync(path.join(staticDir, 'other', 'y.js'), jsContentB);
    const html = '<script src="/jsx/../js/x.js"></script>\n' + '<script src="/other/y.js"></script>\n';
    fs.writeFileSync(path.join(staticDir, 'index.html'), html);

    runUpdateSri(tree);

    const rewritten = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
    assert.ok(
      rewritten.includes(`integrity="${sriHash(jsContentA)}"`),
      `expected /jsx/../js/x.js rewritten with correct hash: ${rewritten}`
    );
    assert.ok(
      rewritten.includes(`integrity="${sriHash(jsContentB)}"`),
      `expected /other/y.js rewritten with correct hash: ${rewritten}`
    );
  });
});

// --- Upstream check: a non-JSON registry response must go through fail(), not abort the script ---

function writeFakeCurlThatReturnsNonJson(tree) {
  const binDir = path.join(tree, 'fakebin');
  fs.mkdirSync(binDir, { recursive: true });
  const curlPath = path.join(binDir, 'curl');
  // Mimics `curl -fsSL -o <file> <url>`: writes "not json" to the -o target
  // and exits 0, simulating a 200 response with a non-JSON body (e.g. an
  // HTML error page from a proxy/CDN in front of the registry).
  fs.writeFileSync(
    curlPath,
    [
      '#!/bin/bash',
      'out=""',
      'args=("$@")',
      'for ((i=0; i<${#args[@]}; i++)); do',
      '  if [ "${args[$i]}" = "-o" ]; then',
      '    out="${args[$((i+1))]}"',
      '  fi',
      'done',
      'if [ -n "$out" ]; then',
      '  echo "not json" > "$out"',
      'else',
      '  echo "not json"',
      'fi',
      'exit 0'
    ].join('\n') + '\n'
  );
  fs.chmodSync(curlPath, 0o755);
  return { binDir };
}

test('upstream check reports non-JSON registry body via fail() and continues', () => {
  withScratchTree((tree) => {
    writeFullFixtureTree(tree, {
      tarball: `https://registry.npmjs.org/${PINNED_PACKAGE}/-/${PINNED_PACKAGE}-1.0.0.tgz`
    });
    const { binDir } = writeFakeCurlThatReturnsNonJson(tree);

    let threw = false;
    let stdout = '';
    try {
      stdout = execFileSync('bash', [path.join(tree, VERIFY_SCRIPT)], {
        cwd: tree,
        stdio: 'pipe',
        env: {
          ...process.env,
          PATH: `${binDir}:${process.env.PATH}`,
          VENDOR_VERIFY_UPSTREAM: '1'
        }
      }).toString();
    } catch (err) {
      threw = true;
      stdout = String(err.stdout);
      assert.equal(err.status, 1, `unexpected exit status; stdout: ${stdout}`);
    }

    assert.ok(threw, `expected verify-vendor.sh to exit non-zero; stdout: ${stdout}`);
    assert.match(stdout, new RegExp(PINNED_FILE.replace('.', '\\.')));
    assert.match(stdout, /non-JSON/);
    assert.match(stdout, /FAILED: \d+ error/);
  });
});

// --- Upstream check: an unsupported dist.integrity algorithm must go
// through fail(), not abort the script under set -e ---

function writeFakeCurlWithUnsupportedAlgo(tree, tarball) {
  const binDir = path.join(tree, 'fakebin');
  fs.mkdirSync(binDir, { recursive: true });
  const curlPath = path.join(binDir, 'curl');
  // Mimics both curl invocations: the metadata GET (no -o) returns JSON
  // whose dist.integrity uses an algorithm openssl dgst does not support
  // in this form ("md5-..."), and the tarball download (-o) just needs to
  // succeed so execution reaches the algorithm check.
  fs.writeFileSync(
    curlPath,
    [
      '#!/bin/bash',
      'out=""',
      'args=("$@")',
      'for ((i=0; i<${#args[@]}; i++)); do',
      '  if [ "${args[$i]}" = "-o" ]; then',
      '    out="${args[$((i+1))]}"',
      '  fi',
      'done',
      'if [ -n "$out" ]; then',
      '  echo "dummy-tarball-bytes" > "$out"',
      'else',
      `  echo '{"dist":{"tarball":"${tarball}","integrity":"md5-deadbeef"}}'`,
      'fi',
      'exit 0'
    ].join('\n') + '\n'
  );
  fs.chmodSync(curlPath, 0o755);
  return { binDir };
}

// --- Duplicate attributes: browsers are first-wins, the parser must match ---

test('verify rejects a duplicate src where only the second src matches the integrity', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("legit");\n';
    const hash = sriHash(jsContent);
    // A browser loads the FIRST src ("/js/evil.js"). The integrity here only
    // matches the second, decoy src ("/js/x.js"), so this must FAIL rather
    // than validate against the wrong (second) src.
    const staticDir = writeFixture(
      tree,
      `<script src="/js/evil.js" src="/js/x.js" integrity="${hash}"></script>\n`,
      jsContent
    );
    fs.writeFileSync(path.join(staticDir, 'js', 'evil.js'), 'console.log("evil");\n');
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /evil\.js/);
  });
});

test('verify rejects duplicate integrity attributes where only the second is correct', () => {
  withScratchTree((tree) => {
    const jsContent = 'console.log("x");\n';
    const hash = sriHash(jsContent);
    // First-wins: the browser uses the first integrity attribute, which is
    // wrong here. A second, correct integrity attribute must not save it.
    writeFixture(
      tree,
      `<script src="/js/x.js" integrity="sha384-wrong" integrity="${hash}"></script>\n`,
      jsContent
    );
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /SRI mismatch/);
  });
});

test('update-sri.sh hashes the first src when a tag has a duplicate src attribute', () => {
  withScratchTree((tree) => {
    const jsContentA = 'console.log("first");\n';
    const jsContentB = 'console.log("second");\n';
    const hashA = sriHash(jsContentA);
    const staticDir = path.join(tree, 'webroot');
    fs.mkdirSync(path.join(staticDir, 'js'), { recursive: true });
    fs.writeFileSync(path.join(staticDir, 'js', 'a.js'), jsContentA);
    fs.writeFileSync(path.join(staticDir, 'js', 'b.js'), jsContentB);
    fs.writeFileSync(
      path.join(staticDir, 'index.html'),
      '<script src="/js/a.js" src="/js/b.js"></script>\n'
    );
    runUpdateSri(tree);
    const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
    assert.ok(
      html.includes(`integrity="${hashA}"`),
      `expected update-sri.sh to hash the FIRST src (a.js), not b.js: ${html}`
    );
  });
});

// --- update-sri.sh must not accept a symlink that escapes the static dir,
// even though its lexical check alone cannot see the escape ---

test('update-sri.sh refuses a src that resolves through a symlink escaping the static dir', () => {
  withScratchTree((tree) => {
    const staticDir = path.join(tree, 'webroot');
    fs.mkdirSync(path.join(staticDir, 'js'), { recursive: true });
    const outsideDir = path.join(tree, 'outside');
    fs.mkdirSync(outsideDir, { recursive: true });
    const secretContent = 'secret-outside-content\n';
    fs.writeFileSync(path.join(outsideDir, 'evil.js'), secretContent);
    // static/js/linked -> <dir outside static>
    fs.symlinkSync(outsideDir, path.join(staticDir, 'js', 'linked'));
    const originalHtml = '<script src="/js/linked/evil.js"></script>\n';
    fs.writeFileSync(path.join(staticDir, 'index.html'), originalHtml);

    let threw = false;
    try {
      runUpdateSri(tree);
    } catch (err) {
      threw = true;
      assert.notEqual(err.status, 0, `expected update-sri.sh to exit non-zero; stderr: ${err.stderr}`);
    }
    assert.ok(threw, 'expected update-sri.sh to exit non-zero for a symlink-escaping src');

    const htmlAfter = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
    assert.equal(htmlAfter, originalHtml, 'expected the HTML file to be left unchanged');
  });
});

test('verify-vendor.sh rejects the same symlink-escape fixture', () => {
  withScratchTree((tree) => {
    const staticDir = path.join(tree, 'webroot');
    fs.mkdirSync(path.join(staticDir, 'js'), { recursive: true });
    const outsideDir = path.join(tree, 'outside');
    fs.mkdirSync(outsideDir, { recursive: true });
    const secretContent = 'secret-outside-content\n';
    fs.writeFileSync(path.join(outsideDir, 'evil.js'), secretContent);
    fs.symlinkSync(outsideDir, path.join(staticDir, 'js', 'linked'));
    const hash = sriHash(secretContent);
    fs.writeFileSync(
      path.join(staticDir, 'index.html'),
      `<script src="/js/linked/evil.js" integrity="${hash}"></script>\n`
    );
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /evil\.js/);
  });
});

test('verify rejects an unsupported integrity algorithm from the registry via fail() and continues', () => {
  withScratchTree((tree) => {
    const tarball = `https://registry.npmjs.org/${PINNED_PACKAGE}/-/${PINNED_PACKAGE}-1.0.0.tgz`;
    writeFullFixtureTree(tree, { tarball, dist_integrity: 'md5-deadbeef' });
    const { binDir } = writeFakeCurlWithUnsupportedAlgo(tree, tarball);

    let threw = false;
    let stdout = '';
    try {
      stdout = execFileSync('bash', [path.join(tree, VERIFY_SCRIPT)], {
        cwd: tree,
        stdio: 'pipe',
        env: {
          ...process.env,
          PATH: `${binDir}:${process.env.PATH}`,
          VENDOR_VERIFY_UPSTREAM: '1'
        }
      }).toString();
    } catch (err) {
      threw = true;
      stdout = String(err.stdout);
      assert.equal(err.status, 1, `unexpected exit status; stdout: ${stdout}`);
    }

    assert.ok(threw, `expected verify-vendor.sh to exit non-zero; stdout: ${stdout}`);
    assert.match(stdout, new RegExp(PINNED_FILE.replace('.', '\\.')));
    assert.match(stdout, /unsupported/);
    assert.match(stdout, /FAILED: \d+ error/);
  });
});

// --- update-sri.sh must hash the tag's real src, not whatever a naive
// \bsrc=... regex finds first in the raw tag text. "data-src" contains
// "-src", and a word-boundary regex matches "src" right there (the '-' is
// a non-word char, so \b fires between '-' and 's'), so a tag with both
// data-src and src attributes previously got the DATA-SRC value hashed
// when the decoy src alphabetically or positionally preceded the real one
// in the naive regex scan. script-tags.pl already parses attributes
// correctly and reports the real src; the rewriter must use that value
// instead of re-deriving it from the raw tag text. ---

test('update-sri.sh hashes the real src, not a decoy data-src, and leaves data-src untouched', () => {
  withScratchTree((tree) => {
    const legitContent = 'console.log("legit");\n';
    const evilContent = 'console.log("evil");\n';
    const legitHash = sriHash(legitContent);
    const evilHash = sriHash(evilContent);
    const staticDir = path.join(tree, 'webroot');
    fs.mkdirSync(path.join(staticDir, 'js'), { recursive: true });
    fs.writeFileSync(path.join(staticDir, 'js', 'legit.js'), legitContent);
    fs.writeFileSync(path.join(staticDir, 'js', 'evil.js'), evilContent);
    const originalHtml = '<script data-src="/js/evil.js" src="/js/legit.js"></script>\n';
    fs.writeFileSync(path.join(staticDir, 'index.html'), originalHtml);

    runUpdateSri(tree);

    const rewritten = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
    assert.ok(
      rewritten.includes(`integrity="${legitHash}"`),
      `expected the real src (legit.js) to be hashed: ${rewritten}`
    );
    assert.ok(
      !rewritten.includes(evilHash),
      `expected the decoy data-src (evil.js) to NOT be hashed: ${rewritten}`
    );
    assert.ok(
      rewritten.includes('data-src="/js/evil.js"'),
      `expected data-src to be preserved untouched: ${rewritten}`
    );
    assert.ok(
      rewritten.includes('src="/js/legit.js"'),
      `expected src to be preserved untouched: ${rewritten}`
    );
  });
});

test('verify-vendor.sh FAILs a data-src/src tag whose integrity matches the decoy data-src value', () => {
  withScratchTree((tree) => {
    const legitContent = 'console.log("legit");\n';
    const evilContent = 'console.log("evil");\n';
    const evilHash = sriHash(evilContent);
    const staticDir = writeFixture(
      tree,
      `<script data-src="/js/evil.js" src="/js/x.js" integrity="${evilHash}"></script>\n`,
      legitContent
    );
    fs.writeFileSync(path.join(staticDir, 'js', 'evil.js'), evilContent);
    const stdout = runVerifyExpectFailure(tree);
    assert.match(stdout, /SRI mismatch/);
  });
});
