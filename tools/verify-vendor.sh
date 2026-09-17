#!/bin/bash
# Verify vendored JavaScript libraries against their manifested hashes,
# and verify SRI attributes in HTML match actual file hashes.
# Exits non-zero if any check fails.

set -euo pipefail
cd "$(dirname "$0")/.."

VENDOR_DIR="static/js/vendor"
MANIFEST="$VENDOR_DIR/versions.json"

# Pinned registry package per vendor filename. versions.json's
# registry_package is attacker-editable in a PR (e.g. swapped to a
# typosquat package that publishes an identical file under a different
# name), so it is checked against this hard-coded pin before any network
# call is made. Adding or renaming a vendored library requires editing
# this map — see the README bump procedure.
declare -A PINNED_REGISTRY_PACKAGE=(
  [marked.min.js]="marked"
  [highlight.min.js]="@highlightjs/cdn-assets"
  [purify.min.js]="dompurify"
  [argon2.umd.min.js]="hash-wasm"
)
STATIC_DIR="${STATIC_DIR:-static}"
# SRI_ONLY=1 skips vendor-hash/license/upstream checks and runs only the SRI
# attribute check below, so tests can point STATIC_DIR at a throwaway
# fixture without needing a full vendor/ + info.html tree alongside it.
SRI_ONLY="${SRI_ONLY:-0}"
errfile=$(mktemp)
echo 0 > "$errfile"

fail() {
  echo "FAIL: $1"
  echo $(( $(cat "$errfile") + 1 )) > "$errfile"
}

sri_hash() {
  echo "sha384-$(openssl dgst -sha384 -binary "$1" | openssl base64 -A)"
}

SCRIPT_TAGS_PL="tools/lib/script-tags.pl"

if [ "$SRI_ONLY" != "1" ]; then

# --- 1. Vendor file hash verification ---
echo "=== Vendor file integrity ==="

# Check every JS file in vendor/ has a manifest entry
for file in "$VENDOR_DIR"/*.js; do
  name=$(basename "$file")
  if ! jq -e ".\"$name\"" "$MANIFEST" >/dev/null 2>&1; then
    fail "$name exists in vendor/ but is not in versions.json"
  fi
done

# Check every manifest entry has a matching file with correct hash
for key in $(jq -r 'keys[]' "$MANIFEST"); do
  expected=$(jq -r ".\"$key\".sha384" "$MANIFEST")
  file="$VENDOR_DIR/$key"

  if [ ! -f "$file" ]; then
    fail "$key listed in versions.json but file not found"
    continue
  fi

  if [ -z "$expected" ] || [ "$expected" = "null" ]; then
    fail "$key has no sha384 hash in versions.json"
    continue
  fi

  actual=$(sri_hash "$file")

  if [ "$actual" = "$expected" ]; then
    echo "  OK: $key"
  else
    fail "$key hash mismatch"
    echo "  expected: $expected"
    echo "  actual:   $actual"
  fi
done

# --- 2. License verification ---
echo ""
echo "=== License compliance ==="

# Licenses compatible with AGPL-3.0
ALLOWED="MIT ISC BSD-2-Clause BSD-3-Clause Apache-2.0 MPL-2.0 Unlicense 0BSD CC0-1.0"

for key in $(jq -r 'keys[]' "$MANIFEST"); do
  license=$(jq -r ".\"$key\".license" "$MANIFEST")

  if [ -z "$license" ] || [ "$license" = "null" ]; then
    fail "$key has no license in versions.json"
    continue
  fi

  # Handle SPDX OR expressions: (MPL-2.0 OR Apache-2.0)
  # Strip parens, split on OR, check each alternative
  clean=$(echo "$license" | tr -d '()')
  ok=false
  for alt in $(echo "$clean" | tr ' ' '\n' | grep -v '^OR$'); do
    for allowed in $ALLOWED; do
      if [ "$alt" = "$allowed" ]; then
        ok=true
        break 2
      fi
    done
  done

  if [ "$ok" = true ]; then
    echo "  OK: $key ($license)"
  else
    fail "$key has disallowed license: $license"
  fi
done

fi # SRI_ONLY

# --- 3. SRI attribute verification ---
echo ""
echo "=== SRI integrity attributes ==="

shopt -s nullglob
HTML_CHECK_FILES=("$STATIC_DIR"/*.html)
if [ -d "protected" ]; then
  HTML_CHECK_FILES+=(protected/*.html)
fi
shopt -u nullglob

if [ "${#HTML_CHECK_FILES[@]}" -eq 0 ]; then
  fail "no html files found under $STATIC_DIR or protected/ to check for SRI attributes"
else
  # script-tags.pl's stderr is left to flow straight to this script's
  # stderr (not redirected or discarded), so a parse error is always
  # visible even though we capture its stdout below.
  if ! tag_output=$(perl "$SCRIPT_TAGS_PL" "${HTML_CHECK_FILES[@]}"); then
    fail "script-tags.pl failed while parsing HTML files (see stderr above)"
    tag_output=""
  fi

  checked=0
  # Confinement roots, computed once (not per tag/iteration): every
  # site-relative src must resolve to a path under STATIC_DIR/. Using
  # realpath -m so this works even before the target file is known to
  # exist.
  static_root_real=$(realpath -m "$STATIC_DIR")
  # Tab is one of bash's "IFS whitespace" characters, so `read` with
  # IFS=$'\t' would silently collapse a run of tabs (e.g. an empty
  # integrity field between two tabs) instead of preserving the empty
  # field. Translate tabs to a non-whitespace separator first so `read`
  # splits on it literally.
  while IFS=$'\x1f' read -r file src integrity offset raw; do
    [ -z "$file" ] && continue
    html_name=$(basename "$file")

    # The literal "/js/*" prefix filter used to be the whole rule here,
    # which meant a src like "/jsx/../js/x.js" (resolves in the browser to
    # /js/x.js) was skipped with no output at all. Every tag whose trimmed
    # src is site-relative (a single leading '/': not "//host" and not
    # "http(s)://...") is now checked, wherever under STATIC_DIR it points.
    # A tag with no src (inline) is ignored. A non-site-relative src is a
    # FAIL: the CSP is script-src 'self', so such a tag is either a bug or
    # an attack.
    case "$src" in
      "")
        continue
        ;;
      //*)
        fail "$html_name -> $src is a protocol-relative script src, not allowed under script-src 'self': $raw"
        continue
        ;;
      /*)
        ;;
      *)
        fail "$html_name -> $src is not a site-relative script src, not allowed under script-src 'self': $raw"
        continue
        ;;
    esac

    checked=$((checked + 1))
    file_path="${STATIC_DIR}${src}"

    # Canonicalize and confine: a site-relative src must resolve to a real
    # file inside STATIC_DIR/. Without this, a src like "/jsx/../js/x.js"
    # or "/../secret.js" could resolve to a file outside the static tree
    # (or in a different vendored subdirectory) while looking harmless in
    # the HTML.
    file_path_real=$(realpath -m "$file_path")

    case "$file_path_real" in
      "$static_root_real"/*) ;;
      *)
        fail "$html_name -> $src escapes $STATIC_DIR (resolves to $file_path_real): $raw"
        continue
        ;;
    esac

    if [ ! -f "$file_path_real" ]; then
      fail "$html_name -> $src references a file that does not exist: $file_path ($raw)"
      continue
    fi

    if [ -z "$integrity" ]; then
      fail "$html_name -> $src missing integrity attribute ($raw)"
      continue
    fi

    if ! [[ "$integrity" =~ ^sha384-[A-Za-z0-9+/]+=*$ ]]; then
      fail "$html_name -> $src integrity attribute is not a valid sha384 hash: $integrity ($raw)"
      continue
    fi

    actual=$(sri_hash "$file_path_real")

    if [ "$actual" = "$integrity" ]; then
      echo "  OK: $html_name -> $src"
    else
      fail "$html_name -> $src SRI mismatch"
      echo "  in HTML:  $integrity"
      echo "  actual:   $actual"
    fi
  done <<< "${tag_output//$'\t'/$'\x1f'}"

  if [ "$checked" -eq 0 ]; then
    fail "zero site-relative script tags found across all html files (parser or path is likely wrong)"
  fi
fi

if [ "$SRI_ONLY" != "1" ]; then

# --- 4. License table sync verification ---
echo ""
echo "=== License table in info.html ==="

expected_html=$(mktemp)
cp "$STATIC_DIR/info.html" "$expected_html"
bash tools/sync-licenses.sh >/dev/null 2>&1

if diff -q "$expected_html" "$STATIC_DIR/info.html" >/dev/null 2>&1; then
  echo "  OK: license table matches versions.json"
else
  # Restore original and report failure
  cp "$expected_html" "$STATIC_DIR/info.html"
  fail "info.html license table is out of sync with versions.json (run tools/sync-licenses.sh)"
fi
rm -f "$expected_html"

# --- 5. Upstream tarball verification (network, opt-in) ---
# Proves the in-tree file matches what the npm registry actually publishes,
# not just that it is self-consistent with versions.json. versions.json is
# attacker-editable in a PR, so it is NOT the trust anchor: the registry is.
# For each package this fetches the registry's own metadata and checks that
# versions.json's tarball/dist_integrity match what the registry says before
# ever downloading anything, and refuses any tarball not hosted on
# registry.npmjs.org. Off by default so offline/local runs keep working;
# opt in explicitly with VENDOR_VERIFY_UPSTREAM=1 (CI has its own step for
# this — see ci.yml).
if [ "${VENDOR_VERIFY_UPSTREAM:-0}" = "1" ]; then
  echo ""
  echo "=== Upstream tarball verification (network) ==="

  NPM_REGISTRY_URL="${NPM_REGISTRY_URL:-https://registry.npmjs.org}"

  # Pin validation happens first and touches no network: every pinned
  # filename must have a versions.json entry, and every vendor file must
  # have a pin, before any registry_package is trusted for a curl call.
  for pinned_key in "${!PINNED_REGISTRY_PACKAGE[@]}"; do
    if ! jq -e ".\"$pinned_key\"" "$MANIFEST" >/dev/null 2>&1; then
      fail "$pinned_key is pinned in verify-vendor.sh but has no versions.json entry"
    fi
  done
  for file in "$VENDOR_DIR"/*.js; do
    vendor_key=$(basename "$file")
    if [ -z "${PINNED_REGISTRY_PACKAGE[$vendor_key]+set}" ]; then
      fail "$vendor_key has no pinned registry_package in verify-vendor.sh"
    fi
  done

  for key in $(jq -r 'keys[]' "$MANIFEST"); do
    file="$VENDOR_DIR/$key"

    # Each of these is a var=$(jq ...) assignment: under `set -e`, if jq
    # ever failed here (malformed manifest entry, etc.) that failure would
    # propagate as the assignment's own exit status and abort the whole
    # script instead of just this package. Guard the whole batch so a
    # failure goes through fail()+continue like everything else in this
    # loop.
    if ! registry_package=$(jq -r ".\"$key\".registry_package // .\"$key\".package // empty" "$MANIFEST") ||
      ! version=$(jq -r ".\"$key\".version // empty" "$MANIFEST") ||
      ! tarball=$(jq -r ".\"$key\".tarball // empty" "$MANIFEST") ||
      ! dist_integrity=$(jq -r ".\"$key\".dist_integrity // empty" "$MANIFEST") ||
      ! tarball_path=$(jq -r ".\"$key\".tarball_path // empty" "$MANIFEST"); then
      fail "$key: failed to read manifest fields from versions.json"
      continue
    fi

    if [ -z "$registry_package" ] || [ -z "$version" ] || [ -z "$tarball" ] || [ -z "$dist_integrity" ] || [ -z "$tarball_path" ]; then
      fail "$key has no upstream verification data in versions.json (registry_package/version/tarball/dist_integrity/tarball_path)"
      continue
    fi

    # Refuse an entry whose registry_package does not match the hard-coded
    # pin before ever contacting the network. This is the primary defense
    # against a PR that swaps registry_package to a typosquat/compromised
    # package while keeping tarball/dist_integrity self-consistent.
    pinned_package="${PINNED_REGISTRY_PACKAGE[$key]:-}"
    if [ -z "$pinned_package" ]; then
      fail "$key has no pinned registry_package in verify-vendor.sh"
      continue
    fi
    if [ "$registry_package" != "$pinned_package" ]; then
      fail "$key: versions.json registry_package '$registry_package' does not match pinned package '$pinned_package' in verify-vendor.sh"
      continue
    fi

    # Refuse a self-hosted tarball before ever contacting the network: the
    # attacker-editable versions.json is not the trust anchor, so a tarball
    # URL claiming anything other than the real registry is rejected here,
    # with zero curl calls made.
    tarball_host=$(echo "$tarball" | sed -E 's#^[a-zA-Z]+://([^/]+)/.*#\1#')
    if [ "$tarball_host" != "registry.npmjs.org" ]; then
      fail "$key: versions.json tarball host '$tarball_host' is not registry.npmjs.org ($tarball)"
      continue
    fi

    # URL-encode the package name (scoped packages need '/' as %2F).
    encoded_package=$(printf '%s' "$registry_package" | sed 's#/#%2F#g')
    registry_url="$NPM_REGISTRY_URL/$encoded_package/$version"

    if ! registry_json=$(curl -fsSL "$registry_url"); then
      fail "$key: FETCH_FAILED fetching registry metadata from $registry_url"
      continue
    fi

    if ! jq -e . >/dev/null 2>&1 <<<"$registry_json"; then
      fail "$key: registry returned non-JSON metadata from $registry_url"
      continue
    fi

    if ! registry_tarball=$(jq -r '.dist.tarball // empty' <<<"$registry_json") ||
      ! registry_integrity=$(jq -r '.dist.integrity // empty' <<<"$registry_json"); then
      fail "$key: failed to read dist.tarball/dist.integrity from registry metadata at $registry_url"
      continue
    fi

    if [ -z "$registry_tarball" ] || [ -z "$registry_integrity" ]; then
      fail "$key: registry metadata at $registry_url is missing dist.tarball/dist.integrity"
      continue
    fi

    if [ "$registry_tarball" != "$tarball" ]; then
      fail "$key: versions.json tarball ($tarball) does not match registry dist.tarball ($registry_tarball)"
      continue
    fi

    if [ "$registry_integrity" != "$dist_integrity" ]; then
      fail "$key: versions.json dist_integrity does not match registry dist.integrity"
      continue
    fi

    registry_tarball_host=$(echo "$registry_tarball" | sed -E 's#^[a-zA-Z]+://([^/]+)/.*#\1#')
    if [ "$registry_tarball_host" != "registry.npmjs.org" ]; then
      fail "$key: registry-provided tarball host '$registry_tarball_host' is not registry.npmjs.org"
      continue
    fi

    if ! tmpdir=$(mktemp -d); then
      fail "$key: failed to create a temp directory for upstream verification"
      continue
    fi
    tarfile="$tmpdir/pkg.tgz"

    if ! curl -fsSL -o "$tarfile" "$registry_tarball"; then
      fail "$key: FETCH_FAILED downloading $registry_tarball"
      rm -rf "$tmpdir"
      continue
    fi

    # dist.integrity looks like "sha512-<base64>". The algorithm comes from
    # the registry response, so it must be validated before being handed to
    # `openssl dgst -$algo`: an unsupported or malformed algorithm would
    # make openssl fail, and under `set -e` an unguarded
    # `actual_b64=$(openssl ... | openssl ...)` assignment would abort the
    # whole script instead of just failing this one package.
    algo="${registry_integrity%%-*}"
    expected_b64="${registry_integrity#*-}"

    case "$algo" in
      sha256 | sha384 | sha512) ;;
      *)
        fail "$key: unsupported integrity algorithm '$algo' in registry dist.integrity"
        rm -rf "$tmpdir"
        continue
        ;;
    esac

    if ! actual_b64=$(openssl dgst "-$algo" -binary "$tarfile" | openssl base64 -A); then
      fail "$key: failed computing $algo digest of downloaded tarball"
      rm -rf "$tmpdir"
      continue
    fi

    if [ "$actual_b64" != "$expected_b64" ]; then
      fail "$key: tarball at $registry_tarball does not match registry dist.integrity"
      rm -rf "$tmpdir"
      continue
    fi

    if ! tar_err=$(tar -xzf "$tarfile" -C "$tmpdir" "$tarball_path" 2>&1 >/dev/null); then
      fail "$key: tar failed extracting $tarball_path: $tar_err"
      rm -rf "$tmpdir"
      continue
    fi

    if cmp -s "$tmpdir/$tarball_path" "$file"; then
      echo "  OK: $key matches upstream $tarball_path (verified against $NPM_REGISTRY_URL)"
    else
      fail "$key: in-tree file does not byte-match upstream $tarball_path"
    fi

    rm -rf "$tmpdir"
  done
fi

fi # SRI_ONLY

# --- Result ---
errors=$(cat "$errfile")
rm -f "$errfile"

echo ""
if [ "$errors" -gt 0 ]; then
  echo "FAILED: $errors error(s) found"
  echo "Run tools/update-sri.sh to fix SRI hashes, or update versions.json for vendor changes."
  exit 1
else
  echo "All checks passed."
fi
