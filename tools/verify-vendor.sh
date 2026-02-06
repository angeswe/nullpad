#!/bin/bash
# Verify vendored JavaScript libraries against their manifested hashes,
# and verify SRI attributes in HTML match actual file hashes.
# Exits non-zero if any check fails.

set -euo pipefail
cd "$(dirname "$0")/.."

VENDOR_DIR="static/js/vendor"
MANIFEST="$VENDOR_DIR/versions.json"
STATIC_DIR="static"
errfile=$(mktemp)
echo 0 > "$errfile"

fail() {
  echo "FAIL: $1"
  echo $(( $(cat "$errfile") + 1 )) > "$errfile"
}

sri_hash() {
  echo "sha384-$(openssl dgst -sha384 -binary "$1" | openssl base64 -A)"
}

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

# --- 3. SRI attribute verification ---
echo ""
echo "=== SRI integrity attributes ==="

for html in "$STATIC_DIR"/*.html; do
  html_name=$(basename "$html")

  # Extract script tags with src="/js/..."
  { grep -oP '<script src="/js/[^"]+?"[^>]*>' "$html" 2>/dev/null || true; } | while IFS= read -r tag; do
    src=$(echo "$tag" | grep -oP 'src="/js/[^"]+' | sed 's/^src="//')
    file_path="${STATIC_DIR}${src}"

    if ! echo "$tag" | grep -q 'integrity='; then
      fail "$html_name -> $src missing integrity attribute"
      continue
    fi

    integrity=$(echo "$tag" | grep -oP 'integrity="[^"]+' | sed 's/^integrity="//')

    if [ ! -f "$file_path" ]; then
      fail "$html_name references $src but file not found"
      continue
    fi

    actual=$(sri_hash "$file_path")

    if [ "$actual" = "$integrity" ]; then
      echo "  OK: $html_name -> $src"
    else
      fail "$html_name -> $src SRI mismatch"
      echo "  in HTML:  $integrity"
      echo "  actual:   $actual"
    fi
  done
done

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
