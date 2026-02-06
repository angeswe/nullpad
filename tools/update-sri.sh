#!/bin/bash
# Update SRI (Subresource Integrity) hashes in all HTML files.
# Run after modifying any JS file in static/js/.

set -euo pipefail
cd "$(dirname "$0")/.."

STATIC_DIR="static"
HTML_FILES=$(find "$STATIC_DIR" -name "*.html" -maxdepth 1)

# Generate SRI hash for a file
sri_hash() {
  echo "sha384-$(openssl dgst -sha384 -binary "$1" | openssl base64 -A)"
}

# For each JS file referenced in HTML, update its integrity attribute
for html in $HTML_FILES; do
  # Find all script src paths in this file
  grep -oP 'src="/js/[^"]+' "$html" | sed 's/^src="//' | while read -r src_path; do
    file_path="${STATIC_DIR}${src_path}"
    if [ ! -f "$file_path" ]; then
      echo "WARNING: $file_path not found (referenced in $html)"
      continue
    fi

    hash=$(sri_hash "$file_path")

    # Replace: src="/js/..." with or without existing integrity
    # Match: <script src="/js/path"[optional integrity]></script>
    sed -i "s|<script src=\"${src_path}\"[^>]*>|<script src=\"${src_path}\" integrity=\"${hash}\">|g" "$html"
  done || true
  echo "Updated: $html"
done

echo "SRI hashes updated."
