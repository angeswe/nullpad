#!/bin/bash
# Regenerate the license table in info.html from versions.json.
# Run after modifying static/js/vendor/versions.json.

set -euo pipefail
cd "$(dirname "$0")/.."

MANIFEST="static/js/vendor/versions.json"
HTML="static/info.html"

if [ ! -f "$MANIFEST" ]; then
  echo "ERROR: $MANIFEST not found"
  exit 1
fi

# Display names for packages (fallback to package name)
display_name() {
  case "$1" in
    dompurify)    echo "DOMPurify" ;;
    tweetnacl)    echo "TweetNaCl.js" ;;
    highlight.js) echo "highlight.js" ;;
    *)            echo "$1" ;;
  esac
}

# Format SPDX expression for display
format_license() {
  echo "$1" | tr -d '()' | sed 's/ OR / \/ /g'
}

# Build table rows
rows=""
for key in $(jq -r 'keys[]' "$MANIFEST"); do
  pkg=$(jq -r ".\"$key\".package" "$MANIFEST")
  version=$(jq -r ".\"$key\".version" "$MANIFEST")
  license=$(jq -r ".\"$key\".license" "$MANIFEST")
  url=$(jq -r ".\"$key\".url" "$MANIFEST")
  name=$(display_name "$pkg")
  license_display=$(format_license "$license")

  rows+="            <tr>
              <td><a href=\"${url}\" target=\"_blank\" rel=\"noopener\">${name}</a></td>
              <td>${version}</td>
              <td>${license_display}</td>
            </tr>
"
done

# Replace content between markers
tmpfile=$(mktemp)
awk -v rows="$rows" '
  /<!-- BEGIN LICENSES -->/ {
    print
    print "          <tbody>"
    printf "%s", rows
    print "          </tbody>"
    skip = 1
    next
  }
  /<!-- END LICENSES -->/ {
    print
    skip = 0
    next
  }
  !skip { print }
' "$HTML" > "$tmpfile"

mv "$tmpfile" "$HTML"
echo "Updated license table in $HTML"
