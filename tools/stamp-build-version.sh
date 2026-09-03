#!/bin/bash
# Stamp the build version into every HTML page footer.
# Usage: tools/stamp-build-version.sh <version>
#
# <version> is either a git commit SHA (7-40 lowercase hex chars), which links
# the footer to https://github.com/angeswe/nullpad/commit/<sha>, or the literal
# "dev", which links to the repository. Anything else fails the build rather
# than shipping a footer that looks right but links nowhere.
#
# Build-time only (called from the Dockerfiles): it consumes the placeholders in
# place, so never run it in a working tree you intend to commit.

set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:?usage: $0 <version>}"
repo_url="https://github.com/angeswe/nullpad"

if [[ "$version" =~ ^[0-9a-f]{7,40}$ ]]; then
  commit_url="$repo_url/commit/$version"
elif [[ "$version" == "dev" ]]; then
  commit_url="$repo_url"
else
  echo "error: build version '$version' is neither a commit SHA (7-40 lowercase hex chars) nor 'dev'" >&2
  exit 1
fi

# An unmatched glob stays literal, so a missing directory fails the checks below.
pages=(static/*.html protected/*.html)

# Refuse to "succeed" on pages that have nothing to stamp (already stamped, or
# missing the footer) rather than shipping whatever version they already carry.
for page in "${pages[@]}"; do
  if [[ ! -r "$page" ]]; then
    echo "error: $page is missing or unreadable" >&2
    exit 1
  fi
  if ! grep -q "__BUILD_VERSION__" "$page" || ! grep -q "__BUILD_COMMIT_URL__" "$page"; then
    echo "error: $page has no build placeholders to stamp" >&2
    exit 1
  fi
done

sed -i "s|__BUILD_VERSION__|${version}|g; s|__BUILD_COMMIT_URL__|${commit_url}|g" "${pages[@]}"

# Final guard is recursive so a placeholder in a page the glob does not cover
# (or one that strayed into JS/CSS) cannot ship. grep exits 1 when nothing
# matches; anything else means it could not check and must not pass either.
leftovers=$(grep -rl "__BUILD_" static protected) && status=0 || status=$?
if (( status == 0 )); then
  echo "error: build placeholders remain in: ${leftovers//$'\n'/ }" >&2
  exit 1
elif (( status != 1 )); then
  echo "error: could not verify pages after stamping (grep exit $status)" >&2
  exit 1
fi

echo "Stamped build version ${version} into ${#pages[@]} pages"
