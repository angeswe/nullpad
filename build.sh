#!/bin/bash
# build.sh - build the production image for the cluster and push it to the registry.
set -e

# Load .env.production into environment if present (REGISTRY_PASSWORD lives there)
if [[ -f .env.production ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env.production
  set +a
fi

APP="${APP:-$(basename "$(pwd)")}"
REGISTRY="${REGISTRY:-registry.valsta.nu:5005}"
REGISTRY_USER="${REGISTRY_USER:-din}"
REGISTRY_PASSWORD="${REGISTRY_PASSWORD:-}"

: "${REGISTRY_PASSWORD:?REGISTRY_PASSWORD must be set (export it or put it in .env.production)}"

# Login to registry (non-interactive; the password never goes on a command line)
printf '%s' "$REGISTRY_PASSWORD" | docker login "https://$REGISTRY" -u "$REGISTRY_USER" --password-stdin

timestamp=$(date +%Y%m%d-%H%M%S)

# Ensure a buildx builder that uses host networking for name resolution
if docker buildx inspect net-host >/dev/null 2>&1; then
  docker buildx use net-host >/dev/null
else
  docker buildx create --name net-host --driver docker-container --driver-opt network=host --use >/dev/null
fi
docker buildx inspect --bootstrap >/dev/null

image_ts="$REGISTRY/$APP:$timestamp"
image_latest="$REGISTRY/$APP:latest"
echo "==> Building $APP for linux/arm64 -> $image_ts (+ latest)"
REG_IP=$(getent hosts "${REGISTRY%%:*}" | awk '{print $1}' | head -n1)
# --provenance=false --sbom=false: emit a plain single-platform arm64 manifest
# instead of an OCI index with an attestation. trivy-operator defaults to the
# linux/amd64 entry of an index and fails on arm64-only ones ("only Linux amd64
# images are supported"); a plain manifest is scanned natively. See k3s-cluster.
docker buildx build \
  --platform linux/arm64 \
  --provenance=false \
  --sbom=false \
  --add-host "${REGISTRY%%:*}:$REG_IP" \
  -f Dockerfile.prod \
  -t "$image_ts" \
  -t "$image_latest" \
  --push \
  .

echo "✅ $APP pushed at $timestamp"
