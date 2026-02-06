# nullpad

[![CI](https://github.com/angeswe/nullpad/actions/workflows/ci.yml/badge.svg)](https://github.com/angeswe/nullpad/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

Zero-knowledge encrypted paste and file sharing. Server never sees plaintext.

**Live instance**: [nullpad.io](https://nullpad.io) — Note: nullpad.io is behind Cloudflare, which logs requests. Self-host for maximum privacy.

## What is nullpad?

A privacy-first pastebin where all encryption happens in your browser. The server only stores ciphertext — no plaintext, no keys, no user secrets. Share sensitive data with confidence.

## How it works

- **Client-side encryption**: Browser encrypts content with AES-256-GCM before upload
- **Key in URL fragment**: Decryption key lives in the URL hash (`#key`), never sent to server
- **Optional PIN protection**: Add a second factor via Argon2id key derivation
- **Passwordless auth**: Ed25519 challenge-response authentication — no passwords stored
- **Auto-expiration**: Everything has a TTL — pastes, sessions, invites all expire automatically
- **Burn after reading**: Atomic read-and-delete for one-time secrets

## Quick Start (Docker)

```bash
# Copy example config
cp .env.example .env

# Generate admin keypair
openssl genpkey -algorithm ED25519 -out admin_key.pem
openssl pkey -in admin_key.pem -pubout -outform DER | tail -c 32 | base64
# Save admin_key.pem securely, copy the base64 output to ADMIN_PUBKEY in .env
nano .env

# Start services
docker compose up -d

# Visit http://localhost:3015
```

## Development Setup

**Prerequisites**: Rust (latest stable), Redis (7.0+)

```bash
# Install Redis
# Ubuntu/Debian: apt install redis-server
# macOS: brew install redis
# Or run via Docker: docker run -d -p 6379:6379 redis:7-alpine

# Start Redis (skip if using Docker)
redis-server

# Copy config and set ADMIN_PUBKEY
cp .env.example .env

# Run the app
cargo run --release

# Visit http://localhost:3000
```

## Configuration

See `.env.example` for all available options. Key environment variables:

- `ADMIN_PUBKEY` — Base64-encoded Ed25519 public key (32 bytes), generated via openssl (required)
- `ADMIN_ALIAS` — Admin username (default: "admin")
- `REDIS_URL` — Redis connection string (default: "redis://127.0.0.1:6379")
- `BIND_ADDR` — Server bind address (default: "0.0.0.0:3000")
- `MAX_UPLOAD_BYTES` — Max file size (default: 52428800 / 50MB)
- `DEFAULT_TTL_SECS` — Default paste expiration (default: 86400 / 24h)
- `MAX_TTL_SECS` — Maximum paste lifetime (default: 604800 / 7d)

Rate limiting, session lifetimes, and challenge timeouts are also configurable. Set `RUST_LOG=info` (or `debug`) for application logging.

## Security Model

**Encryption**
- Content: AES-256-GCM via Web Crypto API
- Key derivation: Argon2id (m=19456, t=2, p=1) — OWASP recommended params
- Keys never leave the browser or touch the server

**Authentication**
- Ed25519 challenge-response (no passwords)
- Single-use nonces with 30s TTL
- Session tokens expire in 15 minutes
- Auth challenge returns identical responses for valid and invalid aliases (anti-enumeration)
- ADMIN_PUBKEY validated as correct Ed25519 key at startup (fail-fast)

**Transport & Headers**
- Strict CSP: `default-src 'self'`
- SRI hashes on all script tags
- HSTS, no-referrer policy
- X-Content-Type-Options: nosniff
- Request body size limit enforced at framework level

**Rate Limiting**
- IP-based rate limiting on paste creation, paste retrieval, and auth endpoints
- Uses X-Forwarded-For / X-Real-IP behind reverse proxies, falls back to direct IP

**Data Expiration**
- All Redis keys have TTLs by default — trusted users may create "forever" pastes with no expiration
- Burn-after-reading uses atomic Lua script (no race conditions)
- Burn and admin delete clean up user_pastes references atomically

**Logging**
- No HTTP access logs — nullpad does not log request paths, paste IDs, or IP addresses
- Only security-relevant events are logged: rate limit triggers (hashed IP), auth failures, admin actions
- This is intentional — access logs would undermine the zero-knowledge model

**Note on CDN/Proxy logging**: If you deploy behind Cloudflare, nginx, or another reverse proxy, those services may log requests independently. Nullpad has no control over upstream logging. For maximum privacy, review your proxy's logging configuration.

## Tech Stack

**Backend**
- Rust with Axum 0.8 web framework
- Redis for ephemeral storage (everything expires)
- ed25519-dalek for signature verification
- zeroize for secure memory cleanup

**Frontend**
- Vanilla HTML/JS (no build step)
- Web Crypto API for AES-256-GCM and Ed25519
- hash-wasm for Argon2id key derivation
- marked.js + highlight.js for markdown rendering
- DOMPurify for XSS-safe HTML sanitization

## API Endpoints

### Public

- `GET /healthz` — Health check (returns Redis connectivity status)
- `POST /api/paste` — Create encrypted paste
- `GET /api/paste/{id}` — Retrieve paste (deletes if burn-after-reading)
- `POST /api/auth/challenge` — Request authentication nonce
- `POST /api/auth/verify` — Submit signed challenge
- `POST /api/auth/logout` — Invalidate current session
- `POST /api/register` — Claim invite with alias and public key

### Admin (requires session)

- `POST /api/invites` — Generate invite link
- `GET /api/invites` — List pending invites
- `DELETE /api/invites/{token}` — Revoke invite
- `GET /api/users` — List trusted users
- `DELETE /api/users/{id}` — Revoke user access
- `DELETE /api/paste/{id}` — Delete specific paste

## File Types

- **Public pastes**: Text/markdown paste only (no file upload), TTL up to 7 days
- **Trusted users**: Any file type via drag & drop after registration, plus a "forever" (no expiration) option

## Deployment

**IMPORTANT**: Nullpad listens on plain HTTP (default `:3000`) and sets HSTS headers with preload. You MUST deploy behind a TLS-terminating reverse proxy in production.

### Why TLS is Required

The application sets `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` to ensure all connections use HTTPS. However, the Rust application itself does not handle TLS — this must be configured at the reverse proxy layer.

### Reverse Proxy Examples

#### nginx with TLS

```nginx
server {
    listen 443 ssl http2;
    server_name paste.example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name paste.example.com;
    return 301 https://$server_name$request_uri;
}
```

#### Caddy (automatic TLS)

```
paste.example.com {
    reverse_proxy localhost:3000
}
```

Caddy automatically obtains and renews TLS certificates via Let's Encrypt.

### X-Forwarded-For Configuration

Nullpad uses the `X-Forwarded-For` header for rate limiting when behind a reverse proxy. Set `TRUSTED_PROXY_COUNT` to the number of trusted proxies in your deployment:

- `TRUSTED_PROXY_COUNT=0` (default): Uses the direct connection IP (no proxy)
- `TRUSTED_PROXY_COUNT=1`: Trusts the first proxy (single nginx/Caddy instance)
- `TRUSTED_PROXY_COUNT=2`: Trusts two proxies (e.g., Cloudflare + nginx)

Example with Cloudflare + nginx:
```bash
TRUSTED_PROXY_COUNT=2
```

### Docker Deployment with TLS

The provided `docker-compose.yml` exposes the application on port 3015 (HTTP only). In production, place a TLS-terminating reverse proxy in front of it (nginx, Caddy, Traefik, etc.) and do not expose port 3015 publicly.

## License

AGPL-3.0 — see LICENSE file for details.
