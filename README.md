# nullpad

Zero-knowledge encrypted paste and file sharing. Server never sees plaintext.

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
# Open tools/keygen.html in your browser, save the public key

# Set ADMIN_PUBKEY in .env (base64-encoded Ed25519 public key)
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

# Start Redis
redis-server

# Copy config and set ADMIN_PUBKEY
cp .env.example .env

# Run the app
cargo run --release

# Visit http://localhost:3000
```

## Configuration

See `.env.example` for all available options. Key environment variables:

- `ADMIN_PUBKEY` — Base64-encoded Ed25519 public key (32 bytes) from tools/keygen.html (required)
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

- **Public pastes**: `.md` and `.txt` files only, TTL up to 7 days
- **Trusted users**: Any file type after registration via invite, plus a "forever" (no expiration) option

## License

AGPL-3.0 — see LICENSE file for details.
