# Security Policy

## Reporting a Vulnerability

**Please do not open public issues for security vulnerabilities.**

If you discover a security vulnerability in nullpad, please report it privately:

1. **GitHub Private Advisory** (preferred): [Report a vulnerability](https://github.com/angeswe/nullpad/security/advisories/new)

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to expect

- Credit in the fix (unless you prefer anonymity)

## Scope

Security issues we care about:

- Cryptographic weaknesses (key leakage, weak encryption, etc.)
- Authentication/authorization bypass
- Server-side vulnerabilities (injection, SSRF, etc.)
- Client-side vulnerabilities (XSS, CSRF, etc.)
- Information disclosure
- Denial of service (within reason)

Out of scope:

- Vulnerabilities in dependencies (report upstream, but let us know)
- Social engineering
- Physical attacks
- Issues in third-party services (Cloudflare, Redis, etc.)

## Security Model

See the [README](README.md#security-model) for details on nullpad's security architecture. Key points:

- All encryption happens client-side (AES-256-GCM)
- Decryption keys never reach the server (URL fragment)
- Ed25519 challenge-response authentication
- No HTTP access logs by design

## Supported Versions

Only the latest version is supported with security updates. We recommend always running the most recent release.
