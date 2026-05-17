/**
 * Nullpad Crypto Module
 *
 * Client-side encryption using Web Crypto API.
 * AES-256-GCM for content encryption, Argon2id for PIN-based key derivation.
 * All encryption/decryption happens in the browser — server never sees plaintext or keys.
 *
 * LIMITATION: AES-GCM lacks key commitment — a ciphertext can theoretically decrypt
 * under multiple keys to different plaintexts. This is a known limitation of GCM mode
 * (see "Partitioning Oracle Attacks"). For nullpad's threat model (single-key per paste),
 * this is acceptable. If key commitment is required, consider AES-GCM-SIV or HKDF-based
 * key derivation with a commitment scheme.
 *
 * SECURITY: JS strings are immutable and cannot be zeroed from memory. String representations
 * of key material (base64url keys, PINs) persist in memory until garbage collected.
 */

(function() {
    'use strict';

    // ============================================================================
    // Base64 Encoding/Decoding Helpers (shared module)
    // ============================================================================

    const { base64Encode, base64Decode, base64urlEncode, base64urlDecode } = NullpadBase64;

    /**
     * Encode string to UTF-8 Uint8Array
     * @param {string} str
     * @returns {Uint8Array}
     */
    function textEncode(str) {
        return new TextEncoder().encode(str);
    }

    /**
     * Decode UTF-8 Uint8Array to string
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    function textDecode(bytes) {
        return new TextDecoder().decode(bytes);
    }

    // ============================================================================
    // ID Generation
    // ============================================================================

    const NANOID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';

    /**
     * Generate a cryptographically random nanoid (12 chars, URL-safe alphabet)
     * @returns {string}
     */
    function generateId() {
        const bytes = new Uint8Array(12);
        crypto.getRandomValues(bytes);
        let id = '';
        for (let i = 0; i < 12; i++) {
            id += NANOID_ALPHABET[bytes[i] & 63]; // 64 chars in alphabet = 6 bits
        }
        return id;
    }

    // ============================================================================
    // Key Generation
    // ============================================================================

    /**
     * Generate a random AES-256-GCM key
     * @returns {string} Base64url-encoded key (URL-safe for fragment)
     */
    function generateKey() {
        const keyBytes = new Uint8Array(32); // 256 bits
        crypto.getRandomValues(keyBytes);
        // SECURITY: Returned string cannot be zeroed from memory (JS strings are immutable)
        return base64urlEncode(keyBytes);
    }

    /**
     * Derive a new key from existing key + PIN using Argon2id with random salt.
     * Returns both the derived key and the salt (caller must store salt with ciphertext).
     * @param {string|Uint8Array} key - Original key as base64url string or raw bytes
     * @param {string} pin - PIN to mix into key derivation
     * @param {Uint8Array} [existingSalt] - Salt from existing paste (for decryption)
     * @returns {Promise<{key: string, salt: Uint8Array}>} Derived key + salt
     */
    async function deriveKeyWithPin(key, pin, existingSalt) {
        // Decode the original key if string, copy if Uint8Array (caller retains original)
        const keyBytes = key instanceof Uint8Array ? new Uint8Array(key) : base64urlDecode(key);

        // Combine key + PIN as password material
        const pinBytes = textEncode(pin);
        const password = new Uint8Array(keyBytes.length + pinBytes.length);
        password.set(keyBytes, 0);
        password.set(pinBytes, keyBytes.length);

        // Use random salt (generated fresh for encryption, provided for decryption)
        const salt = existingSalt || crypto.getRandomValues(new Uint8Array(16));

        try {
            // Derive 32 bytes using Argon2id (OWASP recommended params)
            const hash = await hashwasm.argon2id({
                password,
                salt,
                parallelism: 1,
                iterations: 2,
                memorySize: 19456,
                hashLength: 32,
                outputType: 'binary'
            });

            // SECURITY: Returned key string cannot be zeroed from memory (JS strings are immutable)
            const result = { key: base64urlEncode(new Uint8Array(hash)), salt };
            // Zero the hash output
            new Uint8Array(hash).fill(0);
            return result;
        } finally {
            // Zero sensitive key material
            keyBytes.fill(0);
            pinBytes.fill(0);
            password.fill(0);
        }
    }

    // ============================================================================
    // Plaintext Framing
    // ============================================================================
    //
    // Inside the AES-GCM ciphertext, plaintext is framed as:
    //   [version: 1 byte (0x01)] [length: 4 bytes LE] [data: <length> bytes] [padding: trailing bytes ignored]
    //
    // The version byte lets future formats add padding (forthcoming bucket
    // ladder) without breaking existing pastes. The length prefix is what
    // tells the decoder where real data ends so padding can be stripped.
    //
    // Backward compatibility: pastes encrypted before this change have no
    // version byte. On decrypt, a first byte != VERSION_V1 (or a malformed
    // V1 header) is treated as legacy v0 and returned unchanged.

    const VERSION_V1 = 0x01;
    const V1_HEADER_LEN = 5; // 1 byte version + 4 bytes length

    /** Wrap raw plaintext bytes in the V1 frame: [0x01][length LE u32][data]. */
    function frameV1(plaintextBytes) {
        const out = new Uint8Array(V1_HEADER_LEN + plaintextBytes.length);
        out[0] = VERSION_V1;
        // 4-byte little-endian length prefix
        new DataView(out.buffer).setUint32(1, plaintextBytes.length, true);
        out.set(plaintextBytes, V1_HEADER_LEN);
        return out;
    }

    /**
     * Strip the V1 frame if present and well-formed. Returns null otherwise so
     * the caller can fall back to the legacy v0 path (return bytes as-is).
     *
     * A legacy v0 plaintext whose first byte happens to be 0x01 followed by a
     * 4-byte run that decodes to a length > body would mistakenly enter this
     * function. By returning null on that mismatch rather than throwing, we
     * keep legacy binary pastes (e.g. files starting with 0x01) decryptable
     * instead of surfacing as the generic "Invalid key or PIN" error that the
     * decrypt-retry chain in view.js would otherwise remap a throw into.
     * The residual collision case — first byte 0x01 AND a 4-byte length value
     * that happens to be <= body — silently truncates the legacy plaintext;
     * this is the unavoidable migration cost of an in-band version sniff and
     * affects only pre-existing binary pastes.
     */
    function unframeV1OrNull(decryptedBytes) {
        if (decryptedBytes.length < V1_HEADER_LEN) return null;
        if (decryptedBytes[0] !== VERSION_V1) return null;
        const length = new DataView(
            decryptedBytes.buffer,
            decryptedBytes.byteOffset + 1,
            4
        ).getUint32(0, true);
        const bodyLen = decryptedBytes.length - V1_HEADER_LEN;
        if (length > bodyLen) return null;
        return decryptedBytes.subarray(V1_HEADER_LEN, V1_HEADER_LEN + length);
    }

    // ============================================================================
    // Encryption
    // ============================================================================

    /**
     * Encrypt plaintext with AES-256-GCM
     * @param {string|Uint8Array} plaintext - Data to encrypt
     * @param {string} keyBase64url - Encryption key as base64url string
     * @param {string} [aad] - Optional Additional Authenticated Data (e.g. paste ID)
     * @returns {Promise<string>} Base64-encoded (IV + ciphertext)
     */
    async function encrypt(plaintext, keyBase64url, aad) {
        // Convert plaintext to bytes if it's a string
        const plaintextBytes = typeof plaintext === 'string'
            ? textEncode(plaintext)
            : plaintext;

        // Frame with version byte + length prefix before encryption so the
        // decoder can strip future padding back to the real data length.
        const framedBytes = frameV1(plaintextBytes);

        // Decode key
        const keyBytes = base64urlDecode(keyBase64url);

        try {
            // Import key for AES-GCM
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'AES-GCM' },
                false,
                ['encrypt']
            );

            // Generate random 12-byte IV
            const iv = new Uint8Array(12);
            crypto.getRandomValues(iv);

            // Build AES-GCM params with optional AAD
            const params = { name: 'AES-GCM', iv: iv };
            if (aad) {
                params.additionalData = textEncode(aad);
            }

            // Encrypt with AES-GCM
            const ciphertext = await crypto.subtle.encrypt(
                params,
                cryptoKey,
                framedBytes
            );

            // Concatenate IV + ciphertext
            const ciphertextBytes = new Uint8Array(ciphertext);
            const combined = new Uint8Array(iv.length + ciphertextBytes.length);
            combined.set(iv, 0);
            combined.set(ciphertextBytes, iv.length);

            // Return as standard base64
            return base64Encode(combined);
        } finally {
            keyBytes.fill(0);
        }
    }

    // ============================================================================
    // Decryption
    // ============================================================================

    /**
     * Decrypt AES-256-GCM ciphertext
     * @param {string} encryptedBase64 - Base64-encoded (IV + ciphertext)
     * @param {string|Uint8Array} key - Decryption key as base64url string or raw bytes
     * @param {string} [aad] - Optional Additional Authenticated Data (e.g. paste ID)
     * @returns {Promise<Uint8Array>} Decrypted data (caller decides text vs binary)
     */
    async function decrypt(encryptedBase64, key, aad) {
        // Decode the combined IV + ciphertext
        const combined = base64Decode(encryptedBase64);

        // Extract IV (first 12 bytes) and ciphertext (rest)
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);

        // Decode key if string, copy if Uint8Array (caller retains original)
        const keyBytes = key instanceof Uint8Array ? new Uint8Array(key) : base64urlDecode(key);

        try {
            // Import key for AES-GCM
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );

            // Build AES-GCM params with optional AAD
            const params = { name: 'AES-GCM', iv: iv };
            if (aad) {
                params.additionalData = textEncode(aad);
            }

            // Decrypt with AES-GCM
            const plaintext = await crypto.subtle.decrypt(
                params,
                cryptoKey,
                ciphertext
            );

            const decryptedBytes = new Uint8Array(plaintext);
            // Strip V1 frame ([0x01][len LE u32][data]) when present. Legacy
            // (pre-frame) pastes lack the version byte and are returned as-is.
            return unframeV1OrNull(decryptedBytes) ?? decryptedBytes;
        } finally {
            keyBytes.fill(0);
        }
    }

    // ============================================================================
    // PIN Verifier
    // ============================================================================

    /**
     * Compute a PIN verifier for server-side validation.
     * verifier = HMAC-SHA256(derived_key, paste_id)
     * Server stores this at creation; client recomputes it at retrieval.
     * ZK-safe: server cannot recover PIN without the raw key (URL fragment).
     * @param {string} derivedKeyBase64url - PIN-derived key as base64url string
     * @param {string} pasteId - Paste ID used as HMAC message
     * @returns {Promise<string>} Base64-encoded HMAC (32 bytes)
     */
    async function computePinVerifier(derivedKeyBase64url, pasteId) {
        const keyBytes = base64urlDecode(derivedKeyBase64url);
        try {
            const hmacKey = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            const sig = await crypto.subtle.sign(
                'HMAC',
                hmacKey,
                textEncode(pasteId)
            );
            return base64Encode(new Uint8Array(sig));
        } finally {
            keyBytes.fill(0);
        }
    }

    // ============================================================================
    // Export Public API
    // ============================================================================

    const NullpadCrypto = Object.freeze({
        // ID and key generation
        generateId,
        generateKey,
        deriveKeyWithPin,

        // PIN verification
        computePinVerifier,

        // Encryption/Decryption
        encrypt,
        decrypt,

        // Helpers
        base64urlEncode,
        base64urlDecode,
        base64Encode,
        base64Decode,
        textEncode,
        textDecode
    });

    Object.defineProperty(window, 'NullpadCrypto', {
        value: NullpadCrypto,
        writable: false,
        configurable: false
    });

})();
