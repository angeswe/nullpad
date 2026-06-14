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
    // Padding
    // ============================================================================
    //
    // After V1 framing and before AES-GCM, plaintext is padded to a fixed size
    // to hide length information from the server.
    //
    // Metadata mode: pad to the smallest multiple of 512 that is STRICTLY
    // greater than the framed length. This hides filename-length fingerprinting.
    // Worst case (255-char multibyte filename) produces ~830 framed bytes → 1024
    // padded plaintext → ~1052-byte ciphertext → ~1403 base64 bytes, well within
    // the server's 4096-byte encrypted_metadata cap.
    //
    // Content mode: pad to the first bucket from the ladder below that is
    // STRICTLY greater than the framed length. "Strictly greater" means that an
    // input whose framed length exactly equals a bucket boundary is pushed to the
    // next bucket — this prevents a no-padding side channel.
    //
    // Buckets: 1KiB, 4KiB, 16KiB, 64KiB, 256KiB, 1MiB, 4MiB, 16MiB, MAX_CONTENT_BUCKET
    //
    // MAX_CONTENT_BUCKET = MAX_UPLOAD_BYTES - AES_GCM_OVERHEAD (28 bytes) so that
    // padded plaintext (bucket size) + 12-byte IV + 16-byte GCM tag never exceeds
    // the server's MAX_UPLOAD_BYTES limit (default 52,428,800). Inputs with a framed
    // length ≥ MAX_CONTENT_BUCKET must be rejected with a client-side error before
    // encryption rather than producing an oversized blob.
    //
    // The length prefix in the V1 frame already tells the decoder where real data
    // ends — unframeV1OrNull() strips trailing padding on decrypt with no changes.

    // AES-GCM overhead: 12-byte IV + 16-byte authentication tag.
    const AES_GCM_OVERHEAD = 28;

    // Default server upload cap. Fetched from /api/config at runtime in create.js;
    // this constant is a safe fallback for the crypto module's own checks.
    const DEFAULT_MAX_UPLOAD_BYTES = 52428800; // 50 MiB

    // Maximum framed plaintext that, after AES-GCM encryption, fits the default cap.
    // = DEFAULT_MAX_UPLOAD_BYTES - AES_GCM_OVERHEAD
    const MAX_CONTENT_BUCKET = DEFAULT_MAX_UPLOAD_BYTES - AES_GCM_OVERHEAD; // 52,428,772

    // Content padding bucket ladder (bytes). All values < MAX_CONTENT_BUCKET.
    const CONTENT_BUCKETS = [
        1024,           // 1 KiB
        4096,           // 4 KiB
        16384,          // 16 KiB
        65536,          // 64 KiB
        262144,         // 256 KiB
        1048576,        // 1 MiB
        4194304,        // 4 MiB
        16777216,       // 16 MiB
        MAX_CONTENT_BUCKET
    ];

    /**
     * Pad framedBytes to targetLen with zero bytes.
     * Caller is responsible for ensuring targetLen >= framedBytes.length.
     * @param {Uint8Array} framedBytes
     * @param {number} targetLen
     * @returns {Uint8Array}
     */
    function padTo(framedBytes, targetLen) {
        if (targetLen === framedBytes.length) return framedBytes;
        const out = new Uint8Array(targetLen); // zero-filled by default
        out.set(framedBytes, 0);
        return out;
    }

    /**
     * Select the metadata padding target: smallest multiple of 512 strictly
     * greater than framedLen.
     * @param {number} framedLen
     * @returns {number}
     */
    function metadataPadTarget(framedLen) {
        // Adding 1 before ceil ensures we get the NEXT multiple, not the same
        // one — equality (framedLen already a multiple of 512) must promote up.
        return Math.ceil((framedLen + 1) / 512) * 512;
    }

    /**
     * Select the content padding target: first bucket strictly greater than
     * framedLen. Returns null if no bucket can hold the framed data (caller
     * must reject the upload before encryption).
     * @param {number} framedLen
     * @returns {number|null}
     */
    function contentPadTarget(framedLen) {
        for (const bucket of CONTENT_BUCKETS) {
            if (bucket > framedLen) return bucket;
        }
        return null; // input too large for any bucket
    }

    // ============================================================================
    // Encryption
    // ============================================================================

    /**
     * Encrypt plaintext with AES-256-GCM.
     *
     * @param {string|Uint8Array} plaintext - Data to encrypt
     * @param {string} keyBase64url - Encryption key as base64url string
     * @param {string} [aad] - Optional Additional Authenticated Data (e.g. paste ID)
     * @param {object} [options]
     * @param {'metadata'|'content'|'none'} [options.pad='none'] - Padding mode:
     *   'metadata' pads framed plaintext to the next multiple of 512 (>= framed+1),
     *   'content'  pads to the first bucket from the ladder strictly greater than
     *              framed length,
     *   'none'     no padding (legacy / default).
     * @returns {Promise<string>} Base64-encoded (IV + ciphertext)
     * @throws {Error} if pad='content' and framed length exceeds the top bucket
     */
    async function encrypt(plaintext, keyBase64url, aad, options) {
        if (options !== undefined && options !== null && typeof options !== 'object') {
            throw new TypeError('encrypt(): options must be an object');
        }
        const padMode = (options && options.pad !== undefined) ? options.pad : 'none';

        // Convert plaintext to bytes if it's a string
        const plaintextBytes = typeof plaintext === 'string'
            ? textEncode(plaintext)
            : plaintext;

        // Frame with version byte + length prefix before encryption so the
        // decoder can strip future padding back to the real data length.
        const framedBytes = frameV1(plaintextBytes);

        // Apply padding after framing. The length prefix lets the decoder ignore
        // the trailing zero bytes during decryption — no decrypt changes needed.
        let paddedBytes;
        if (padMode === 'metadata') {
            const target = metadataPadTarget(framedBytes.length);
            paddedBytes = padTo(framedBytes, target);
        } else if (padMode === 'content') {
            const target = contentPadTarget(framedBytes.length);
            if (target === null) {
                throw new Error(
                    'Content too large: exceeds maximum supported upload size.'
                );
            }
            paddedBytes = padTo(framedBytes, target);
        } else if (padMode === 'none') {
            paddedBytes = framedBytes;
        } else {
            throw new Error(`encrypt(): Unknown padding mode: ${padMode}`);
        }

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
                paddedBytes
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

        // Padding helpers (used by create.js for pre-flight size checks)
        contentPadTarget,
        metadataPadTarget,

        // Framing/overhead constants (exported so create.js avoids duplicating them)
        AES_GCM_OVERHEAD,
        V1_HEADER_LEN,

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
