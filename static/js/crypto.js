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

    /**
     * One allocation: header, data, zero padding.
     * Caller ensures targetLen >= V1_HEADER_LEN + plaintextBytes.length.
     * @param {Uint8Array} plaintextBytes
     * @param {number} targetLen
     * @returns {Uint8Array}
     */
    function frameAndPad(plaintextBytes, targetLen) {
        const out = new Uint8Array(targetLen);
        out[0] = VERSION_V1;
        new DataView(out.buffer).setUint32(1, plaintextBytes.length, true);
        out.set(plaintextBytes, V1_HEADER_LEN);
        return out;
    }

    /**
     * Strip the V1 frame if present and well-formed. Returns null otherwise so
     * the caller can fall back to the legacy v0 path (return bytes as-is).
     *
     * A plaintext is V1 only if byte 0 is 0x01, the 4-byte length fits in the
     * body, and every byte after the data is zero (V1 padding is all zeros).
     * Returning null rather than throwing keeps legacy binary pastes that start
     * with 0x01 decryptable instead of surfacing as the generic "Invalid key or
     * PIN" error that the decrypt-retry chain in view.js would remap a throw
     * into. The residual collision case is a legacy plaintext with first byte
     * 0x01, a fitting length, and an all-zero tail after that length: it is
     * silently truncated. This is the migration cost of an in-band version
     * sniff and affects only pre-existing binary pastes.
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
        for (let i = V1_HEADER_LEN + length; i < decryptedBytes.length; i++) {
            if (decryptedBytes[i] !== 0) return null;
        }
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
    // Buckets: 4x steps up to 1MiB (1KiB, 4KiB, 16KiB, 64KiB, 256KiB, 1MiB), then
    // 2x steps above (2MiB, 4MiB, 8MiB, 16MiB, 32MiB). The top bucket is
    // maxBlobBytes - AES_GCM_OVERHEAD (28 bytes): every bucket is clamped to it,
    // and content above the last ladder bucket pads to it. maxBlobBytes is the server's
    // cap for this user (from /api/config), so padded plaintext + 12-byte IV +
    // 16-byte GCM tag never exceeds it. Inputs with a framed length >=
    // maxBlobBytes - 28 must be rejected before encryption.
    //
    // The length prefix in the V1 frame already tells the decoder where real data
    // ends — unframeV1OrNull() strips trailing padding on decrypt with no changes.

    // AES-GCM overhead: 12-byte IV + 16-byte authentication tag.
    const AES_GCM_OVERHEAD = 28;

    // Smallest cap: an empty V1 frame must still be strictly below the top bucket.
    const MIN_BLOB_BYTES = AES_GCM_OVERHEAD + V1_HEADER_LEN + 1;

    const CONTENT_LADDER = [1024, 4096, 16384, 65536, 262144, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432];

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
     * First ladder bucket strictly greater than framedLen, clamped to maxBlobBytes - 28.
     * null when framedLen >= maxBlobBytes - 28.
     * @param {number} framedLen
     * @param {number} maxBlobBytes - Largest encrypted blob the server takes
     * @returns {number|null}
     * @throws {TypeError} if maxBlobBytes is not an integer from MIN_BLOB_BYTES to 0xFFFFFFFF
     */
    function contentPadTarget(framedLen, maxBlobBytes) {
        if (!Number.isInteger(maxBlobBytes) || maxBlobBytes < MIN_BLOB_BYTES || maxBlobBytes > 0xFFFFFFFF) {
            throw new TypeError(`maxBlobBytes must be an integer from ${MIN_BLOB_BYTES} to 4294967295`);
        }
        const topBucket = maxBlobBytes - AES_GCM_OVERHEAD;
        if (framedLen >= topBucket) return null;
        const bucket = CONTENT_LADDER.find((size) => size > framedLen);
        return bucket === undefined ? topBucket : Math.min(bucket, topBucket);
    }

    /**
     * Largest content in bytes that contentPadTarget still accepts for maxBlobBytes.
     * @param {number} maxBlobBytes
     * @returns {number}
     */
    function maxContentBytes(maxBlobBytes) {
        return maxBlobBytes - AES_GCM_OVERHEAD - V1_HEADER_LEN - 1;
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
     * @param {object} options
     * @param {'metadata'|'content'} options.pad - Padding mode:
     *   'metadata' pads framed plaintext to the next multiple of 512 (>= framed+1),
     *   'content'  pads to the first bucket from the ladder strictly greater than
     *              framed length, clamped to options.maxBlobBytes - 28.
     * @param {number} [options.maxBlobBytes] - Server blob cap; required when pad='content'
     * @returns {Promise<Uint8Array>} IV (12) + ciphertext + tag (16)
     * @throws {TypeError} if options.pad is missing, or pad='content' and maxBlobBytes is missing or invalid
     * @throws {Error} if the pad mode is unknown, or pad='content' and framed length exceeds the top bucket
     */
    async function encryptBytes(plaintext, keyBase64url, aad, options) {
        if (!options || typeof options !== 'object' || options.pad === undefined) {
            throw new TypeError('options.pad is required');
        }

        const plaintextBytes = typeof plaintext === 'string'
            ? textEncode(plaintext)
            : plaintext;
        const framedLen = V1_HEADER_LEN + plaintextBytes.length;

        let target;
        if (options.pad === 'metadata') {
            target = metadataPadTarget(framedLen);
        } else if (options.pad === 'content') {
            target = contentPadTarget(framedLen, options.maxBlobBytes);
            if (target === null) {
                throw new Error(
                    'Content too large: exceeds maximum supported upload size.'
                );
            }
        } else {
            throw new Error(`Unknown padding mode: ${options.pad}`);
        }
        const paddedBytes = frameAndPad(plaintextBytes, target);

        const keyBytes = base64urlDecode(keyBase64url);

        try {
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'AES-GCM' },
                false,
                ['encrypt']
            );

            const iv = new Uint8Array(12);
            crypto.getRandomValues(iv);

            const params = { name: 'AES-GCM', iv: iv };
            if (aad) {
                params.additionalData = textEncode(aad);
            }

            const ciphertext = await crypto.subtle.encrypt(
                params,
                cryptoKey,
                paddedBytes
            );

            const ciphertextBytes = new Uint8Array(ciphertext);
            const combined = new Uint8Array(iv.length + ciphertextBytes.length);
            combined.set(iv, 0);
            combined.set(ciphertextBytes, iv.length);
            return combined;
        } finally {
            keyBytes.fill(0);
        }
    }

    /**
     * Base64 of encryptBytes(). Used for encrypted_metadata.
     * @returns {Promise<string>}
     */
    async function encrypt(plaintext, keyBase64url, aad, options) {
        return base64Encode(await encryptBytes(plaintext, keyBase64url, aad, options));
    }

    // ============================================================================
    // Decryption
    // ============================================================================

    /**
     * Decrypt AES-256-GCM ciphertext
     * @param {string|Uint8Array} data - IV + ciphertext, as a base64 string or raw bytes
     * @param {string|Uint8Array} key - Decryption key as base64url string or raw bytes
     * @param {string} [aad] - Optional Additional Authenticated Data (e.g. paste ID)
     * @returns {Promise<Uint8Array>} Decrypted data (caller decides text vs binary)
     */
    async function decrypt(data, key, aad) {
        // The combined IV + ciphertext. Raw bytes are used as they are (paste
        // bodies arrive as bytes); strings are base64 (e.g. encrypted metadata).
        let combined;
        if (data instanceof Uint8Array) {
            combined = data;
        } else if (typeof data === 'string') {
            combined = base64Decode(data);
        } else {
            throw new TypeError('decrypt: data must be a base64 string or a Uint8Array');
        }

        // Extract IV (first 12 bytes) and ciphertext (rest). subarray, not
        // slice: the ciphertext can be large and does not need a copy.
        const iv = combined.slice(0, 12);
        const ciphertext = combined.subarray(12);

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
        // Key generation
        generateKey,
        deriveKeyWithPin,

        // PIN verification
        computePinVerifier,

        // Encryption/Decryption
        encrypt,
        encryptBytes,
        decrypt,

        // Padding helpers (maxContentBytes sets create.js's size limit)
        contentPadTarget,
        maxContentBytes,
        metadataPadTarget,

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
