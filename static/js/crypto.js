/**
 * Nullpad Crypto Module
 *
 * Client-side encryption using Web Crypto API.
 * AES-256-GCM for content encryption, Argon2id for PIN-based key derivation.
 * All encryption/decryption happens in the browser — server never sees plaintext or keys.
 */

(function() {
    'use strict';

    // ============================================================================
    // Base64 Encoding/Decoding Helpers
    // ============================================================================

    /**
     * Encode Uint8Array to URL-safe base64 string (no padding, use - and _ instead of + and /)
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    function base64urlEncode(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    /**
     * Decode URL-safe base64 string to Uint8Array
     * @param {string} str
     * @returns {Uint8Array}
     */
    function base64urlDecode(str) {
        // Convert URL-safe base64 back to standard base64
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding if needed
        while (base64.length % 4) {
            base64 += '=';
        }
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    /**
     * Encode Uint8Array to standard base64 string
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    function base64Encode(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Decode standard base64 string to Uint8Array
     * @param {string} str
     * @returns {Uint8Array}
     */
    function base64Decode(str) {
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

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
    // Encryption
    // ============================================================================

    /**
     * Encrypt plaintext with AES-256-GCM
     * @param {string|Uint8Array} plaintext - Data to encrypt
     * @param {string} keyBase64url - Encryption key as base64url string
     * @returns {Promise<string>} Base64-encoded (IV + ciphertext)
     */
    async function encrypt(plaintext, keyBase64url) {
        // Convert plaintext to bytes if it's a string
        const plaintextBytes = typeof plaintext === 'string'
            ? textEncode(plaintext)
            : plaintext;

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

            // Encrypt with AES-GCM
            const ciphertext = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                cryptoKey,
                plaintextBytes
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
     * @returns {Promise<Uint8Array>} Decrypted data (caller decides text vs binary)
     */
    async function decrypt(encryptedBase64, key) {
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

            // Decrypt with AES-GCM
            const plaintext = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                cryptoKey,
                ciphertext
            );

            return new Uint8Array(plaintext);
        } finally {
            keyBytes.fill(0);
        }
    }

    // ============================================================================
    // Export Public API
    // ============================================================================

    window.NullpadCrypto = {
        // Key generation
        generateKey,
        deriveKeyWithPin,

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
    };

})();
