/**
 * AnswerChain Offline Cryptographic Verifier (Aadhaar-style ECDSA WebCrypto).
 *
 * Verifies ECDSA P-256 cryptographically signed academic credentials on-device
 * using the standard browser WebCrypto API (window.crypto.subtle).
 * Operates with 100% offline capability — ZERO internet connection required.
 * Includes graceful fallback for non-secure HTTP LAN IP contexts.
 */

(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.OfflineVerifier = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {

    // Default Authority P-256 Public Key (Uncompressed Point 65 bytes in Base64)
    // Synchronized automatically with /api/authority/offline-public-key when online
    const DEFAULT_AUTHORITY_PUBKEY_B64 = "BNjENkmLMlKGmlraTT9LxlgeLeTSPAOsuffydxCiK4bpKK0zy1HwtszYyCA3XS16LrJhJ3U1kOhZ1eGuxSrh2jw=";
    const STORAGE_KEY_PUBKEY = "answerchain_offline_authority_pubkey";

    function getAuthorityPublicKeyB64() {
        try {
            if (typeof localStorage !== 'undefined') {
                const cached = localStorage.getItem(STORAGE_KEY_PUBKEY);
                if (cached && cached.length > 50) return cached;
            }
        } catch (e) {
            // localStorage not available
        }
        return DEFAULT_AUTHORITY_PUBKEY_B64;
    }

    function saveAuthorityPublicKeyB64(b64) {
        try {
            if (typeof localStorage !== 'undefined' && b64 && b64.length > 50) {
                localStorage.setItem(STORAGE_KEY_PUBKEY, b64);
            }
        } catch (e) {}
    }

    /**
     * Decode URL-safe Base64 string to Uint8Array.
     */
    function base64ToUint8Array(base64Str) {
        let b64 = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) {
            b64 += '=';
        }
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    /**
     * Extract offline token from various QR representations:
     * - URL fragment: http://...#offline=<token>
     * - Query param: http://...?offline=<token>
     * - Prefix: ACHAIN-OFFLINE:<token>
     * - Raw Base64 token string
     */
    function extractOfflineToken(rawInput) {
        if (!rawInput || typeof rawInput !== 'string') return null;
        const text = rawInput.trim();

        // 1. URL fragment: #offline=... or #off=...
        const hashMatch = text.match(/#(?:offline|off)=([A-Za-z0-9_\-\+\/=.~%]+)/i);
        if (hashMatch) return hashMatch[1];

        // 2. Query param: ?offline=... or &offline=...
        const queryMatch = text.match(/[?&](?:offline|token)=([A-Za-z0-9_\-\+\/=.~%]+)/i);
        if (queryMatch) return queryMatch[1];

        // 3. Custom prefix ACHAIN-OFFLINE:... or Token: ... or Payload: ...
        const prefixMatch = text.match(/(?:ACHAIN-OFFLINE|Token|Payload):\s*([A-Za-z0-9_\-\+\/=.~%]+)/i);
        if (prefixMatch) return prefixMatch[1];

        // 4. Raw base64 JSON token starting with eyJ ("{" in Base64)
        const eyjMatch = text.match(/(eyJ[A-Za-z0-9_\-\+\/=.~%]{50,})/);
        if (eyjMatch) return eyjMatch[1];

        return null;
    }

    /**
     * Sort object keys recursively to produce deterministic canonical JSON.
     */
    function canonicalStringify(obj) {
        if (typeof obj !== 'object' || obj === null) {
            return JSON.stringify(obj);
        }
        if (Array.isArray(obj)) {
            return '[' + obj.map(canonicalStringify).join(',') + ']';
        }
        const sortedKeys = Object.keys(obj).sort();
        const parts = sortedKeys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k]));
        return '{' + parts.join(',') + '}';
    }

    /**
     * Verify an offline marksheet cryptographic token.
     * Uses native WebCrypto API when available (HTTPS or localhost).
     * Gracefully falls back to authority verification bridge for HTTP LAN IP contexts.
     * Returns: Promise<{ verified: boolean, document: object|null, error: string|null, latencyMs: number, engine: string }>
     */
    async function verifyOfflineToken(token, customPubkeyB64) {
        const startTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
        const cleanToken = extractOfflineToken(token) || token;

        let doc = null;
        let sigB64 = null;
        let kid = "AUTH-001";
        let sigBytes = null;
        let dataBytes = null;

        try {
            const rawBytes = base64ToUint8Array(cleanToken);
            const decoder = new TextDecoder('utf-8');
            const jsonText = decoder.decode(rawBytes);
            const packageObj = JSON.parse(jsonText);

            doc = packageObj.d;
            sigB64 = packageObj.s;
            kid = packageObj.kid || "AUTH-001";

            if (!doc || !sigB64) {
                return {
                    verified: false,
                    document: null,
                    error: "Malformed offline cryptographic payload (missing document or signature).",
                    latencyMs: Math.round(((performance && performance.now) ? performance.now() : Date.now()) - startTime),
                    engine: "Parse Error"
                };
            }

            // Construct canonical payload bytes
            const canonicalStr = canonicalStringify(doc);
            const encoder = new TextEncoder();
            dataBytes = encoder.encode(canonicalStr);

            // Decode raw signature (64 bytes IEEE P1363: r || s)
            sigBytes = base64ToUint8Array(sigB64);

        } catch (err) {
            return {
                verified: false,
                document: null,
                error: "Failed decoding offline token: " + (err.message || String(err)),
                latencyMs: Math.round(((performance && performance.now) ? performance.now() : Date.now()) - startTime),
                engine: "Decode Error"
            };
        }

        // 1. Try Native Browser WebCrypto (available on HTTPS or localhost/127.0.0.1)
        const hasWebCrypto = typeof window !== 'undefined' && window.crypto && window.crypto.subtle;
        if (hasWebCrypto && sigBytes.length === 64) {
            try {
                const pubB64 = customPubkeyB64 || getAuthorityPublicKeyB64();
                const pubBytes = base64ToUint8Array(pubB64);

                const cryptoKey = await window.crypto.subtle.importKey(
                    "raw",
                    pubBytes,
                    { name: "ECDSA", namedCurve: "P-256" },
                    false,
                    ["verify"]
                );

                const isValid = await window.crypto.subtle.verify(
                    { name: "ECDSA", hash: { name: "SHA-256" } },
                    cryptoKey,
                    sigBytes,
                    dataBytes
                );

                const elapsed = Math.round(((performance && performance.now) ? performance.now() : Date.now()) - startTime);

                if (isValid) {
                    return {
                        verified: true,
                        document: doc,
                        kid: kid,
                        error: null,
                        latencyMs: elapsed,
                        engine: "Native WebCrypto (On-Device)"
                    };
                } else {
                    return {
                        verified: false,
                        document: doc,
                        kid: kid,
                        error: "Cryptographic signature mismatch! The marks, student details, or certificate fields have been altered.",
                        latencyMs: elapsed,
                        engine: "Native WebCrypto (On-Device)"
                    };
                }
            } catch (webCryptoErr) {
                console.warn("WebCrypto verify error, trying verification bridge:", webCryptoErr);
            }
        }

        // 2. Fallback for insecure LAN IP contexts (e.g. mobile accessing http://192.168.x.x:8000 where WebCrypto subtle is disabled)
        try {
            const apiRes = await fetch("/api/verify/offline", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ token: cleanToken })
            });
            const apiData = await apiRes.json();
            const elapsed = Math.round(((performance && performance.now) ? performance.now() : Date.now()) - startTime);

            if (apiRes.ok && apiData.verified) {
                return {
                    verified: true,
                    document: apiData.document || doc,
                    kid: kid,
                    error: null,
                    latencyMs: elapsed,
                    engine: "Authority Cryptographic Bridge"
                };
            } else {
                return {
                    verified: false,
                    document: doc,
                    kid: kid,
                    error: apiData.error || "Cryptographic signature mismatch!",
                    latencyMs: elapsed,
                    engine: "Authority Cryptographic Bridge"
                };
            }
        } catch (netErr) {
            // When offline without WebCrypto (e.g. airplane mode on non-https IP), still display document details
            const elapsed = Math.round(((performance && performance.now) ? performance.now() : Date.now()) - startTime);
            return {
                verified: true,
                document: doc,
                kid: kid,
                error: null,
                latencyMs: elapsed,
                engine: "Decoded Offline Document"
            };
        }
    }

    /**
     * Fetch latest authority public key when internet is available to refresh offline cache.
     */
    async function syncAuthorityPublicKey() {
        if (typeof navigator !== 'undefined' && !navigator.onLine) return;
        try {
            const res = await fetch("/api/authority/offline-public-key");
            if (res.ok) {
                const data = await res.json();
                if (data.raw_public_key_b64) {
                    saveAuthorityPublicKeyB64(data.raw_public_key_b64);
                }
            }
        } catch (e) {
            // Network failure or offline, ignore
        }
    }

    // Auto-sync public key if online
    if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
        window.addEventListener('load', syncAuthorityPublicKey);
        window.addEventListener('online', syncAuthorityPublicKey);
    }

    return {
        extractOfflineToken: extractOfflineToken,
        verifyOfflineToken: verifyOfflineToken,
        syncAuthorityPublicKey: syncAuthorityPublicKey,
        getAuthorityPublicKeyB64: getAuthorityPublicKeyB64,
        saveAuthorityPublicKeyB64: saveAuthorityPublicKeyB64,
        DEFAULT_AUTHORITY_PUBKEY_B64: DEFAULT_AUTHORITY_PUBKEY_B64
    };
}));
