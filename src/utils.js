// ============================================================
// utils.js
// Base utilities and constants for the WebCrypto wrapper.
// ============================================================

export const CRYPTO_CONST = Object.freeze({
    ALGO_AES: "AES-GCM",
    ALGO_HASH_512: "SHA-512",
    ALGO_HMAC: "HMAC",
    ALGO_PBKDF2: "PBKDF2",
    PBKDF_ITER: 100000,
    PBKDF_BITS: 256,
    SALT_STRING: "webcrypto-utils-salt",
    INFO_CHAT: "Chat",
    INFO_FILE: "File",
    INFO_AUTH: "Auth"
});

const te = new TextEncoder();
const td = new TextDecoder();

export const Utils = {
    u8cat(...parts) {
        const total = parts.reduce((a, p) => a + p.length, 0);
        const out = new Uint8Array(total);
        let off = 0;
        for (const p of parts) { out.set(p, off); off += p.length; }
        return out;
    },

    b64urlEncode(u8) {
        let s = "";
        for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
        return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    },

    b64urlDecode(s) {
        const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
        const bin = atob(b64);
        const u8 = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
        return u8;
    },

    encodeText(text) { return te.encode(text); },
    decodeText(u8) { return td.decode(u8); }
};
