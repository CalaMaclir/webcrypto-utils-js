// ============================================================
// hash.js
// Hash, HMAC, and KDF functions including HKDF polyfill.
// ============================================================

import { CRYPTO_CONST, Utils } from './utils.js';

export const CryptoHash = {
    async sha512Bytes(data) {
        const buf = data instanceof ArrayBuffer ? data : data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
        const hash = await crypto.subtle.digest(CRYPTO_CONST.ALGO_HASH_512, buf);
        return new Uint8Array(hash);
    },

    // HKDF (Native or Polyfill)
    async hkdf(ikmU8, saltU8, infoStr, length) {
        try {
            // 1. まずネイティブ実装を試みる
            const key = await crypto.subtle.importKey("raw", ikmU8, "HKDF", false, ["deriveBits"]);
            const bits = await crypto.subtle.deriveBits(
                { name: "HKDF", hash: CRYPTO_CONST.ALGO_HASH_512, salt: saltU8, info: Utils.encodeText(infoStr) },
                key,
                length * 8
            );
            return new Uint8Array(bits);
        } catch (e) {
            // 2. 失敗した場合（HKDF未対応ブラウザ）、HMAC-SHA512で手動計算する (RFC 5869)
            return this.hkdfPolyfill(ikmU8, saltU8, infoStr, length);
        }
    },

    // HKDF-SHA-512 Polyfill
    async hkdfPolyfill(ikmU8, saltU8, infoStr, length) {
        const saltKey = await crypto.subtle.importKey(
            "raw",
            saltU8.length > 0 ? saltU8 : new Uint8Array(64), // 空ならゼロパディング
            { name: "HMAC", hash: "SHA-512" },
            false,
            ["sign"]
        );
        const prkBuf = await crypto.subtle.sign("HMAC", saltKey, ikmU8);
        const prkU8 = new Uint8Array(prkBuf);

        const infoU8 = Utils.encodeText(infoStr);
        const counter = new Uint8Array([1]); // T(1)
        const input = Utils.u8cat(infoU8, counter);

        const prkKey = await crypto.subtle.importKey(
            "raw",
            prkU8,
            { name: "HMAC", hash: "SHA-512" },
            false,
            ["sign"]
        );
        const t1Buf = await crypto.subtle.sign("HMAC", prkKey, input);

        return new Uint8Array(t1Buf).slice(0, length);
    }
};
