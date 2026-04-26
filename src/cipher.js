// ============================================================
// cipher.js
// AES-GCM Encryption and Decryption logic.
// ============================================================

import { CRYPTO_CONST } from './utils.js';

export const CryptoCipher = {
    async importAesKey(rawKey) {
        return crypto.subtle.importKey("raw", rawKey, CRYPTO_CONST.ALGO_AES, false, ["encrypt", "decrypt"]);
    },

    async encryptAes(key, iv, aad, data) {
        return crypto.subtle.encrypt(
            { name: CRYPTO_CONST.ALGO_AES, iv, additionalData: (aad || new Uint8Array()), tagLength: 128 },
            key,
            data
        );
    },

    async decryptAes(key, iv, aad, data) {
        return crypto.subtle.decrypt(
            { name: CRYPTO_CONST.ALGO_AES, iv, additionalData: (aad || new Uint8Array()), tagLength: 128 },
            key,
            data
        );
    }
};
