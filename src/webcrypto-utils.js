// ============================================================
// webcrypto-utils.js
// High-level wrapper for simple E2EE and Hybrid PQC
// ============================================================

import { CryptoKX } from './kx.js';
import { CryptoCipher } from './cipher.js';
import { Utils } from './utils.js';

// --- バイナリプロトコル用ヘルパー関数 ---
const PROTOCOL_VER = 1;
const TYPE_MSG_TEXT = 1;

function writeU32LE(val) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, val >>> 0, true);
    return b;
}

function readU32LE(u8, off) {
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    return dv.getUint32(off, true) >>> 0;
}
// ----------------------------------------
/**
 * WebCryptoUtils
 * ブラウザ標準の暗号化を、直感的なAPIで利用するためのメインクラス
 */
export class WebCryptoUtils {
    
    /**
     * 1. 鍵ペアの生成 (X25519 または Hybrid ML-KEM)
     */
    static async generateKeys(type = 'X25519') {
        const isHybrid = type === 'Hybrid';
        // Hybridの場合は受信側(isOfferer=true)として生成
        return await CryptoKX.genECDH(isHybrid ? 'Hybrid-MLKEM-768' : 'X25519', true);
    }

    /**
     * 2. 公開鍵を送信可能な文字列(Base64URL)に変換
     * @param {Object} keyPair 
     * @returns {Promise<string>}
     */
    static async exportPublicKey(keyPair) {
        const raw = await CryptoKX.exportPubRaw(keyPair);
        return Utils.b64urlEncode(raw);
    }

    /**
     * 3. 文字列データを公開鍵で暗号化する (簡易E2EE)
     * 内部でエフェメラル鍵を生成し、共通鍵を導出してAESで暗号化します。
     * @param {string} text 暗号化したい文字列
     * @param {string} recipientPubB64 相手の公開鍵 (Base64URL)
     * @param {string} algoName 使用するアルゴリズム
     * @returns {Promise<Object>} { ciphertext, ephemeralPub, nonce, iv }
     */
    static async encrypt(text, recipientPubB64, algoName = 'X25519') {
        const dataU8 = Utils.encodeText(text);
        const peerPubRaw = Utils.b64urlDecode(recipientPubB64);
        const internalAlgo = algoName === 'Hybrid' ? 'Hybrid-MLKEM-768' : algoName;
        const peerPubKey = await CryptoKX.importPeerPubRaw(peerPubRaw, internalAlgo);

        // 送信用の一時的な鍵ペアを生成
        const ephemeralKeyPair = await CryptoKX.genECDH(internalAlgo, false);
        const nonce = crypto.getRandomValues(new Uint8Array(16));

        // 共通鍵(Kek)を導出
        const kekRaw = await CryptoKX.deriveSessionKey(ephemeralKeyPair.privateKey, peerPubKey, nonce, internalAlgo);
        const kek = await CryptoCipher.importAesKey(kekRaw);

        // AES-GCMで暗号化
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ctBuf = await CryptoCipher.encryptAes(kek, iv, new Uint8Array(0), dataU8);

        return {
            ciphertext: Utils.b64urlEncode(new Uint8Array(ctBuf)),
            ephemeralPub: Utils.b64urlEncode(await CryptoKX.exportPubRaw(ephemeralKeyPair)),
            nonce: Utils.b64urlEncode(nonce),
            iv: Utils.b64urlEncode(iv)
        };
    }

    /**
     * 4. 暗号化されたデータを自分の秘密鍵で復号する
     * @param {Object} encryptedPackage encrypt関数の戻り値
     * @param {Object} myKeyPair 自分の秘密鍵を含む鍵ペア
     * @param {string} algoName 
     * @returns {Promise<string>} 復号された文字列
     */
    static async decrypt(encryptedPackage, myKeyPair, algoName = 'X25519') {
        const { ciphertext, ephemeralPub, nonce, iv } = encryptedPackage;

        const ephemPubRaw = Utils.b64urlDecode(ephemeralPub);
        const internalAlgo = algoName === 'Hybrid' ? 'Hybrid-MLKEM-768' : algoName;
        
        const ephemPubKey = await CryptoKX.importPeerPubRaw(ephemPubRaw, internalAlgo);
        const nonceU8 = Utils.b64urlDecode(nonce);
        const ivU8 = Utils.b64urlDecode(iv);
        const ctU8 = Utils.b64urlDecode(ciphertext);

        // 相手の一時公開鍵と自分の秘密鍵から共通鍵を再構築
        const kekRaw = await CryptoKX.deriveSessionKey(myKeyPair.privateKey, ephemPubKey, nonceU8, internalAlgo);
        const kek = await CryptoCipher.importAesKey(kekRaw);

        // 復号
        const ptBuf = await CryptoCipher.decryptAes(kek, ivU8, new Uint8Array(0), ctU8);
        return Utils.decodeText(new Uint8Array(ptBuf));
    }

    /**
     * 5. 【追加】複数宛先への暗号化 (Multi-Recipient E2EE)
     */
    /**
     * 【追加】複数宛先への暗号化 (Multi-Recipient E2EE)
     * 1つのメッセージを1回だけ暗号化し、その復号キー(CEK)を宛先人数分暗号化します。
     * * @param {string} text 暗号化したい文字列
     * @param {string[]} recipientPubB64Array 相手の公開鍵(Base64URL)の配列
     * @param {string} algoName 使用するアルゴリズム ('Hybrid' または 'X25519')
     * @returns {Promise<Object>} 暗号化パッケージ
     */
    static async encryptForMultiple(text, recipientPubB64Array, algoName = 'X25519') {
        const dataU8 = Utils.encodeText(text);
        const internalAlgo = algoName === 'Hybrid' ? 'Hybrid-MLKEM-768' : algoName;

        // 1. ファイル/メッセージ暗号化用のマスターキー(CEK)とNonceを生成
        const fileKeyRaw = crypto.getRandomValues(new Uint8Array(32));
        const fileKeyObj = await CryptoCipher.importAesKey(fileKeyRaw);
        const fileNonce = crypto.getRandomValues(new Uint8Array(16));
        const payloadIv = crypto.getRandomValues(new Uint8Array(12));

        // 2. 各宛先ごとにCEKを暗号化(カプセル化)する
        const recipients = [];
        for (const peerPubB64 of recipientPubB64Array) {
            const peerPubKey = await CryptoKX.importPeerPubRaw(Utils.b64urlDecode(peerPubB64), internalAlgo);

            // 宛先ごとに一時的な鍵ペア(ephemeral)を生成
            const ephemeralKeyPair = await CryptoKX.genECDH(internalAlgo, false);

            // KEK(Key Encrypting Key)を導出 (ソルトとしてfileNonceを利用)
            const kekRaw = await CryptoKX.deriveSessionKey(ephemeralKeyPair.privateKey, peerPubKey, fileNonce, internalAlgo);
            const kekObj = await CryptoCipher.importAesKey(kekRaw);

            // KEKを使ってCEK(fileKeyRaw)を暗号化
            const wrapIv = crypto.getRandomValues(new Uint8Array(12));
            const wrappedFileKeyBuffer = await CryptoCipher.encryptAes(kekObj, wrapIv, new Uint8Array(0), fileKeyRaw);

            // 一時公開鍵をエクスポート
            const ephemeralPubRaw = await CryptoKX.exportPubRaw(ephemeralKeyPair);

            recipients.push({
                ephemeralPub: Utils.b64urlEncode(ephemeralPubRaw),
                wrapIv: Utils.b64urlEncode(wrapIv),
                wrappedCek: Utils.b64urlEncode(new Uint8Array(wrappedFileKeyBuffer))
            });
        }

        // 3. CEKを使ってデータ本体を暗号化
        const encryptedPayloadBuffer = await CryptoCipher.encryptAes(fileKeyObj, payloadIv, fileNonce, dataU8);

        return {
            ciphertext: Utils.b64urlEncode(new Uint8Array(encryptedPayloadBuffer)),
            fileNonce: Utils.b64urlEncode(fileNonce),
            payloadIv: Utils.b64urlEncode(payloadIv),
            recipients: recipients // 宛先ごとの鍵カプセルのリスト
        };
    }

    /**
     * 6. 【追加】複数宛先向けの暗号化パッケージから復号する
     * * @param {Object} encryptedPackage encryptForMultipleの戻り値
     * @param {Object} myKeyPair 自分の秘密鍵を含む鍵ペア
     * @param {string} algoName 使用するアルゴリズム ('Hybrid' または 'X25519')
     * @returns {Promise<string>} 復号された文字列
     */
    static async decryptFromMultiple(encryptedPackage, myKeyPair, algoName = 'X25519') {
        const { ciphertext, fileNonce, payloadIv, recipients } = encryptedPackage;
        const internalAlgo = algoName === 'Hybrid' ? 'Hybrid-MLKEM-768' : algoName;

        const fileNonceU8 = Utils.b64urlDecode(fileNonce);
        const payloadIvU8 = Utils.b64urlDecode(payloadIv);
        const encryptedPayloadU8 = Utils.b64urlDecode(ciphertext);

        let fileKeyObj = null;

        // パッケージに含まれるカプセル群の中から、自分の鍵で開けられるものを探す
        for (const entry of recipients) {
            try {
                const ephemeralPubRaw = Utils.b64urlDecode(entry.ephemeralPub);
                const wrapIv = Utils.b64urlDecode(entry.wrapIv);
                const wrappedCek = Utils.b64urlDecode(entry.wrappedCek);

                const ephemeralPubObj = await CryptoKX.importPeerPubRaw(ephemeralPubRaw, internalAlgo);

                // 鍵導出
                const kekRaw = await CryptoKX.deriveSessionKey(myKeyPair.privateKey, ephemeralPubObj, fileNonceU8, internalAlgo);
                const kekObj = await CryptoCipher.importAesKey(kekRaw);

                // CEKの復号
                const fileKeyBuffer = await CryptoCipher.decryptAes(kekObj, wrapIv, new Uint8Array(0), wrappedCek);
                fileKeyObj = await CryptoCipher.importAesKey(new Uint8Array(fileKeyBuffer));

                break; // 成功したらループを抜ける
            } catch (e) {
                // 自分の鍵ではないカプセルの場合は復号に失敗するので、無視して次へ進む
            }
        }

        if (!fileKeyObj) {
            throw new Error("このデバイスの鍵では復号できません。（カプセルが見つからないか無効です）");
        }

        // データ本体の復号
        const payloadBuffer = await CryptoCipher.decryptAes(fileKeyObj, payloadIvU8, fileNonceU8, encryptedPayloadU8);
        return Utils.decodeText(new Uint8Array(payloadBuffer));
    }

    // ============================================================
    // バイナリプロトコル (パッキング) 関連メソッド
    // ============================================================

    /**
     * 7. 【追加】JSONパッケージをバイナリフレーム(ArrayBuffer)にパッキングする
     * 構造: [Ver:1][Type:1][Seq:4][Nonce:16][IV:12][EphemPubLen:2][EphemPub: N bytes][CTLen:4][CT]
     */
    static pack(encryptedPackage, seq = 0) {
        const ephemPubU8 = Utils.b64urlDecode(encryptedPackage.ephemeralPub);
        const nonceU8 = Utils.b64urlDecode(encryptedPackage.nonce);
        const ivU8 = Utils.b64urlDecode(encryptedPackage.iv);
        const ctU8 = Utils.b64urlDecode(encryptedPackage.ciphertext);

        const headerLen = 1 + 1 + 4 + 16 + 12 + 2 + ephemPubU8.length + 4;
        const out = new Uint8Array(headerLen + ctU8.length);
        let off = 0;

        out[off++] = PROTOCOL_VER;
        out[off++] = TYPE_MSG_TEXT;
        out.set(writeU32LE(seq), off); off += 4;
        out.set(nonceU8, off); off += 16;
        out.set(ivU8, off); off += 12;
        new DataView(out.buffer).setUint16(off, ephemPubU8.length, true); off += 2;
        out.set(ephemPubU8, off); off += ephemPubU8.length;
        out.set(writeU32LE(ctU8.length), off); off += 4;
        out.set(ctU8, off);

        return out.buffer; // バイナリとして返却
    }

    /**
     * 8. 【追加】バイナリフレームをJSONパッケージにアンパックする
     */
    static unpack(arrayBuffer) {
        const u8 = new Uint8Array(arrayBuffer);
        const dv = new DataView(arrayBuffer);
        let off = 0;

        if (u8.length < 40) throw new Error("Frame too short");

        const ver = u8[off++];
        const type = u8[off++];

        if (ver !== PROTOCOL_VER) throw new Error(`Unsupported Protocol Version: ${ver}`);
        if (type !== TYPE_MSG_TEXT) throw new Error(`Unsupported Message Type: ${type}`);

        const seq = readU32LE(u8, off); off += 4;
        const nonceU8 = u8.slice(off, off + 16); off += 16;
        const ivU8 = u8.slice(off, off + 12); off += 12;

        const ephemLen = dv.getUint16(off, true); off += 2;
        const ephemPubU8 = u8.slice(off, off + ephemLen); off += ephemLen;

        const ctLen = readU32LE(u8, off); off += 4;
        const ctU8 = u8.slice(off, off + ctLen);

        return {
            seq,
            encryptedPackage: {
                ephemeralPub: Utils.b64urlEncode(ephemPubU8),
                nonce: Utils.b64urlEncode(nonceU8),
                iv: Utils.b64urlEncode(ivU8),
                ciphertext: Utils.b64urlEncode(ctU8)
            }
        };
    }

    /**
     * 9. 【追加】暗号化とバイナリパッキングを一度に行う高レイヤーメソッド
     */
    static async encryptAndPack(text, recipientPubB64, seq = 0, algoName = 'X25519') {
        const pkg = await this.encrypt(text, recipientPubB64, algoName);
        return this.pack(pkg, seq);
    }

    /**
     * 10. 【追加】バイナリアンパックと復号を一度に行う高レイヤーメソッド
     */
    static async unpackAndDecrypt(arrayBuffer, myKeyPair, algoName = 'X25519') {
        const unpacked = this.unpack(arrayBuffer);
        const text = await this.decrypt(unpacked.encryptedPackage, myKeyPair, algoName);
        return { seq: unpacked.seq, text };
    }
}

