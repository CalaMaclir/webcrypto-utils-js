// ============================================================
// kx.js
// ============================================================
import { CRYPTO_CONST, Utils } from './utils.js';
import { CryptoHash } from './hash.js';

let mlkem = null;
const HYBRID_ALGO = "Hybrid-MLKEM-768";

// ★追加: 必要なタイミングで確実にML-KEMをロードする関数
async function ensureMLKEM() {
    if (mlkem) return; // 既にロード済みの場合はスキップ
    try {
        // ----------------------------------------------------
        // 【重要】元のプロジェクトでお使いの `mlkem.js` を
        // srcフォルダ内にコピーして配置してください。
        // （もし特定のCDNを使用していた場合はそのURLに書き換えます）
        // ----------------------------------------------------
        const modulePath = './mlkem.js';
        const m = await import(modulePath);
        mlkem = m.default || m;
    } catch (e) {
        console.error("ML-KEM load error:", e);
        throw new Error("ML-KEMモジュールが見つかりません。src/フォルダ内に mlkem.js が配置されているか確認してください。");
    }
}

export const CryptoKX = {
    async detectCapabilities() {
        const algos = [];
        const tests = [
            { label: "X25519", gen: { name: "X25519" }, importAlgo: { name: "X25519" }, bits: 256 },
            { label: "P-521", gen: { name: "ECDH", namedCurve: "P-521" }, importAlgo: { name: "ECDH", namedCurve: "P-521" }, bits: 528 },
            { label: "P-256", gen: { name: "ECDH", namedCurve: "P-256" }, importAlgo: { name: "ECDH", namedCurve: "P-256" }, bits: 256 }
        ];

        for (const t of tests) {
            try {
                const kp = await crypto.subtle.generateKey(t.gen, true, ["deriveBits"]);
                const rawPub = await crypto.subtle.exportKey("raw", kp.publicKey);
                const pub = await crypto.subtle.importKey("raw", rawPub, t.importAlgo, true, []);
                await crypto.subtle.deriveBits({ name: t.gen.name, public: pub }, kp.privateKey, t.bits);
                algos.push(t.label);
            } catch (e) { }
        }

        if (algos.includes("X25519")) {
            try {
                await ensureMLKEM();
                if (mlkem && mlkem.generateKey) {
                    algos.push(HYBRID_ALGO);
                }
            } catch (e) {
                console.warn("ML-KEM skipped:", e.message);
            }
        }
        return algos;
    },

    // src/kx.js 内の genECDH 関数を以下の内容に差し替えます
    async genECDH(algoName, isOfferer) {
        if (algoName === HYBRID_ALGO) {
            await ensureMLKEM(); // ★ 鍵生成前にロードを保証
            const x25519Kp = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
            let mlkemKp = null;

            if (isOfferer) {
                mlkemKp = await mlkem.generateKey(
                    { name: "ML-KEM-768" },
                    true,
                    ["encapsulateBits", "decapsulateBits"]
                );
            }

            // ★修正: WebCrypto標準の { publicKey, privateKey } 形式に合わせるためのラッパー
            const ret = {
                type: "hybrid",
                isOfferer,
                x25519: x25519Kp,
                mlkem: mlkemKp,
                mlkemCT: null
            };

            // ここでラップして返すことで、.privateKey でアクセス可能になります
            return {
                publicKey: { _ref: ret },
                privateKey: { _ref: ret }
            };
        }

        // 既存ECDH
        if (algoName === "X25519") {
            return crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
        } else if (algoName === "P-521") {
            return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveBits"]);
        } else {
            return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
        }
    },

    // src/kx.js 内の exportPubRaw 関数を以下の内容に差し替えます
    async exportPubRaw(keyPairOrKey) {
        // 1. 引数が「鍵ペア全体」か「公開鍵のみ」かを判定して、公開鍵オブジェクトを取得
        const pubKeyObj = keyPairOrKey.publicKey || keyPairOrKey;

        // 2. ハイブリッド暗号用のラッパー（_ref）があれば中身を取り出す
        const kp = pubKeyObj._ref || pubKeyObj;

        if (kp.type === "hybrid") {
            await ensureMLKEM(); // ロードを保証
            // X25519の実際の公開鍵（CryptoKey）をエクスポート
            const x25519Raw = await crypto.subtle.exportKey("raw", kp.x25519.publicKey);

            if (kp.isOfferer) {
                const mlkemPubBuf = await mlkem.exportKey("raw-public", kp.mlkem.publicKey);
                return Utils.u8cat(new Uint8Array(x25519Raw), new Uint8Array(mlkemPubBuf));
            } else {
                if (kp.mlkemCT) {
                    return Utils.u8cat(new Uint8Array(x25519Raw), kp.mlkemCT);
                } else {
                    return new Uint8Array(x25519Raw);
                }
            }
        }

        // 既存の標準WebCryptoキー（通常のX25519など）の場合
        const raw = await crypto.subtle.exportKey("raw", kp);
        return new Uint8Array(raw);
    },

    async importPeerPubRaw(rawU8, algoName) {
        if (algoName === HYBRID_ALGO) {
            if (rawU8.length < 32) throw new Error("Key too short");
            const x25519Raw = rawU8.slice(0, 32);
            const rest = rawU8.slice(32);

            const x25519Pub = await crypto.subtle.importKey("raw", x25519Raw, { name: "X25519" }, true, []);
            return {
                type: "hybrid",
                x25519: x25519Pub,
                rest: rest
            };
        }

        if (algoName === "X25519") {
            return crypto.subtle.importKey("raw", rawU8, { name: "X25519" }, true, []);
        } else if (algoName === "P-521") {
            return crypto.subtle.importKey("raw", rawU8, { name: "ECDH", namedCurve: "P-521" }, true, []);
        } else {
            return crypto.subtle.importKey("raw", rawU8, { name: "ECDH", namedCurve: "P-256" }, true, []);
        }
    },

    async deriveSessionKey(myPrivKeyObj, peerPubKeyObj, saltU8, algoName, infoStr = CRYPTO_CONST.INFO_CHAT) {
        if (algoName === HYBRID_ALGO) {
            await ensureMLKEM(); // ★ ロードを保証
            const myObj = myPrivKeyObj._ref || myPrivKeyObj;

            const ss_x25519_bits = await crypto.subtle.deriveBits(
                { name: "X25519", public: peerPubKeyObj.x25519 },
                myObj.x25519.privateKey,
                256
            );
            const ss_x25519 = new Uint8Array(ss_x25519_bits);
            let ss_kem = null;

            if (myObj.isOfferer) {
                const ct = peerPubKeyObj.rest;
                if (ct.length !== 1088) throw new Error("Invalid ML-KEM Ciphertext length");

                const ssBuf = await mlkem.decapsulateBits(
                    { name: "ML-KEM-768" },
                    myObj.mlkem.privateKey,
                    ct
                );
                ss_kem = new Uint8Array(ssBuf);
            } else {
                const peerPubRaw = peerPubKeyObj.rest;
                if (peerPubRaw.length !== 1184) throw new Error("Invalid ML-KEM Public Key length");

                const peerKemPub = await mlkem.importKey(
                    "raw-public",
                    peerPubRaw,
                    { name: "ML-KEM-768" },
                    true,
                    ["encapsulateBits"]
                );

                const res = await mlkem.encapsulateBits(
                    { name: "ML-KEM-768" },
                    peerKemPub
                );

                myObj.mlkemCT = new Uint8Array(res.ciphertext);
                ss_kem = new Uint8Array(res.sharedKey);
            }

            const combined = Utils.u8cat(ss_x25519, ss_kem);
            return CryptoHash.hkdf(combined, saltU8, infoStr, 32);
        }

        let bits;
        if (algoName === "X25519") {
            bits = await crypto.subtle.deriveBits({ name: "X25519", public: peerPubKeyObj }, myPrivKeyObj, 256);
        } else if (algoName === "P-521") {
            bits = await crypto.subtle.deriveBits({ name: "ECDH", public: peerPubKeyObj }, myPrivKeyObj, 528);
        } else {
            bits = await crypto.subtle.deriveBits({ name: "ECDH", public: peerPubKeyObj }, myPrivKeyObj, 256);
        }
        return CryptoHash.hkdf(new Uint8Array(bits), saltU8, infoStr, 32);
    }
};