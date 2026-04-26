# webcrypto-utils-js（仮公開、実装中）

**A lightweight, dependency-free wrapper for the WebCrypto API, bringing simplified E2EE and Hybrid PQC (ML-KEM & X25519) to the browser.**

`webcrypto-utils-js` は、ブラウザ標準の WebCrypto API をより直感的、かつセキュアに扱うための JavaScript ライブラリです。複雑な鍵導出や暗号化プロセスをラップし、エンドツーエンド暗号化（E2EE）を手軽に実装できるように設計されています。

## 🚀 Features

- **Zero Dependencies**: 外部ライブラリに依存せず、ブラウザのネイティブ API (WebCrypto) のみを使用するため、軽量で安全です。
- **Hybrid PQC Ready**: 次世代の耐量子計算機暗号 `ML-KEM-768` と、信頼性の高い `X25519` を組み合わせたハイブリッド鍵交換をサポート。
- **Simplified API**: 鍵生成、公開鍵のエクスポート、暗号化・復号といった E2EE に必要なフローを数行で記述可能。
- **Modern Security**: エフェメラル鍵（使い捨て鍵）の生成と HKDF による鍵導出を内部で自動化し、Forward Secrecy を考慮した設計。

## 📦 File Structure

本リポジトリのコアとなるモジュール構成です。

- `utils.js`: Base64URL エンコードやバイト列結合などの低レイヤーユーティリティ。
- `hash.js`: SHA-512、HKDF（Polyfill付）、PBKDF2 ハッシュ関連。
- `kx.js`: X25519/P-521 および ML-KEM のハイブリッド鍵交換ロジック。
- `cipher.js`: AES-GCM (256-bit) による高速な共通鍵暗号。
- **`webcrypto-utils.js`**: 上記を統合し、最も簡単に使えるインターフェースを提供。

## 🛠 Quick Start

```javascript
import { WebCryptoUtils } from './webcrypto-utils.js';

async function example() {
    // 1. 自分の鍵ペアを生成 (Hybrid PQC 推奨)
    const myKeys = await WebCryptoUtils.generateKeys('Hybrid');

    // 2. 自分の公開鍵をエクスポート
    const myPub = await WebCryptoUtils.exportPublicKey(myKeys);
    console.log("Your Public Key:", myPub);

    // 3. 相手の公開鍵(recipientPub)を使って暗号化
    // 内部でメッセージ専用のエフェメラル鍵が生成されます
    const secret = "This is a highly confidential message.";
    const encrypted = await WebCryptoUtils.encrypt(secret, recipientPub, 'Hybrid');

    // 4. 自分の秘密鍵を使って復号
    const decrypted = await WebCryptoUtils.decrypt(encrypted, myKeys, 'Hybrid');
    console.log("Decrypted:", decrypted);
}
```

## 🔐 Core Concepts

### Hybrid Post-Quantum Cryptography (PQC)
このライブラリは NIST の標準化に合わせて `ML-KEM-768` を採用しています。しかし、新しいアルゴリズムには未知の脆弱性がある可能性も否定できないため、実績のある `X25519` と組み合わせて鍵を導出（Hybrid 方式）しています。これにより、どちらか一方のアルゴリズムが破られても安全性が保たれます。

### Verifiable Security
管理者がデータを復号できない E2EE システムを構築する際、ブラウザ標準の暗号化 API を用いることで「実装の透明性」を担保できます。

## 📄 License
MIT License
