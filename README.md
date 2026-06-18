# 🛡️ Cipher-Forge: Advanced Security Suite

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10-yellow.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)

**Cipher-Forge** is an enterprise-grade, open-source, dual-purpose security suite designed for Android developers and privacy-conscious users. It features an advanced Java Keystore Generator alongside a mathematically armored, high-fidelity **5-Layer Cascade File Vault** with Shamir key sharing and hardware-profile binding.

## 👨‍💻 Author & Copyright
**Created by:** [SkyData]  
**Copyright:** © 2026 [SkyData]. All rights reserved.  
**Attribution Requirement:** You are free to use, modify, and distribute this software, but **you must explicitly credit the original author ([SkyData])** and include the original license in any copies or forks.

---

## ✨ Features

### 1. 🔑 Professional Keystore Generator
Generate industry-standard cryptographic keys for signing Android APKs and App Bundles (AAB) [1].
- **Supported Formats:** PKCS12 (Standard), JKS (Legacy), JCEKS.
- **Bouncy Castle Integration:** Native support for generating highly specialized BKS, BCFKS, and UBER container formats.
- **Asymmetric Algorithms:** RSA, EC (Elliptic Curve), DSA.
- **Fingerprint Extraction:** Automatically executes `keytool` routines to provide SHA-1 and SHA-256 fingerprints in a clean text manifest.

---

### 2. 🛡️ Fortress-Grade Cascade File Vault
An agnostic binary protection vault designed to process files entirely in volatile memory (zero disk footprint), hardened with standard-breaking post-quantum cryptographic cascades.

#### 🔒 Multi-Stage Key Stretching Pipeline
To systematically disable brute-force and GPU/ASIC dictionary clustering attacks, passphrases pass through a memory-hard serial stretching process before key derivation:
$$\text{Password} \xrightarrow{\text{Scrypt}} \text{Intermediate Key}_1 \xrightarrow{\text{PBKDF2-HMAC-SHA3-512 (10,000 Rounds)}} \text{Intermediate Key}_2 \xrightarrow{\text{Argon2id}} \text{Master Cryptographic Seed}$$

#### 🌀 5-Layer Symmetric Cascade Architecture
Symmetric encryption sequentially mutates payloads through five mathematically distinct, isolated, and cryptographically independent boundaries using keys derived via HKDF-SHA3-512:
1. **Salsa20:** Initial stream encryption layer.
2. **AES-256-CBC:** Standard-compliant block-chaining encapsulation.
3. **Camellia-256-CFB:** ISO/IEC certified, OpenSSL-backed Japanese national standard block cipher.
4. **AES-256-GCM-SIV:** Nonce misuse-resistant authenticated encryption (AEAD) ensuring ciphertext uniqueness.
5. **XChaCha20-Poly1305:** Highly robust AEAD envelope using a massive 192-bit nonce space.
