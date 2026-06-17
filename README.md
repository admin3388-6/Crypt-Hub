# 🛡️ Cipher-Forge: Advanced Security Suite

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10-yellow.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)

**Cipher-Forge** is a professional, open-source, dual-purpose security suite designed for Android developers and privacy enthusiasts. It features a robust Keystore Generator and a Quantum-Resistant File Vault.

## 👨‍💻 Author & Copyright
**Created by:** [SkyData]  
**Copyright:** © 2026 [SkyData]. All rights reserved.  
**Attribution Requirement:** You are free to use, modify, and distribute this software, but **you must explicitly credit the original author ([SkyData])** and include the original license in any copies or forks.

---

## ✨ Features

### 1. 🔑 Professional Keystore Generator
Generate industry-standard cryptographic keys for Android APK/AAB signing.
- **Supported Formats:** PKCS12, JKS, JCEKS.
- **Bouncy Castle Support:** Generate highly specialized BKS, BCFKS, and UBER formats.
- **Algorithms:** RSA, EC (Elliptic Curve), DSA.
- **Fingerprint Extraction:** Automatically extracts and provides unique SHA-1 and SHA-256 fingerprints.

### 2. 🛡️ Quantum-Resistant File Vault
A military-grade file encryption tool that processes files entirely in RAM (Zero-Trace).
- **Key Derivation:** Uses **Argon2id** (GPU/ASIC resistant) to derive keys from your password.
- **Cascade Encryption:** 
  - Layer 1: **AES-256-GCM**
  - Layer 2: **ChaCha20-Poly1305**
- **Tamper-Proof:** Any modification to the encrypted `.locked` file will result in immediate decryption failure (MAC validation).
- **Max File Size:** 50MB per request.

---

## 🚀 How to Run (Docker)

This tool is designed to run seamlessly on Docker (perfect for Hugging Face Spaces).

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/Cipher-Forge.git
cd Cipher-Forge

# 2. Build the Docker image
docker build -t cipher-forge .

# 3. Run the container
docker run -p 7860:7860 cipher-forge
