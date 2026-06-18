🛡️ Cipher-Forge: Advanced Security Suite

License Python Docker

Cipher-Forge is an enterprise-grade, open-source, dual-purpose security suite
designed for Android developers and privacy-conscious users. It features an
advanced Java Keystore Generator alongside a mathematically armored,
high-fidelity 5-Layer Cascade File Vault with Shamir key sharing and
hardware-profile binding.

👨‍💻 Author & Copyright

Created by: [SkyData]
Copyright: © 2026 [SkyData]. All rights reserved.
Attribution Requirement: You are free to use, modify, and distribute this
software, but you must explicitly credit the original author ([SkyData]) and
include the original license in any copies or forks.

✨ Features

1. 🔑 Professional Keystore Generator

Generate industry-standard cryptographic keys for signing Android APKs and App
Bundles (AAB).

  - Supported Formats: PKCS12 (Standard), JKS (Legacy), JCEKS.
  - Bouncy Castle Integration: Native support for generating highly specialized
    BKS, BCFKS, and UBER container formats.
  - Asymmetric Algorithms: RSA, EC (Elliptic Curve), DSA.
  - Fingerprint Extraction: Automatically executes keytool routines to provide
    SHA-1 and SHA-256 fingerprints in a clean text manifest.

2. 🛡️ Fortress-Grade Cascade File Vault

An agnostic binary protection vault designed to process files entirely in
volatile memory (zero disk footprint), hardened with standard-breaking
post-quantum cryptographic cascades.

🔒 Multi-Stage Key Stretching Pipeline

To systematically disable brute-force and GPU/ASIC dictionary clustering
attacks, passphrases pass through a memory-hard serial stretching process before
key derivation:
\text{Password} \xrightarrow{\text{Scrypt}} \text{Intermediate Key}_1 \xrightarrow{\text{PBKDF2-HMAC-SHA3-512 (10,000 Rounds)}} \text{Intermediate Key}_2 \xrightarrow{\text{Argon2id}} \text{Master Cryptographic Seed}

🌀 5-Layer Symmetric Cascade Architecture

Symmetric encryption sequentially mutates payloads through five mathematically
distinct, isolated, and cryptographically independent boundaries using keys
derived via HKDF-SHA3-512:

1.  Salsa20: Initial stream encryption layer.
2.  AES-256-CBC: Standard-compliant block-chaining encapsulation.
3.  Camellia-256-CFB: ISO/IEC certified, OpenSSL-backed Japanese national
    standard block cipher.
4.  AES-256-GCM-SIV: Nonce misuse-resistant authenticated encryption (AEAD)
    ensuring ciphertext uniqueness.
5.  XChaCha20-Poly1305: Highly robust AEAD envelope using a massive 192-bit
    nonce space.

Plaintext Payload ➔ Salsa20 ➔ AES-CBC ➔ Camellia-CFB ➔ AES-GCM-SIV ➔ XChaCha20-Poly1305 ➔ Ciphertext + HMAC-SHA3-512

🛡️ Advanced Security Configurations

  - Encrypt-then-MAC (HMAC-SHA3-512): The 256-byte header and encrypted payload
    are completely signed with an HMAC-SHA3-512 validation tag, preventing
    padding oracle or bit-flipping tampering [1].
  - Shamir's Secret Sharing Scheme (SSSS): Option to split the master
    cryptographic seed into N unique key portions (e.g., 2-of-3 split).
    Decryption is impossible unless the threshold number of keys are recombined.
  - Device Binding (Browser Fingerprinting): Integrates client-side hardware
    profiling. The file payload can optionally be locked to the user's specific
    browser/hardware, rendering the ciphertext useless on any other machine.
  - Random Obfuscated Padding: Payload lengths are obscured using a randomized
    block padding scheme to hide the true file size from statistical
    traffic-analysis attacks.
  - Format-Agnostic Processing: Perfectly protects videos (MP4, MKV), raw
    databases (SQL, SQLite), compressed archives (ZIP, 7z), documents (PDF,
    DOCX), and images (EXIF metadata completely zeroed out).
  - Extended File Limits: Supports universal processing for single-file uploads
    of up to 100MB [2].

3. 🖥️ Interactive Cyberpunk Interface

  - Zero-Glitch LTR Layout: Polished, responsive dark-mode interface built on
    native Bootstrap 5 grid alignment.
  - Active Hot-Upload Zone: Glowing drag-and-drop file interface providing
    real-time visual drop-state changes.
  - Typing Hacker Console Emulator: Triggers immersive green neon console
    terminal logs mapping out pipeline execution steps in real-time, displaying
    details like salt generations, KDF operations, and cascade boundary
    computations [1, 2].
  - Rate-Limiting Firewall: Automatically triggers a 30-minute cooling lockout
    penalty upon 5 failed key verification attempts.

🚀 How to Run (Docker & Deployment)

This tool is optimized for fast, containerized deployments (perfect for Hugging
Face Spaces or private Docker instances).

# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/Cipher-Forge.git
cd Cipher-Forge

# 2. Build the Docker image
docker build -t cipher-forge .

# 3. Run the container
docker run -p 7860:7860 cipher-forge

After launching, navigate to http://localhost:7860 in your browser.

📦 Dependencies & Packages

  - Framework: Flask & Werkzeug (Web Routing Engine)
  - Symmetric Cryptography Engine: PyCryptodome (Salsa20, AES-CBC, AEAD, Shamir)
  - Asymmetric & Camellia Backend: Pyca/Cryptography (HKDF, PBKDF2, Camellia
    CFB, default_backend)
  - Key Stretching Core: Argon2-cffi (Argon2id implementation)
  - Production Server: Gunicorn (Multi-threaded process manager)
  - Keystore Library: Java Runtime Environment (default-jdk) & Bouncy Castle
    Providers

📄 License

This project is licensed under the MIT License - see the LICENSE file for
details. Any distribution or fork must maintain explicit attribution to
[SkyData] as defined in the copyright clause above.
