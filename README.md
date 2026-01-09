# Hybrid Cryptography System

<div align="center">

![Hybrid Cryptography System](docs/images/HYBRID CRYPTOGRAPHY SYSTEM.png)

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Security](https://img.shields.io/badge/Security-AES--256--GCM%20%2B%20RSA--4096-red?style=flat-square)](TECHNICAL_OVERVIEW.md)
[![Architecture](https://img.shields.io/badge/Architecture-Hybrid%20Cryptography-orange?style=flat-square)](TECHNICAL_OVERVIEW.md)

**A Production-Grade Multi-User Authenticated Encryption Suite**

</div>

---

## Overview

The Hybrid Cryptography System is a battle-hardened encryption framework that combines symmetric and asymmetric cryptography with digital signatures to deliver authenticated encryption with non-repudiation guarantees. The system is designed for secure multi-user workflows where identity verification, data confidentiality, and integrity assurance are non-negotiable.

### Cryptographic Primitives

The implementation employs NIST-approved algorithms with proven security properties:

| Component | Algorithm | Key Size | Mode/Padding | Purpose |
|-----------|-----------|----------|-------------|---------|
| **Confidentiality** | AES | 256 bits | GCM (Galois/Counter) | Authenticated symmetric encryption |
| **Session Key Exchange** | RSA | 4096 bits | OAEP with SHA-256 | Secure asymmetric key wrapping |
| **Digital Signature** | RSA | 4096 bits | PSS with SHA-256 | Non-repudiation & authenticity |
| **Key Derivation** | PBKDF2 | - | HMAC-SHA256 (100k iterations) | Passphrase-based key generation |

### Architecture Highlights

- **DB-Backed Identity Management:** SQLite-backed user registry with PBKDF2-derived passphrase hashes (salted, iterated).
- **Per-User Key Storage:** Encrypted private keys stored locally under `./keys/<username>/`, with paths indexed in the database.
- **Embedded Sender Identity:** Sender's public key is Base64-encoded and included in encrypted packages, enabling automatic verification without external key distribution.
- **Tampering Detection:** Strict verification of GCM authentication tags and RSA-PSS signatures; any corruption triggers a `ValueError` exception with "TAMPERING DETECTED" alert.
- **Universal Format Support:** Binary-agnostic—all file types treated as opaque byte streams.

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Usage](#usage)
   - [GUI Workflow](#gui-workflow)
   - [Python API](#python-api)
4. [Universal Format Support](#universal-format-support)
5. [Identity & Authentication Flow](#identity--authentication-flow)
6. [Encryption Package Structure](#encryption-package-structure)
7. [API Reference](#api-reference)
8. [Security Properties](#security-properties)
9. [Project Structure](#project-structure)

<<<<<<< HEAD
---
=======
## Project Structure (short)

```
Hybrid-Cryptography-System/
├── crypto_engine/
│   ├── __init__.py
│   └── hybrid_crypto.py              # Core engine (Base64 encoding)
├── examples/
│   ├── demo.py                       # Main demonstration (production-ready)
│   ├── sample_message.txt            # Generated test message
│   ├── message_encrypted.json        # Generated encrypted package
│   └── message_decrypted.txt         # Generated decrypted output
├── keys/                             # Generated at runtime
│   ├── sender/
│   │   ├── private_key_encrypted.json
│   │   └── public_key.pem
│   └── receiver/
│       ├── private_key_encrypted.json
│       └── public_key.pem
├── scripts/
│   └── cleanup_docs_and_keys.ps1     # Repository cleanup utility
├── requirements.txt                  # Dependencies
├── README.md                         # This file
├── TECHNICAL_OVERVIEW.md             # Cryptographic specifications
├── QUICKSTART.md                     # Getting started guide
├── DELIVERABLES.md                   # Requirements checklist
├── LICENSE                           # MIT License
└── .gitignore                        # Git configuration
```
>>>>>>> 602359dc19bb9c4e42cf5bd1cbf4db5d63ad0cab

## Installation

### Requirements

- Python 3.7 or higher
- pip (Python package manager)
- PyCryptodome 3.18.0+ (pure Python cryptography library)

### Setup

```bash
git clone https://github.com/Layba-khan01/Hybrid-Cryptography-System.git
cd Hybrid-Cryptography-System
pip install -r requirements.txt
```

**Note:** PyCryptodome is used (not PyCrypto) to ensure side-channel attack mitigations and maintain a pure Python implementation without C dependencies.

---

## Quick Start

### 1. Graphical Interface (Recommended for Multi-User Scenarios)

```bash
python -m crypto_engine.gui_app
```

**Workflow:**
1. **Login / Register Tab:** Create a new user account (auto-generates RSA-4096 keypair under `./keys/<username>/`) or login with existing credentials.
2. **Encrypt & Share Tab:** Select plaintext file → Choose receiver from DB combobox → Provide passphrase to unlock sender's private key → Encrypt with AES-256-GCM + RSA-4096.
3. **Receive & Decrypt Tab:** Load encrypted JSON package → Receive & Decrypt tabs auto-enabled post-login → Select sender from combobox for public key lookup → Decrypt & verify signature.

### 2. Programmatic Integration (Python API)

```python
from crypto_engine import (
    generate_rsa_keypair,
    encrypt_file,
    decrypt_file,
    load_private_key,
    save_encrypted_file,
    load_encrypted_file
)

# Step 1: Generate keypairs for sender and receiver
sender_keys = generate_rsa_keypair("sender_passphrase", output_dir="./keys/alice")
receiver_keys = generate_rsa_keypair("receiver_passphrase", output_dir="./keys/bob")

# Step 2: Sender encrypts plaintext
encrypted_pkg = encrypt_file(
    plaintext="./documents/confidential.pdf",
    receiver_public_key_pem=receiver_keys['public_key_pem'].encode(),
    sender_private_key_pem=sender_keys['private_key_pem'].encode()
)
save_encrypted_file(encrypted_pkg, "./transmit/confidential.json")

# Step 3: Receiver decrypts and verifies
receiver_private_key = load_private_key(
    receiver_keys['private_key_file'],
    passphrase="receiver_passphrase"
)
encrypted_pkg = load_encrypted_file("./transmit/confidential.json")

try:
    plaintext = decrypt_file(
        encrypted_package=encrypted_pkg,
        receiver_private_key_pem=receiver_private_key,
        sender_public_key_pem=sender_keys['public_key_pem'].encode()
    )
    print(f"Decryption successful. Recovered {len(plaintext)} bytes.")
except ValueError as e:
    if "Signature verification failed" in str(e):
        print("TAMPERING DETECTED: Signature invalid—data integrity compromised.")
    elif "Authentication tag verification failed" in str(e):
        print("TAMPERING DETECTED: Ciphertext corrupted or modified.")
```

### 3. Demonstration

```bash
python examples/demo.py
```

Runs a full end-to-end encryption/decryption cycle with tampering detection test.

---

## Usage

### GUI Workflow

**Login / Register Tab**
- **Register:** Username → Passphrase → Confirm Passphrase → Auto-generates RSA-4096 keypair → Stores paths in SQLite DB.
- **Login:** Username → Passphrase → DB verification (PBKDF2-HMAC-SHA256 comparison) → Enables Encrypt & Decrypt tabs.

**Encrypt & Share Tab**
- **File Selection:** Browse for plaintext file (any type).
- **Receiver Selection:** Combobox populated from DB usernames.
- **Sender Private Key:** Auto-loaded from logged-in user state; passphrase prompt required on encryption (security best practice).
- **Output:** Saves Base64-encoded JSON package to user-specified path.

**Receive & Decrypt Tab**
- **Package Loading:** Browse for encrypted JSON file.
- **Receiver Credentials:** Uses logged-in user's private key and passphrase.
- **Sender Public Key:** Looks up by username in DB combobox or extracts from embedded `public_key_pem` field.
- **Verification & Decryption:** Full signature + authentication tag verification before plaintext release.
- **Tampering Alert:** If verification fails, displays "TAMPERING DETECTED" dialog.

### Python API

For programmatic workflows, import functions directly from `crypto_engine`:

```python
from crypto_engine import (
    derive_key_from_passphrase,
    generate_rsa_keypair,
    load_private_key,
    encrypt_file,
    decrypt_file,
    save_encrypted_file,
    load_encrypted_file,
    verify_package_integrity,
    get_file_metadata
)
```

---

## Identity & Authentication Flow

### User Registration

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User enters (username, passphrase, confirm passphrase)   │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ 2. hybrid_crypto.generate_rsa_keypair()                     │
│    - Derives PBKDF2-HMAC-SHA256 key from passphrase         │
│    - Generates RSA-4096 keypair                             │
│    - Encrypts private key with derived key                  │
│    - Saves private_key_encrypted.json + public_key.pem      │
│      to ./keys/<username>/                                  │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ 3. DBManager.register_user()                                │
│    - Derives PBKDF2-HMAC-SHA256 hash from passphrase        │
│    - Stores (username, hash, salt, key_paths) in SQLite     │
│    - Enables user to login on future GUI sessions           │
└─────────────────────────────────────────────────────────────┘
```

**Security Properties:**
- **Passphrase Hashing:** PBKDF2-HMAC-SHA256 with 100,000 iterations and random salt (per user)
- **Key Derivation:** Same PBKDF2 configuration derives both private key encryption key and DB hash salt
- **Private Key Protection:** Encrypted at rest in JSON file; decrypted only after passphrase verification

### User Login

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User enters (username, passphrase)                       │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ 2. DBManager.verify_passphrase()                            │
│    - Retrieves stored (hash, salt) from SQLite              │
│    - Derives PBKDF2-HMAC-SHA256 from input passphrase       │
│    - Constant-time comparison: computed_hash == stored_hash │
└────────────────────┬────────────────────────────────────────┘
                     │
                     NO ─────────┐
                     │           │
                     │    ┌──────▼───────┐
                     │    │ Deny access  │
                     │    └──────────────┘
                     │
                     YES
                     │
┌────────────────────▼────────────────────────────────────────┐
│ 3. Load private key and enable GUI tabs                     │
│    - Retrieve key_path_private from DB                      │
│    - Decrypt private_key_encrypted.json using passphrase    │
│    - Load RSA-4096 private key into memory                  │
│    - Store in self.loaded_private_key_pem                   │
│    - Set self.current_user state                            │
│    - Enable Encrypt & Decrypt tabs                          │
└─────────────────────────────────────────────────────────────┘
```

**Security Properties:**
- **Timing-Safe Comparison:** Constant-time hash comparison prevents timing attacks
- **In-Memory Management:** Private key only decrypted after successful login; cleared on logout
- **Per-User Isolation:** Each user's keys stored in separate directory; DB prevents cross-user access

---

## Universal Format Support

The system treats all files as opaque binary streams, making it format-agnostic. Supported file categories include:

- **Text:** `.txt`, `.md`, `.csv`, `.json`, `.xml`, `.log`, `.yml`, `.ini`
- **Images:** `.jpg`, `.png`, `.gif`, `.bmp`, `.tiff`, `.webp`, `.ico`
- **Documents:** `.pdf`, `.docx`, `.xlsx`, `.pptx`, `.doc`, `.xls`, `.odt`
- **Media:** `.mp4`, `.avi`, `.mov`, `.mkv`, `.mp3`, `.wav`, `.flac`, `.aac`
- **Archives:** `.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.bz2`
- **Executables:** `.exe`, `.dll`, `.so`, `.dylib`, `.bin`
- **Any Other Binary Type**

The system automatically:
1. Detects file metadata (MIME type, extension, size).
2. Treats content as raw bytes (no format assumptions).
3. Preserves original filename in encrypted package metadata.
4. Embeds file type classification for post-decryption context.
