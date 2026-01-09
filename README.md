# Hybrid Cryptography System

<div align="center">

![Hybrid Cryptography System](docs/images/banner.png)

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Security](https://img.shields.io/badge/Security-AES--256--GCM%20%2B%20RSA--4096-red?style=flat-square)](TECHNICAL_OVERVIEW.md)
[![Architecture](https://img.shields.io/badge/Architecture-Hybrid%20Cryptography-orange?style=flat-square)](TECHNICAL_OVERVIEW.md)

**A Hardened Reference Implementation of Authenticated Encryption for Secure Multi-User Workflows**

</div>

---

## Executive Summary

The Hybrid Cryptography System is a secure multi-user cryptographic architecture that combines symmetric (AES-256-GCM) and asymmetric (RSA-4096-OAEP/PSS) cryptography with identity management (SQLite + PBKDF2) to deliver end-to-end encrypted communication with non-repudiation guarantees. The system treats all files as opaque byte streams, enabling **binary-agnostic processing** across any file format without format-specific assumptions.

### Cryptographic Foundation

The Hybrid Cryptography System is a battle-hardened encryption framework that combines symmetric and asymmetric cryptography with digital signatures to deliver authenticated encryption with non-repudiation guarantees. The system is designed for secure multi-user workflows where identity verification, data confidentiality, and integrity assurance are non-negotiable.

### Cryptographic Primitives

The implementation employs NIST-approved algorithms with proven security properties:

| Component | Algorithm | Key Size | Mode/Padding | Security Property |
|-----------|-----------|----------|-------------|---------|
| **Confidentiality** | AES | 256 bits | GCM (Galois/Counter, NIST SP 800-38D) | Authenticated encryption; 128-bit auth tag |
| **Session Key Encryption** | RSA | 4096 bits | OAEP with SHA-256 (RFC 8017) | Recipient-only decryption |
| **Authenticity & Non-Repudiation** | RSA | 4096 bits | PSS with SHA-256 (RFC 8017) | Sender signature verification |
| **Key Derivation** | PBKDF2 | - | HMAC-SHA256 (100k iterations, NIST SP 800-132) | Brute-force resistance (~150ms/guess) |

### Architecture Overview

- **Multi-User Identity Layer:** SQLite-backed user registry with PBKDF2-derived passphrase hashes (per-user random salts, constant-time verification)
- **Per-User Key Storage:** Encrypted RSA-4096 private keys stored locally under `./keys/<username>/` with Base64-encoded JSON serialization
- **Embedded Sender Identity:** RSA-4096 public key Base64-encoded and embedded in encrypted packages for seamless verification without external key distribution
- **Dual Tampering Detection:** GCM authentication tag validates ciphertext integrity; RSA-PSS signature validates authenticity and prevents forgery
- **Format-Agnostic Processing:** Binary byte-stream model treats all files identically regardless of extension or MIME type

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Usage](#usage)
4. [Universal Format Support](#universal-format-support)
5. [JSON Package Schema](#json-package-schema)
6. [API Reference](#api-reference)
7. [Security Properties](#security-properties)
8. [Project Structure](#project-structure)
9. [Getting Help](#getting-help)

## Installation

### Requirements

- Python 3.7 or higher
- PyCryptodome 3.18.0+ (pure Python cryptography with side-channel attack mitigations)

### Setup

```bash
git clone https://github.com/Layba-khan01/Hybrid-Cryptography-System.git
cd Hybrid-Cryptography-System
pip install -r requirements.txt
```

---

## Quick Start

### Graphical Interface (Recommended)

```bash
python -m crypto_engine.gui_app
```

**Three-Tab Workflow:**

1. **Login / Register:** Create or authenticate as a user; auto-generates RSA-4096 keys in `./keys/<username>/`
2. **Encrypt & Share:** Select plaintext file → Choose receiver from DB → Provide passphrase → Encrypt with full hybrid protocol
3. **Receive & Decrypt:** Load encrypted JSON → Receive public key lookup → Decrypt with tampering detection

### Python API (Programmatic)

```python
from crypto_engine import (
    generate_rsa_keypair,
    encrypt_file,
    decrypt_file,
    load_private_key,
    save_encrypted_file,
    load_encrypted_file
)

# Generate keypairs
alice_keys = generate_rsa_keypair(passphrase="alice_pass", output_dir="./keys/alice")
bob_keys = generate_rsa_keypair(passphrase="bob_pass", output_dir="./keys/bob")

# Encrypt (Alice → Bob)
encrypted_pkg = encrypt_file(
    plaintext_path="./documents/secret.pdf",
    receiver_public_key_pem=bob_keys['public_key_pem'].encode(),
    sender_private_key_pem=alice_keys['private_key_pem'].encode()
)
save_encrypted_file(encrypted_pkg, "./transmit/secret.json")

# Decrypt (Bob receives)
bob_private_key = load_private_key(
    bob_keys['private_key_file'],
    passphrase="bob_pass"
)
encrypted_pkg = load_encrypted_file("./transmit/secret.json")

try:
    plaintext = decrypt_file(
        encrypted_package=encrypted_pkg,
        receiver_private_key_pem=bob_private_key,
        sender_public_key_pem=alice_keys['public_key_pem'].encode()
    )
    print(f"✓ Decryption successful. Recovered {len(plaintext)} bytes.")
except ValueError as e:
    print(f"⚠ TAMPERING DETECTED: {e}")
```

### Demonstration

```bash
python examples/demo.py
```

---

## Usage

### GUI Tabs & Workflows

| Tab | Workflow | Key Operations |
|-----|----------|-----------------|
| **Login / Register** | Create user account or authenticate | PBKDF2 key generation → RSA-4096 keypair → DB registration |
| **Encrypt & Share** | Encrypt file for recipient | File selection → AES-256-GCM encryption → RSA-4096-OAEP key wrap → RSA-4096-PSS signature |
| **Receive & Decrypt** | Decrypt and verify received file | JSON load → RSA-PSS signature verification → RSA-4096-OAEP key unwrap → AES-256-GCM decryption |

### Python API Workflows

```python
# Advanced: Direct key derivation for custom workflows
from crypto_engine import derive_key_from_passphrase

key, salt = derive_key_from_passphrase("my_passphrase")  # Returns 32-byte key + random salt
key, _ = derive_key_from_passphrase("my_passphrase", salt=salt)  # Deterministic with known salt

# File metadata inspection without decryption
from crypto_engine import get_file_metadata
metadata = get_file_metadata(encrypted_pkg)
print(f"Original: {metadata['original_filename']} ({metadata['original_size']} bytes)")

# Integrity verification
from crypto_engine import verify_package_integrity
is_valid = verify_package_integrity(encrypted_pkg)  # Validates all required fields
```
