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

**The Hybrid Cryptography System** delivers end-to-end encrypted communication through a hardened reference implementation combining symmetric and asymmetric cryptography with identity management.

### Value Proposition

- **Confidentiality + Integrity:** AES-256-GCM authenticated encryption prevents both eavesdropping and tampering
- **Non-Repudiation:** RSA-4096-PSS digital signatures prove sender identity and prevent denial of responsibility
- **Multi-User Isolation:** SQLite + PBKDF2 identity layer provides per-user key management with 100,000 iteration brute-force resistance

The system treats all files as opaque binary streams, enabling **format-agnostic encryption** across any file type without vendor lock-in or format-specific parsing.

### Cryptographic Foundation

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

---

## Installation

### Requirements

- Python 3.7 or higher
- PyCryptodome 3.18.0+ (pure Python cryptography with side-channel attack mitigations)

### Setup

To install the system, clone the repository from GitHub into your local development environment, navigate to the project directory, and install all required dependencies using the package manager. The installation process will download PyCryptodome and other dependencies listed in the requirements file. Once installation completes, the system is ready for use.

---

## Quick Start

### Graphical Interface (Recommended)

Launch the graphical interface by executing the GUI application module. The application window will open with a user-friendly interface designed for secure communication without requiring command-line expertise.

**Three-Tab Workflow:**

1. **Login / Register:** Create or authenticate as a user; auto-generates RSA-4096 keys in `./keys/<username>/`
2. **Encrypt & Share:** Select plaintext file → Choose receiver from DB → Provide passphrase → Encrypt with full hybrid protocol
3. **Receive & Decrypt:** Load encrypted JSON → Receive public key lookup → Decrypt with tampering detection

### Python API (Programmatic)

Developers can integrate the system programmatically by importing the cryptographic functions from the core module. The typical workflow involves generating RSA-4096 keypairs for both parties, encrypting a file using the recipient's public key while signing with the sender's private key, transmitting the encrypted package, and then decrypting and verifying the file on the receiving end. The system automatically detects tampering attempts and raises security alerts if any verification step fails. All operations are accessible through well-documented functions that handle the complete hybrid encryption pipeline internally.

### Demonstration

To understand the complete encryption and decryption workflow, execute the demonstration script included in the examples directory. This script performs a full end-to-end encryption scenario with multiple verification checkpoints, showing how the system protects against tampering and validates authenticity.

---

## Usage

### GUI Tabs & Workflows

| Tab | Workflow | Key Operations |
|-----|----------|-----------------|
| **Login / Register** | Create user account or authenticate | PBKDF2 key generation → RSA-4096 keypair → DB registration |
| **Encrypt & Share** | Encrypt file for recipient | File selection → AES-256-GCM encryption → RSA-4096-OAEP key wrap → RSA-4096-PSS signature |
| **Receive & Decrypt** | Decrypt and verify received file | JSON load → RSA-PSS signature verification → RSA-4096-OAEP key unwrap → AES-256-GCM decryption |

### Advanced Python API Workflows

For specialized use cases, developers can access lower-level functions to derive encryption keys from passphrases using PBKDF2, inspect file metadata from encrypted packages without performing decryption, and validate package integrity before processing. These functions enable custom workflows such as key management automation, batch processing, and integration with external systems while maintaining security guarantees.

---

## Universal Format Support

**Binary-Agnostic Byte-Stream Processing:** The system treats all files as opaque byte sequences, enabling seamless encryption of any format without format-specific parsing or assumptions.

**Supported Categories:**
- **Text:** Documents, code, configuration, logs (`.txt`, `.md`, `.json`, `.xml`, `.yml`, `.csv`, `.log`)
- **Media:** Images, video, audio (`.jpg`, `.png`, `.gif`, `.mp4`, `.avi`, `.mp3`, `.wav`)
- **Business:** Office documents, archives (`.pdf`, `.docx`, `.xlsx`, `.zip`, `.7z`, `.tar`)
- **System:** Executables, libraries, compiled binaries (`.exe`, `.dll`, `.so`, `.dylib`)
- **Any custom or proprietary binary format**

**Metadata Preservation:** Original filename, MIME type, size, and file extension are recovered post-decryption.

---

## JSON Package Schema

All encrypted packages use Base64-encoded JSON (RFC 4648) for universal API/database compatibility. The package includes all necessary components for the receiver to verify authenticity and decrypt the plaintext:

| Field | Content | Encoding | Purpose |
|-------|---------|----------|----------|
| `algorithm` | Crypto identifiers (AES-256-GCM, RSA-4096-OAEP/PSS) | JSON object | Algorithm transparency |
| `ciphertext` | Encrypted plaintext | Base64 | Confidentiality |
| `iv` | 96-bit initialization vector | Base64 | Nonce for AES-GCM |
| `auth_tag` | 128-bit authentication tag | Base64 | Ciphertext integrity verification |
| `encrypted_session_key` | AES key wrapped with RSA-4096-OAEP | Base64 | Recipient-only decryption |
| `signature` | Ciphertext signed with RSA-4096-PSS | Base64 | Authenticity + non-repudiation |
| `public_key_pem` | Sender's RSA-4096 public key | Base64 string | Signature verification (no PKI needed) |
| `metadata` | Filename, size, MIME type, category | JSON object | File recovery context |

**Encryption Pipeline (Sender):**
1. Generate random 256-bit session key
2. Encrypt plaintext with AES-256-GCM + random IV → ciphertext + auth_tag
3. Wrap session key with recipient's RSA-4096 public key → encrypted_session_key
4. Sign ciphertext with sender's RSA-4096 private key → signature
5. Base64-encode all binary fields and serialize to JSON

**Decryption Pipeline (Receiver - Fail-Closed Design):**
1. Extract and Base64-decode components
2. Verify RSA-4096-PSS signature using sender's embedded public key → **GATE 1**
3. Unwrap session key using receiver's RSA-4096 private key
4. Decrypt ciphertext using session key + IV with AES-256-GCM
5. Verify GCM authentication tag → **GATE 2**
6. Release plaintext only if both gates pass

---

## API Reference

### Core Encryption Functions (`crypto_engine.hybrid_crypto`)

| Function | Parameters | Returns | Security Responsibility |
|----------|-----------|---------|------------------------|
| `derive_key_from_passphrase(passphrase, salt=None, key_length=32, iterations=100000)` | `str`, `bytes \| None`, `int`, `int` | `(key: bytes, salt: bytes)` | PBKDF2 key derivation; brute-force resistance |
| `generate_rsa_keypair(passphrase, key_size=4096, output_dir="./keys")` | `str`, `int`, `str` | `Dict[str, str]` | RSA-4096 key generation; private key encryption with derived key |
| `load_private_key(private_key_file, passphrase)` | `str`, `str` | `bytes` | Decrypt private key from disk; passphrase verification |
| `encrypt_file(plaintext_path, receiver_public_key_pem, sender_private_key_pem)` | `str`, `bytes`, `bytes` | `Dict[str, Any]` | Full hybrid encryption: AES-256-GCM + RSA-4096-OAEP + RSA-4096-PSS |
| `decrypt_file(encrypted_package, receiver_private_key_pem, sender_public_key_pem)` | `Dict[str, Any]`, `bytes`, `bytes` | `bytes` | Full hybrid decryption with dual tampering detection |
| `save_encrypted_file(package, path)` | `Dict[str, Any]`, `str` | `None` | Serialize encrypted package to JSON file |
| `load_encrypted_file(path)` | `str` | `Dict[str, Any]` | Deserialize encrypted package from JSON file |
| `get_file_metadata(encrypted_package)` | `Dict[str, Any]` | `Dict[str, Any]` | Extract metadata without decryption |
| `verify_package_integrity(encrypted_package)` | `Dict[str, Any]` | `bool` | Validate all required fields present |

### Database Functions (`crypto_engine.db_manager.DBManager`)

| Method | Parameters | Returns | Security Responsibility |
|--------|-----------|---------|------------------------|
| `register_user(username, passphrase, private_key_path, public_key_path)` | `str`, `str`, `str`, `str` | `None` | PBKDF2 hash derivation; per-user salt generation |
| `get_user_data(username)` | `str` | `Dict \| None` | Retrieve encrypted key paths from SQLite |
| `verify_passphrase(username, passphrase)` | `str`, `str` | `bool` | PBKDF2 constant-time comparison; timing-attack resistance |
| `get_all_usernames()` | (none) | `List[str]` | Return registered users for GUI combobox population |
| `get_public_key_by_username(username)` | `str` | `bytes \| None` | Load public key from disk; no decryption required |

---

## Security Properties

### Confidentiality: AES-256-GCM

- **Cipher:** AES (NIST FIPS 197) with 256-bit keys
- **Mode:** GCM (Galois/Counter Mode per NIST SP 800-38D) with 96-bit random IV
- **Authentication:** 128-bit auth tag detects any ciphertext modification
- **Per-File Randomness:** Unique IV per encryption ensures identical plaintexts produce different ciphertexts
- **Effective Security:** 256-bit symmetric security level

### Authentication & Non-Repudiation: RSA-4096-PSS

- **Key Size:** 4096-bit RSA modulus (~112-bit ECC-equivalent)
- **Scheme:** PSS (Probabilistic Signature Scheme) per RFC 8017
- **Hash:** SHA-256 (512-bit digests)
- **Signed Data:** Ciphertext only (metadata authenticated implicitly through signature)
- **Non-Repudiation:** Sender cannot deny creating signature (private key required)

### Key Wrapping: RSA-4096-OAEP

- **Key Size:** 4096-bit RSA modulus
- **Scheme:** OAEP (Optimal Asymmetric Encryption Padding) per RFC 8017
- **Hash:** SHA-256
- **Session Key:** 256-bit AES key encrypted for recipient only

### Key Derivation: PBKDF2-HMAC-SHA256

- **Standard:** NIST SP 800-132
- **Hash Function:** HMAC-SHA256
- **Iterations:** 100,000 (recommended 2023 minimum per OWASP)
- **Salt:** 32 bytes, cryptographically random per user
- **Derived Key:** 32 bytes (matches AES-256 requirement)
- **Resistance:** ~6 guesses/second on modern CPU (~150ms per derivation)

### Identity Management: SQLite + PBKDF2

- **Storage:** `user_data/app.db` (SQLite3)
- **Passphrase Hashing:** PBKDF2-HMAC-SHA256 with random per-user salts
- **Comparison:** Constant-time hash verification (prevents timing side-channel attacks)
- **Private Key Lifecycle:** Decrypted only after successful login; cleared on logout
- **Access Control:** Filesystem-level per-user directories + DB-level isolation

### Limitations & Known Constraints

| Constraint | Reason | Mitigation |
|-----------|--------|-----------|
| **Files Loaded in Memory** | AES-GCM requires full ciphertext for auth tag verification | Use external tools or HSM integration for streaming |
| **No Key Revocation** | Revoked keys cannot be invalidated retroactively | Implement key versioning + expiration timestamps |
| **No Forward Secrecy** | Session keys stored in encrypted packages indefinitely | Use ephemeral key derivation for ephemeral confidentiality |
| **SQLite Unencrypted** | Database stored on disk as plaintext | Enable full-disk encryption (BitLocker, LUKS, FileVault) |
| **Passphrase Entropy Assumption** | No enforcement of strong passphrases | Add GUI passphrase strength meter; enforce policies |
| **No Multi-Device Support** | Keys stored locally only | Integrate secure key server (HSM, Azure Key Vault) |
| **RSA Quantum Vulnerability** | Post-quantum cryptography not yet standardized | Monitor NIST PQC standardization; plan migration |
| **No Hardware Security Module** | Private keys stored in software memory | Integrate PKCS#11 HSM support for high-security deployments |

---

## Project Structure

```
Hybrid-Cryptography-System/
├── crypto_engine/                    # Main cryptography package
│   ├── __init__.py                   # Public API exports
│   ├── hybrid_crypto.py              # Core engine (AES-256-GCM, RSA-4096, PBKDF2)
│   ├── db_manager.py                 # SQLite user management & key registry
│   ├── gui_app.py                    # Tkinter GUI (Login, Encrypt, Decrypt tabs)
│   └── __pycache__/                  # Python bytecode cache
├── docs/
│   ├── images/
│   │   ├── banner.png                # Project branding banner
│   │   └── gui_main.png              # GUI screenshot (optional)
│   └── ARCHITECTURE.md               # Detailed flow diagrams & design docs
├── examples/
│   ├── demo.py                       # End-to-end encryption/decryption demo
│   ├── sample_message.txt            # Example plaintext
│   ├── message_encrypted.json        # Example encrypted package
│   └── message_decrypted.txt         # Example decrypted output
├── keys/                             # User RSA keypair storage (created at runtime)
│   └── <username>/
│       ├── private_key_encrypted.json # PBKDF2-encrypted RSA-4096 private key
│       └── public_key.pem            # RSA-4096 public key (PEM format)
├── user_data/                        # Database directory (created at runtime)
│   └── app.db                        # SQLite3 user registry
├── scripts/
│   └── cleanup_docs_and_keys.ps1     # PowerShell cleanup utility
├── requirements.txt                  # Python dependencies
├── README.md                         # This file
├── QUICKSTART.md                     # Step-by-step setup guide
├── TECHNICAL_OVERVIEW.md             # Cryptographic algorithm specifications
├── DELIVERABLES.md                   # Feature checklist & implementation status
├── RELEASE_NOTES.md                  # Version history & migration guide
├── LICENSE                           # MIT License
└── .gitignore                        # Git ignore patterns
```

---

## Getting Help

### Common Questions

**Q: How do I start using the system?**  
A: Launch the graphical interface to register a user account. The system automatically generates an RSA-4096 keypair and stores it in encrypted form. After registration, use the Encrypt & Share tab to send encrypted files to other registered users.

**Q: What if I lose my passphrase?**  
A: The private key cannot be recovered without the correct passphrase. PBKDF2 is intentionally slow to prevent brute-force attacks. You must regenerate your keypair with a new passphrase.

**Q: Can I use the same passphrase for multiple users?**  
A: Each user receives a unique random salt during registration. Even with the same passphrase, different salts produce different hashes, so each user has independent credentials.

**Q: What happens if a file is corrupted during transmission?**  
A: The GCM authentication tag validates ciphertext integrity. Any bit-flip causes tag verification to fail, and the system alerts the user to tampering rather than returning corrupted plaintext.

**Q: How do I share a public key with another user?**  
A: Public keys are automatically embedded in every encrypted package. The receiver can verify the sender without external key distribution or a PKI infrastructure.

### Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| GUI fails to launch | Python environment incomplete or dependencies missing | Verify Python 3.7+ and run package installation again |
| Signature verification failed | Wrong sender or tampered message | Contact sender to verify identity; request retransmission |
| Authentication tag verification failed | File corrupted during transmission | Re-download or request file be resent |
| User already exists | Username already registered | Choose a unique username |
| Passphrase incorrect | Wrong passphrase entered during login | Re-enter passphrase carefully (case-sensitive); if forgotten, create new account |
| Cannot find receiver in list | Receiver account not registered | Ask receiver to register and confirm username |
| Private key file missing | Key storage corruption | Delete account and register again; private keys cannot be recovered |

### Documentation

- **README.md** (this file) — Executive summary & quick reference
- **QUICKSTART.md** — Step-by-step first-time setup
- **TECHNICAL_OVERVIEW.md** — Cryptographic algorithms & security analysis
- **DELIVERABLES.md** — Feature requirements & implementation status
- **RELEASE_NOTES.md** — Version history & breaking changes

### Reporting Issues

Please report bugs or feature requests via GitHub Issues. Include:
- System information (OS: Windows/Linux/macOS, Python version, system architecture)
- Description of the issue and steps to reproduce
- Error messages or unexpected behavior observed
- Whether the issue is reproducible or intermittent
- Any environment details (firewall, antivirus, corporate proxy, etc.)

---

## Standards & References

### Cryptographic Standards

- **NIST SP 800-38D** — GCM Mode Specification (Authenticated Encryption)
- **NIST SP 800-132** — PBKDF2 Key Derivation Function
- **NIST FIPS 197** — Advanced Encryption Standard (AES)
- **RFC 8017** — PKCS #1: RSA Cryptography Specifications (PSS, OAEP)

### Security Best Practices

- **OWASP Password Storage Cheat Sheet** — PBKDF2 iteration count guidance
- **OWASP Cryptographic Storage Cheat Sheet** — AES-256-GCM best practices
- **NIST SP 800-175B** — Guidelines for Use of Cryptographic Algorithms

### Python Libraries

- **PyCryptodome 3.18.0+** — Pure Python cryptography with side-channel mitigations
- **Tkinter (stdlib)** — Cross-platform GUI framework
- **SQLite3 (stdlib)** — Embedded relational database

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## Authors & Contact

**Author:** Layba Khan  
**Repository:** [Hybrid-Cryptography-System](https://github.com/Layba-khan01/Hybrid-Cryptography-System)  
**Issues:** [GitHub Issues](https://github.com/Layba-khan01/Hybrid-Cryptography-System/issues)
