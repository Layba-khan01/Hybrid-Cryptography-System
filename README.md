# Hybrid Cryptography System

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║          🔐 HYBRID CRYPTOGRAPHY SYSTEM - SUCCESSFULLY DEPLOYED 🔐        ║
║                                                                           ║
║               AES-256-GCM • RSA-4096-PSS-OAEP • PBKDF2-SHA256             ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

A production-grade hybrid cryptography system implemented in Python 3 using PyCryptodome. It combines AES-256-GCM (AEAD), RSA-4096-OAEP for session key exchange, RSA-4096-PSS for signatures, and PBKDF2-SHA256 for passphrase-based key derivation.

## Quick Links

- Demo: `examples/demo.py`
- Core engine: `crypto_engine/hybrid_crypto.py`
- Deep dive: `TECHNICAL_OVERVIEW.md`

## Table of Contents

- Overview
- Quick Start
- Usage
- Security Considerations
- API Reference
- Contributing & Support

## Project Structure

```
Hybrid-Cryptography-System/
├── crypto_engine/
│   ├── __init__.py                   # Package initialization
│   ├── hybrid_crypto.py              # Core cryptography engine (Base64 encoding)
│   ├── db_manager.py                 # SQLite DB manager for multi-user auth & key lookup
│   └── gui_app.py                    # Tkinter GUI application (DB-backed)
├── examples/
│   ├── demo.py                       # Main demonstration (production-ready)
│   ├── sample_message.txt            # Generated test message
│   ├── message_encrypted.json        # Generated encrypted package
│   └── message_decrypted.txt         # Generated decrypted output
├── keys/                             # Generated at runtime (per-user directories)
│   └── <username>/
│       ├── private_key_encrypted.json
│       └── public_key.pem
├── user_data/                        # Database directory (created at runtime)
│   └── app.db                        # SQLite database for user management
├── scripts/
│   └── cleanup_docs_and_keys.ps1     # Repository cleanup utility
├── requirements.txt                  # Dependencies (pycryptodomex)
├── README.md                         # Complete documentation
├── TECHNICAL_OVERVIEW.md             # Cryptographic specifications
├── QUICKSTART.md                     # Getting started guide
├── DELIVERABLES.md                   # Requirements checklist
├── RELEASE_NOTES.md                  # Recent changes and migration guide
├── LICENSE                           # MIT License
└── .gitignore                        # Git configuration
```

## Installation

**Requirements:** Python 3.7+, pip

```bash
cd Hybrid-Cryptography-System
pip install -r requirements.txt
```

## Usage

### GUI

```bash
python -m crypto_engine.gui_app
```

**Tabs:** Login/Register, Encrypt & Share, Receive & Decrypt  
**Features:** DB-backed user auth, secure passphrases, file browser, tampering detection

### Python API

```python
from crypto_engine import generate_rsa_keypair, encrypt_file, decrypt_file, load_private_key

# Generate keys
sender = generate_rsa_keypair("passphrase")
receiver = generate_rsa_keypair("passphrase")

# Encrypt
encrypted = encrypt_file("file.txt", receiver['public_key_pem'].encode(), sender['private_key_pem'].encode())

# Decrypt
key = load_private_key(receiver['private_key_file'], "passphrase")
plaintext = decrypt_file(encrypted, key, sender['public_key_pem'].encode())
```

### Demo

```bash
python examples/demo.py
```

## API Reference

| Function | Purpose |
|----------|---------|
| `generate_rsa_keypair(passphrase, key_size=4096, output_dir="./keys")` | Generate RSA-4096 keypair |
| `load_private_key(path, passphrase)` | Decrypt & load private key |
| `encrypt_file(plaintext, receiver_pub, sender_priv)` | Encrypt with AES-256-GCM + RSA-4096 |
| `decrypt_file(package, receiver_priv, sender_pub=None)` | Decrypt & verify signature |
| `save_encrypted_file(package, path)` | Save to JSON |
| `load_encrypted_file(path)` | Load from JSON |

**Package Structure (Base64-encoded):**
```json
{
  "ciphertext": "...",
  "iv": "...",
  "auth_tag": "...",
  "encrypted_session_key": "...",
  "signature": "...",
  "public_key_pem": "...",
  "algorithm": {"encryption": "AES-256-GCM", "key_exchange": "RSA-4096-OAEP", "signature": "RSA-4096-PSS"},
  "metadata": {"original_filename": "...", "original_size": 1024, ...}
}
```

**Supported Files:** Text, images, PDFs, videos, audio, archives, executables, and any binary type.

## Security

**Strengths:** AES-256-GCM, RSA-4096, PBKDF2 (100k iter), per-file randomness

**Best Practices:** Strong passphrases (16+ chars), protect private keys, distribute public keys securely, rotate keys periodically

**Limitations:** Files loaded into memory, no key revocation

## Testing

```bash
python examples/demo.py
```

## License

MIT License - see LICENSE file

## References

- [NIST SP 800-132 - PBKDF2](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
- [RFC 8017 - RSA](https://tools.ietf.org/html/rfc8017)
- [NIST SP 800-38D - GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
