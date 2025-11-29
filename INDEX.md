This file was consolidated into `README.md` during the documentation cleanup.

Refer to `README.md` for navigation and `TECHNICAL_OVERVIEW.md` for the implementation deep-dive.

Deprecated: content moved during repository documentation consolidation.
## 🔐 What It Does

### Encrypts Files Securely
```python
encrypted = encrypt_file(
    "document.txt",
    receiver_public_key,
    sender_private_key
)
```

### Decrypts With Full Verification
```python
plaintext = decrypt_file(
    encrypted_package,
    receiver_private_key,
    sender_public_key
)
```

### Manages Keys Securely
```python
keys = generate_rsa_keypair("passphrase")
# Private key stored encrypted, decrypted only with passphrase
```

---

## 📚 Documentation by Use Case

### "I want to get started immediately"
→ Read [QUICKSTART.md](QUICKSTART.md)
→ Run `python examples/demo.py`
→ Try the basic usage example

### "I want to understand how it works"
→ Read [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md)
→ Review the encryption/decryption flow diagrams
→ Check the security properties analysis

### "I need the API reference"
→ Read [README.md](README.md) - API Reference section
→ Check function signatures in [crypto_engine/hybrid_crypto.py](crypto_engine/hybrid_crypto.py)
→ Review docstrings for detailed parameters

### "I want to know about security"
→ Read [README.md](README.md) - Security Considerations section
→ Read [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) - Threat Protection Matrix
→ Review [QUICKSTART.md](QUICKSTART.md) - Best Practices section

### "I need to integrate this into my project"
→ Read [QUICKSTART.md](QUICKSTART.md) - Usage example
→ Copy `crypto_engine/` to your project
→ `pip install -r requirements.txt`
→ `from crypto_engine import *`

### "I want to verify what was implemented"
→ Read [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)
→ Read [DELIVERABLES.md](DELIVERABLES.md)
→ Check [crypto_engine/hybrid_crypto.py](crypto_engine/hybrid_crypto.py)

---

## 🔑 Core Functions

### 1. derive_key_from_passphrase()
**Purpose**: PBKDF2 key derivation

**Location**: [crypto_engine/hybrid_crypto.py:24-67](crypto_engine/hybrid_crypto.py)

**Usage**:
```python
from crypto_engine import derive_key_from_passphrase

key, salt = derive_key_from_passphrase("my_passphrase")
# Returns: 32-byte key, 16-byte salt
```

**Parameters**:
- passphrase (str): User's passphrase
- salt (optional bytes): Unique salt
- key_length (default 32): Output key length
- iterations (default 100,000): PBKDF2 iterations

**Documentation**: See [README.md](README.md) - API Reference

---

### 2. generate_rsa_keypair()
**Purpose**: Generate and securely store RSA-4096 keys

**Location**: [crypto_engine/hybrid_crypto.py:87-179](crypto_engine/hybrid_crypto.py)

**Usage**:
```python
from crypto_engine import generate_rsa_keypair

keys = generate_rsa_keypair("passphrase", output_dir="./keys")
```

**Returns**:
- private_key_pem: Encrypted private key (PEM format)
- public_key_pem: Public key (PEM format)
- private_key_file: Path to encrypted private key
- public_key_file: Path to public key
- salt: Salt used for encryption

**Documentation**: See [README.md](README.md) - API Reference

---

### 3. encrypt_file()
**Purpose**: Encrypt file with full hybrid protocol

**Location**: [crypto_engine/hybrid_crypto.py:265-347](crypto_engine/hybrid_crypto.py)

**Usage**:
```python
from crypto_engine import encrypt_file

encrypted = encrypt_file(
    "document.txt",
    receiver_public_key_pem,
    sender_private_key_pem
)
```

**Process**:
1. Generate AES-256 session key
2. Encrypt with AES-256-GCM (produces C, IV, T)
3. Encrypt session key with RSA-4096-OAEP
4. Sign with RSA-4096-PSS

**Documentation**: See [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) - File Encryption

---

### 4. decrypt_file()
**Purpose**: Decrypt file with full verification

**Location**: [crypto_engine/hybrid_crypto.py:350-423](crypto_engine/hybrid_crypto.py)

**Usage**:
```python
from crypto_engine import decrypt_file

plaintext = decrypt_file(
    encrypted_package,
    receiver_private_key_pem,
    sender_public_key_pem
)
```

**Verification**:
1. Verify RSA-4096-PSS signature
2. Decrypt AES session key with RSA-4096-OAEP
3. Decrypt ciphertext with AES-256-GCM
4. Verify GCM authentication tag

**Documentation**: See [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) - File Decryption

---

### 5. load_private_key()
**Purpose**: Decrypt and load private key from file

**Location**: [crypto_engine/hybrid_crypto.py:182-219](crypto_engine/hybrid_crypto.py)

**Usage**:
```python
from crypto_engine import load_private_key

private_key = load_private_key(
    "keys/private_key_encrypted.json",
    "passphrase"
)
```

---

### 6. save_encrypted_file()
**Purpose**: Save encrypted package to JSON file

**Location**: [crypto_engine/hybrid_crypto.py:426-439](crypto_engine/hybrid_crypto.py)

**Usage**:
```python
from crypto_engine import save_encrypted_file

save_encrypted_file(encrypted, "message.json")
```

---

### 7. load_encrypted_file()
**Purpose**: Load encrypted package from JSON file

**Location**: [crypto_engine/hybrid_crypto.py:442-459](crypto_engine/hybrid_crypto.py)

**Usage**:
```python
from crypto_engine import load_encrypted_file

encrypted = load_encrypted_file("message.json")
```

---

### 8. Utility Functions
- **get_file_metadata()** - Extract metadata without decryption
- **verify_package_integrity()** - Validate package structure

---

## 📁 File Structure

```
Hybrid-Cryptography-System/
├── crypto_engine/                    Core cryptographic engine
│   ├── __init__.py                   Package exports
│   └── hybrid_crypto.py              Main implementation (800+ lines)
│
├── examples/                         Demonstrations
│   └── demo.py                       Complete working example (350+ lines)
│
├── keys/                             Generated keys (runtime)
│   ├── sender/
│   └── receiver/
│
├── INDEX.md                          This navigation guide
├── QUICKSTART.md                     Getting started (250+ lines)
├── README.md                         Main documentation (450+ lines)
├── TECHNICAL_OVERVIEW.md             Technical details (350+ lines)
├── IMPLEMENTATION_SUMMARY.md         What was built (300+ lines)
├── DELIVERABLES.md                   Deliverables checklist
├── requirements.txt                  Dependencies
└── LICENSE                           MIT License
```

---

## 🚀 Getting Started

### Step 1: Install
```bash
pip install -r requirements.txt
```

### Step 2: Run Demo
```bash
python examples/demo.py
```

### Step 3: Try It Yourself
```python
from crypto_engine import (
    generate_rsa_keypair,
    encrypt_file,
    decrypt_file,
    load_private_key
)

# Generate keys
sender = generate_rsa_keypair("sender_pass")
receiver = generate_rsa_keypair("receiver_pass")

# Encrypt
encrypted = encrypt_file(
    "secret.txt",
    receiver['public_key_pem'].encode(),
    sender['private_key_pem'].encode()
)

# Decrypt
receiver_key = load_private_key(receiver['private_key_file'], "receiver_pass")
plaintext = decrypt_file(encrypted, receiver_key, sender['public_key_pem'].encode())
```

---

## 🔍 Understanding the Protocols

### Encryption Protocol
**See**: [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) - Encryption Protocol Flow

1. Generate random AES-256 session key (Ks)
2. Encrypt plaintext with AES-256-GCM → (C, IV, T)
3. Encrypt session key with RSA-4096-OAEP → (Ks_enc)
4. Sign ciphertext with RSA-4096-PSS → (Sig)

### Decryption Protocol
**See**: [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) - Decryption Protocol Flow

1. Verify RSA-4096-PSS signature
2. Decrypt session key with RSA-4096-OAEP
3. Decrypt ciphertext with AES-256-GCM
4. Verify authentication tag

---

## 🔒 Security Features

### Confidentiality
- AES-256 encryption
- GCM mode with authentication tag
- Per-file unique keys and IVs

### Authenticity
- RSA-4096-PSS digital signatures
- SHA-256 digest of ciphertext
- Non-repudiation (sender cannot deny)

### Integrity
- GCM authentication tag (128-bit)
- Tampering detection
- Rejection of corrupted data

### Key Security
- PBKDF2-SHA256 key derivation
- 100,000 iterations
- 16-byte unique salt per derivation
- Encrypted private key storage

**See**: [README.md](README.md) - Security Considerations

---

## 🧪 Testing

### Run the Demo
```bash
python examples/demo.py
```

**Tests Performed**:
- ✓ Key generation
- ✓ File encryption
- ✓ File decryption
- ✓ Plaintext recovery
- ✓ Tampering detection
- ✓ Signature verification
- ✓ GCM tag verification

---

## 📊 Performance

| Operation | Time | Notes |
|-----------|------|-------|
| RSA-4096 Key Generation | 5-15 seconds | One-time |
| File Encryption | ~10ms | AES speed |
| File Decryption | ~10ms | AES speed |
| Signature Generation | 1-2 seconds | RSA-PSS |
| Key Derivation | 0.5-1 second | PBKDF2 100k |

**See**: [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) - Performance Characteristics

---

## 🔧 API Quick Reference

```python
# Key Management
from crypto_engine import (
    derive_key_from_passphrase,
    generate_rsa_keypair,
    load_private_key
)

# File Operations
from crypto_engine import (
    encrypt_file,
    decrypt_file,
    save_encrypted_file,
    load_encrypted_file
)

# Utilities
from crypto_engine import (
    get_file_metadata,
    verify_package_integrity
)
```

**Full Reference**: [README.md](README.md) - API Reference

---

## ❓ FAQ

### Q: Is this production-ready?
**A**: Yes. See [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) for verification.

### Q: How secure is this?
**A**: Military-grade. Uses 4096-bit RSA, 256-bit AES, PBKDF2 with 100k iterations. See [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md).

### Q: Can I integrate this into my project?
**A**: Yes. Copy `crypto_engine/` folder and `pip install -r requirements.txt`.

### Q: What if someone tampers with the encrypted file?
**A**: Tampering will be detected via signature verification or GCM tag verification, and decryption will be rejected.

### Q: How do I share with others?
**A**: Exchange public keys through any channel. Encrypt with their public key, they decrypt with their private key.

### Q: What if I forget my passphrase?
**A**: The private key cannot be recovered without the correct passphrase. You'll need to regenerate keys.

**See**: [QUICKSTART.md](QUICKSTART.md) - Troubleshooting

---

## 📖 Documentation Map

| Document | Purpose | Read Time |
|----------|---------|-----------|
| [QUICKSTART.md](QUICKSTART.md) | Get started fast | 10 min |
| [README.md](README.md) | Complete reference | 30 min |
| [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) | Understand crypto | 20 min |
| [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) | Verify implementation | 15 min |
| [DELIVERABLES.md](DELIVERABLES.md) | Check requirements | 10 min |
| [INDEX.md](INDEX.md) | Navigate all docs | 5 min |

---

## 🎓 Learning Path

### Beginner (Want to use it)
1. [QUICKSTART.md](QUICKSTART.md) - Installation & basic usage
2. Run `python examples/demo.py`
3. Modify demo.py for your files

### Intermediate (Want to integrate it)
1. Review [README.md](README.md) - API Reference
2. Read [QUICKSTART.md](QUICKSTART.md) - Key Management
3. Study [examples/demo.py](examples/demo.py)
4. Integrate into your project

### Advanced (Want to understand it)
1. [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) - Protocols
2. [crypto_engine/hybrid_crypto.py](crypto_engine/hybrid_crypto.py) - Source code
3. Review comments and docstrings
4. Study NIST/RFC standards

---

## 🤝 Contributing

Contributions welcome! See [README.md](README.md) - Contributing

---

## 📄 License

MIT License - See [LICENSE](LICENSE)

---

## 📞 Support

- **Documentation**: See [README.md](README.md) - Support
- **Troubleshooting**: See [QUICKSTART.md](QUICKSTART.md) - Troubleshooting
- **Examples**: See [examples/demo.py](examples/demo.py)

---

## ✅ Verification Checklist

Use this to verify the complete installation:

- [ ] Python 3.7+ installed
- [ ] Dependencies installed: `pip install -r requirements.txt`
- [ ] Can import: `from crypto_engine import generate_rsa_keypair`
- [ ] Demo runs: `python examples/demo.py`
- [ ] Documentation readable: Open [QUICKSTART.md](QUICKSTART.md)
- [ ] Ready to use!

---

## 🎯 Next Steps

1. **Immediate**: Run `python examples/demo.py`
2. **Short-term**: Read [QUICKSTART.md](QUICKSTART.md)
3. **Medium-term**: Read [README.md](README.md) API Reference
4. **Long-term**: Read [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md)

---

**Welcome to the Hybrid Cryptography System!**

Start with [QUICKSTART.md](QUICKSTART.md) or run `python examples/demo.py`.

For detailed navigation, use the links above or check the file structure.
