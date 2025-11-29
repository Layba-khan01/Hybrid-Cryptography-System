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
- Quick start: `QUICKSTART.md`
- Deliverables checklist: `DELIVERABLES.md`

## Table of Contents

- Overview
- Quick Start
- Usage
- Security Considerations
- API Reference
- Contributing & Support

## Project Structure (short)

```
crypto_engine/
  └─ hybrid_crypto.py
examples/
  └─ demo.py
keys/
  └─ (generated keys at runtime)
README.md
TECHNICAL_OVERVIEW.md
QUICKSTART.md
DELIVERABLES.md
```

## Installation

### Prerequisites
- Python 3.7+
- pip (Python package manager)

### Setup

1. Clone or download the repository:
```bash
cd Hybrid-Cryptography-System
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```python
from crypto_engine import (
    generate_rsa_keypair,
    encrypt_file,
    decrypt_file,
    load_private_key,
    load_encrypted_file
)

# Generate RSA key pairs
sender_keys = generate_rsa_keypair(passphrase="sender_passphrase")
receiver_keys = generate_rsa_keypair(passphrase="receiver_passphrase")

# Encrypt a file
encrypted = encrypt_file(
    plaintext_path="document.txt",
    receiver_public_key_pem=receiver_keys['public_key_pem'].encode(),
    sender_private_key_pem=sender_keys['private_key_pem'].encode()
)

# Decrypt the file
receiver_private_key = load_private_key(
    receiver_keys['private_key_file'],
    passphrase="receiver_passphrase"
)

plaintext = decrypt_file(
    encrypted_package=encrypted,
    receiver_private_key_pem=receiver_private_key,
    sender_public_key_pem=sender_keys['public_key_pem'].encode()
)
```

### Running the Demonstration

```bash
python examples/demo.py
```

This will:
1. Generate RSA-4096 key pairs for sender and receiver
2. Create a sample confidential message
3. Encrypt the message using the hybrid protocol
4. Decrypt the message and verify authenticity
5. Demonstrate tampering detection

## API Reference

### Core Functions

#### `derive_key_from_passphrase(passphrase, salt=None, key_length=32, iterations=100000)`
Derives a cryptographic key from a passphrase using PBKDF2-SHA256.

**Parameters:**
- `passphrase` (str): User's passphrase
- `salt` (bytes, optional): Unique salt (16 bytes generated if None)
- `key_length` (int): Key length in bytes (default: 32 for AES-256)
- `iterations` (int): PBKDF2 iterations (default: 100,000)

**Returns:** `(derived_key: bytes, salt: bytes)`

#### `generate_rsa_keypair(passphrase, key_size=4096, output_dir="./keys")`
Generates and securely stores an RSA key pair.

**Parameters:**
- `passphrase` (str): Passphrase for encrypting private key
- `key_size` (int): RSA key size in bits (default: 4096)
- `output_dir` (str): Directory to store keys

**Returns:** Dictionary with key paths and PEM formats

#### `encrypt_file(plaintext_path, receiver_public_key_pem, sender_private_key_pem)`
Encrypts a file using the hybrid protocol.

**Process:**
1. Generate random AES-256 session key (Ks)
2. Encrypt plaintext with AES-256-GCM → (C, IV, T)
3. Encrypt session key with RSA-4096-OAEP → (Ks_enc)
4. Sign ciphertext with RSA-4096-PSS → (Sig)

**Parameters:**
- `plaintext_path` (str): Path to file to encrypt
- `receiver_public_key_pem` (bytes): Receiver's public key
- `sender_private_key_pem` (bytes): Sender's private key

**Returns:** Dictionary containing encrypted package

#### `decrypt_file(encrypted_package, receiver_private_key_pem, sender_public_key_pem)`
Decrypts a file with full verification.

**Verification Process:**
1. Verify RSA-4096-PSS signature on ciphertext
2. Decrypt session key with RSA-4096-OAEP
3. Decrypt ciphertext with AES-256-GCM and verify authentication tag

**Parameters:**
- `encrypted_package` (dict): Encrypted data package
- `receiver_private_key_pem` (bytes): Receiver's private key
- `sender_public_key_pem` (bytes): Sender's public key

**Returns:** Decrypted plaintext (bytes)

#### `load_private_key(private_key_file, passphrase)`
Loads and decrypts a private key from an encrypted file.

**Parameters:**
- `private_key_file` (str): Path to encrypted key JSON file
- `passphrase` (str): Passphrase for decryption

**Returns:** Decrypted private key (bytes)

#### `save_encrypted_file(encrypted_package, output_path)`
Saves an encrypted package to a JSON file.

**Parameters:**
- `encrypted_package` (dict): Encrypted data from `encrypt_file()`
- `output_path` (str): Output file path

**Returns:** Path to saved file

#### `load_encrypted_file(encrypted_file_path)`
Loads an encrypted package from a JSON file.

**Parameters:**
- `encrypted_file_path` (str): Path to encrypted JSON file

**Returns:** Encrypted package dictionary

#### `verify_package_integrity(encrypted_package)`
Verifies that an encrypted package has all required fields.

**Parameters:**
- `encrypted_package` (dict): Encrypted data package

**Returns:** `True` if valid, raises `ValueError` if invalid

#### `get_file_metadata(encrypted_package)`
Extracts metadata from an encrypted package without decryption.

**Parameters:**
- `encrypted_package` (dict): Encrypted data package

**Returns:** Metadata dictionary (filename, size, hash algorithm)

## Security Considerations

### Strengths
- ✅ **4096-bit RSA**: Strong resistance to factorization attacks
- ✅ **256-bit AES**: Military-grade symmetric encryption
- ✅ **GCM Mode**: Authenticated encryption preventing tampering
- ✅ **PSS Signature**: Probabilistic signatures prevent forgery
- ✅ **PBKDF2**: 100,000 iterations resist dictionary attacks
- ✅ **Per-file Uniqueness**: New keys/IVs/salts generated for each operation

### Best Practices
1. **Use Strong Passphrases**: Minimum 16 characters with mixed case, numbers, and symbols
2. **Protect Private Keys**: Keep private key files in secure locations
3. **Secure Channel**: Distribute public keys through a trusted channel
4. **Key Rotation**: Periodically regenerate key pairs
5. **Backup**: Securely backup encrypted private keys
6. **Audit**: Log all encryption/decryption operations

### Limitations
- File size is limited by available memory (entire file loaded into memory)
- Passphrase-based private key encryption requires secure passphrase management
- No built-in key revocation mechanism

## Error Handling

The system provides detailed error messages for security failures:

```python
try:
    plaintext = decrypt_file(encrypted, priv_key, pub_key)
except ValueError as e:
    if "Signature verification failed" in str(e):
        print("Authenticity check failed - possible tampering detected")
    elif "Authentication tag verification failed" in str(e):
        print("Ciphertext integrity check failed")
    elif "Passphrase may be incorrect" in str(e):
        print("Private key decryption failed - wrong passphrase")
```

## Performance Metrics

Typical performance on modern hardware:
- **RSA-4096 Key Generation**: 5-15 seconds per keypair
- **AES-256-GCM Encryption**: ~100-200 MB/s for small files
- **RSA-4096-PSS Signature**: ~1-2 seconds per file
- **PBKDF2 Key Derivation**: ~0.5-1 second (100,000 iterations)

## Testing

Run the comprehensive demonstration:

```bash
python examples/demo.py
```

This tests:
- ✓ Key generation with encryption
- ✓ File encryption with AES-256-GCM
- ✓ Session key encryption with RSA-4096-OAEP
- ✓ Signature generation with RSA-4096-PSS
- ✓ File decryption with full verification
- ✓ Tampering detection

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [NIST SP 800-132 - PBKDF2](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
- [RFC 3394 - AES Key Wrap](https://tools.ietf.org/html/rfc3394)
- [RFC 8017 - PKCS #1: RSA](https://tools.ietf.org/html/rfc8017)
- [NIST SP 800-38D - GCM Mode](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

## Contributing

Contributions are welcome! Please ensure:
- Code follows PEP 8 style guidelines
- All functions include docstrings
- Security considerations are documented
- Tests pass for all cryptographic operations

## Support

For issues, questions, or suggestions, please open an issue in the repository.

---

**Security Notice**: This system is designed with strong cryptographic principles, but no system is 100% secure. Always follow security best practices, keep software updated, and use in conjunction with other security measures appropriate for your use case.
