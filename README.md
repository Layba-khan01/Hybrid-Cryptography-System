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

## Project Structure (short)

```
Hybrid-Cryptography-System/
├── crypto_engine/
│   ├── __init__.py
│   ├── hybrid_crypto.py              # Core engine (Base64 encoding)
│   └── gui_app.py                    # Tkinter GUI application
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
├── app.py                            # (Removed - use GUI instead)
├── requirements.txt                  # Dependencies
├── README.md                         # This file
├── TECHNICAL_OVERVIEW.md             # Cryptographic specifications
├── QUICKSTART.md                     # Getting started guide
├── DELIVERABLES.md                   # Requirements checklist
├── LICENSE                           # MIT License
└── .gitignore                        # Git configuration
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

3. (Optional) Install Tkinter (usually included with Python)

## Usage

### GUI (Graphical User Interface)

Launch the interactive Tkinter GUI application:

```bash
python -m crypto_engine.gui_app
```

**Features:**
- Tabbed interface: **Key Management**, **Encrypt & Share**, **Receive & Decrypt**
- Role-based keypair generation (sender/receiver)
- Secure passphrase prompts with masking
- File browser for easy file selection
- In-memory key loading for smooth workflows
- Real-time validation and security alerts
- "TAMPERING DETECTED" warnings on decryption failure

### Option 2: CLI (Command Line Interface)

The `app.py` CLI wrapper provides three simple commands: `generate-keys`, `encrypt`, and `decrypt`.

#### Generate Keys (with Role)
```powershell
# Generate keys for sender (prompts for passphrase)
python app.py generate-keys --output ./keys --role sender

# Generate keys for receiver
python app.py generate-keys --output ./keys --role receiver
```

Keys are automatically organized under `./keys/<role>/` for clean organization.

#### Encrypt a File
```powershell
# Encrypt a file (prompts for sender's passphrase)
python app.py encrypt `
  --plaintext-file examples/sample_message.txt `
  --receiver-public-key ./keys/receiver/public_key.pem `
  --sender-private-key ./keys/sender/private_key_encrypted.json `
  --output-file examples/message_encrypted.json
```

#### Decrypt a File
```powershell
# Decrypt a file (prompts for receiver's passphrase)
python app.py decrypt `
  --ciphertext-file examples/message_encrypted.json `
  --receiver-private-key ./keys/receiver/private_key_encrypted.json `
  --sender-public-key ./keys/sender/public_key.pem `
  --output-file examples/message_decrypted.txt
```

#### View Help
```powershell
python app.py --help
python app.py generate-keys --help
python app.py encrypt --help
python app.py decrypt --help
```

### Python API (Programmatic Access)

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

#### `encrypt_file(plaintext, receiver_public_key_pem, sender_private_key_pem, original_filename=None)`
Encrypts data (file path or raw bytes) using the hybrid protocol.

**Process:**
1. Load plaintext bytes (file or raw bytes) and detect file metadata
2. Generate random AES-256 session key (Ks)
3. Encrypt plaintext with AES-256-GCM → (C, IV, T)
4. Encrypt session key with RSA-4096-OAEP → (Ks_enc)
5. Sign ciphertext with RSA-4096-PSS → (Sig)
6. Include sender's public key (Base64) in package for seamless verification

**Parameters:**
- `plaintext` (str|bytes): File path or raw bytes to encrypt
- `receiver_public_key_pem` (bytes): Receiver's public key
- `sender_private_key_pem` (bytes): Sender's private key
- `original_filename` (str, optional): Override metadata filename

**Returns:** Dictionary containing encrypted package with all binary fields Base64-encoded

**Supported File Types:** Text (.txt, .md, .json, .xml, .csv), images (.jpg, .png, .gif, .tiff, .webp), PDFs (.pdf), videos (.mp4, .avi, .mov, .mkv), audio (.mp3, .wav, .flac), archives (.zip, .rar, .7z), documents (.docx, .xlsx, .pptx), and any other binary file type.

#### `decrypt_file(encrypted_package, receiver_private_key_pem, sender_public_key_pem=None)`
Decrypts a file with full verification.

**Verification Process:**
1. Verify RSA-4096-PSS signature on ciphertext
2. Decrypt session key with RSA-4096-OAEP
3. Decrypt ciphertext with AES-256-GCM and verify authentication tag

**Parameters:**
- `encrypted_package` (dict): Encrypted data package (all binary fields Base64-encoded)
- `receiver_private_key_pem` (bytes): Receiver's private key
- `sender_public_key_pem` (bytes, optional): Sender's public key (auto-extracted from package if not provided)

**Returns:** Decrypted plaintext (bytes)

**Smart Key Extraction:** If `sender_public_key_pem` is not provided, the function automatically attempts to use the embedded `public_key_pem` field from the encrypted package (stored as Base64). This enables seamless verification workflows without requiring the sender's public key separately.

#### Encrypted Package Structure

The `encrypt_file()` function returns a dictionary with the following structure (all binary data is Base64-encoded for JSON serialization):

```json
{
  "ciphertext": "Base64-encoded AES-256-GCM ciphertext",
  "iv": "Base64-encoded initialization vector (16 bytes)",
  "auth_tag": "Base64-encoded GCM authentication tag (16 bytes)",
  "encrypted_session_key": "Base64-encoded RSA-4096-OAEP encrypted AES key",
  "signature": "Base64-encoded RSA-4096-PSS signature of ciphertext",
  "public_key_pem": "Base64-encoded sender public key (PEM format)",
  "algorithm": {
    "encryption": "AES-256-GCM",
    "key_exchange": "RSA-4096-OAEP",
    "signature": "RSA-4096-PSS"
  },
  "metadata": {
    "original_filename": "source_file.txt",
    "original_size": 1024,
    "file_type": "text",
    "extension": ".txt",
    "mime_type": "text/plain",
    "hash_algorithm": "SHA256"
  }
}
```

**Base64 Encoding Benefits:**
- ✅ JSON-compatible: Safe for transmission via APIs
- ✅ Human-readable: Easy to inspect and debug
- ✅ No encoding issues: Works seamlessly in databases and REST APIs
- ✅ Standard format: Compatible with any JSON-based system

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
