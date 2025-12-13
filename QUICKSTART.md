# Quick Start Guide

## Table of Contents
- [Installation](#installation)
- [GUI Quick Start](#gui-quick-start)
- [Python API Quick Start](#python-api-quick-start)
- [Running the Demo](#running-the-demo)
- [Troubleshooting](#troubleshooting)

## Installation

1. **Install Python 3.7+**
   ```bash
   python --version
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## GUI Quick Start (Easiest)

Launch the interactive Tkinter GUI:

```bash
python -m crypto_engine.gui_app
```

The GUI provides an intuitive tabbed interface:
- **Login / Register**: Create a username (generates per-user RSA keypair under `./keys/<username>/`) and login
- **Encrypt & Share**: Select a file, choose a receiver from the DB, and encrypt
- **Receive & Decrypt**: Load encrypted package, login as the receiver, and decrypt

All passphrases are securely prompted and masked from display.

## Python API Quick Start

For programmatic integration, use the Python API directly.

### Encrypt the File (API)

```python
# Step 3: Alice encrypts a message for Bob
print("Encrypting message...")
encrypted_msg = encrypt_file(
    plaintext_path="secret.txt",
    receiver_public_key_pem=bob_keys['public_key_pem'].encode(),
    sender_private_key_pem=alice_keys['private_key_pem'].encode()
)

# Step 4: Save encrypted message
from crypto_engine import save_encrypted_file
save_encrypted_file(encrypted_msg, "secret_encrypted.json")
```

### Decrypt the File (API)

```python
# Step 5: Bob decrypts the message
print("Decrypting message...")
bob_private_key = load_private_key(
    bob_keys['private_key_file'],
    passphrase="bob_secret_passphrase"
)

from crypto_engine import load_encrypted_file
encrypted_msg = load_encrypted_file("secret_encrypted.json")

decrypted = decrypt_file(
    encrypted_package=encrypted_msg,
    receiver_private_key_pem=bob_private_key,
    sender_public_key_pem=alice_keys['public_key_pem'].encode()
)

print("Decrypted message:", decrypted.decode())
```

---

## Running the Demo

The fastest way to see the full system in action:

```bash
python examples/demo.py
```

This will:
- Generate RSA-4096 keys for sender and receiver
- Create a sample encrypted message
- Decrypt it and verify authenticity
- Demonstrate tampering detection

---

## What's Happening

### Encryption Process
```
```
Hybrid-Cryptography-System/
├── crypto_engine/
│   ├── __init__.py
│   ├── gui_app.py                       # Tkinter GUI application
│   └── hybrid_crypto.py                 # Core engine (Base64 encoding)
├── examples/
│   ├── demo.py                          # Main demonstration
│   ├── sample_message.txt               # Generated test message
│   ├── message_encrypted.json           # Generated encrypted package (Base64)
│   └── message_decrypted.txt            # Generated decrypted output
├── keys/                                # Generated at runtime (per-user directories)
│   ├── <username>/
│   │   ├── private_key_encrypted.json
│   │   └── public_key.pem
├── scripts/
│   └── cleanup_docs_and_keys.ps1        # Repository cleanup utility
├── requirements.txt                     # Dependencies (pycryptodomex)
├── README.md                            # Complete API documentation
├── TECHNICAL_OVERVIEW.md                # Cryptographic deep dive
├── QUICKSTART.md                        # This file
├── DELIVERABLES.md                      # Requirements checklist
└── LICENSE                              # MIT License
```
  "signature": "OTvD84PuADKfWakYib7N9OlnW9xp...",
  "public_key_pem": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K...",
  "algorithm": {
    "encryption": "AES-256-GCM",
    "key_exchange": "RSA-4096-OAEP",
    "signature": "RSA-4096-PSS"
  },
  "metadata": {
    "original_filename": "document.txt",
    "original_size": 1024,
    "file_type": "text",
    "extension": ".txt",
    "mime_type": "text/plain",
    "hash_algorithm": "SHA256"
  }
}
```

**Why Base64?** Binary data needs encoding for JSON serialization. Base64 is URL-safe, portable, and compatible with all APIs and databases.

**Embedded Sender Key:** The `public_key_pem` is included in the package (Base64-encoded), allowing automatic signature verification without requiring the sender's public key separately.


### Decryption Process
```
Encrypted Package
   ↓
Verify RSA-PSS signature (Alice's public key) ← Security check!
   ↓
Decrypt AES key with RSA-4096-OAEP (Bob's private key)
   ↓
Decrypt ciphertext with AES-256-GCM and verify auth tag ← Security check!
   ↓
Plaintext
```

## User Registration & Keys

Use the GUI `Login / Register` tab to create a username — registration will generate a per-user key directory under `./keys/<username>/` and store the private/public key paths in the local SQLite DB used by the GUI.

Programmatic access is still available via the Python API if needed. You can generate keys directly with `generate_rsa_keypair()` or load private keys with `load_private_key()`; registration via the GUI is recommended for multi-user workflows.

Example (programmatic key generation):
```python
from crypto_engine import generate_rsa_keypair

keys = generate_rsa_keypair(
   passphrase="your_secure_passphrase",
   key_size=4096,
   output_dir="./keys/your_username"
)
```

Load an encrypted private key programmatically:
```python
from crypto_engine import load_private_key

private_key = load_private_key(
   private_key_file="./keys/your_username/private_key_encrypted.json",
   passphrase="your_secure_passphrase"
)
```

## Sharing Public Keys

To communicate securely with someone:

1. **Generate your keypair** (keep private key secret!)
2. **Share your public key** (it's safe to distribute)
3. **Receive their public key** (verify authenticity if possible)
4. **Exchange encrypted messages**

## Security Best Practices

✅ **DO**
- Use strong passphrases (16+ characters, mixed case, symbols)
- Keep private key files secure
- Verify public keys through a trusted channel
- Use different passphrases for different keys
- Back up encrypted private keys

❌ **DON'T**
- Share or expose private keys
- Use weak passphrases
- Store passphrases in code
- Use the same passphrase for multiple keys
- Ignore verification errors

## Troubleshooting

### "ModuleNotFoundError: No module named 'Cryptodome'"
```bash
pip install -r requirements.txt
```

### "Signature verification failed"
- Verify you're using the correct sender's public key
- Check if the message has been tampered with
- Ensure the encryption/decryption was done correctly

### "Failed to decrypt private key. Passphrase may be incorrect"
- Double-check the passphrase
- Ensure you're using the correct encrypted key file
- Reset password by regenerating keys if necessary

### "Authentication tag verification failed"
- File may be corrupted
- Ciphertext may have been modified
- Wrong AES session key (shouldn't happen normally)

## File Structure After Running Demo

```
Hybrid-Cryptography-System/
├── crypto_engine/
│   ├── __init__.py
│   ├── gui_app.py                       # Tkinter GUI application
│   └── hybrid_crypto.py                 # Core engine (Base64 encoding)
├── examples/
│   ├── demo.py                          # Main demonstration
│   ├── sample_message.txt               # Generated test message
│   ├── message_encrypted.json           # Generated encrypted package (Base64)
│   └── message_decrypted.txt            # Generated decrypted output
├── keys/                                # Generated at runtime (per-user directories)
│   ├── <username>/
│   │   ├── private_key_encrypted.json
│   │   └── public_key.pem
├── scripts/
│   └── cleanup_docs_and_keys.ps1        # Repository cleanup utility
├── requirements.txt                     # Dependencies (pycryptodomex)
├── README.md                            # Complete API documentation
├── TECHNICAL_OVERVIEW.md                # Cryptographic deep dive
├── QUICKSTART.md                        # This file
├── DELIVERABLES.md                      # Requirements checklist
└── LICENSE                              # MIT License
```

**Note:** All binary data in encrypted packages is **Base64-encoded** for JSON serialization and API safety.

## Next Steps

1. **Read the README** for detailed API documentation
2. **Review TECHNICAL_OVERVIEW.md** for cryptographic details
3. **Modify demo.py** to test with your own files
4. **Integrate** into your application

## Testing Your Setup

Quick verification:

```python
import sys
sys.path.insert(0, '.')

from crypto_engine import derive_key_from_passphrase

# Test PBKDF2
key, salt = derive_key_from_passphrase("test_passphrase")
print(f"✓ Key derivation works: {len(key)} bytes")

# Test key replication
key2, _ = derive_key_from_passphrase("test_passphrase", salt=salt)
assert key == key2
print(f"✓ Key derivation is deterministic")

print("✓ System is ready!")
```

## Performance Tips

- **Key generation** takes 5-15 seconds (normal, don't interrupt)
- **Encrypting small files** is fast (< 100ms)
- **Signing** takes 1-2 seconds (RSA-PSS is cryptographically secure)
- **PBKDF2 derivation** takes ~0.5-1 second (security by design)

## Getting Help

- Check **README.md** for API reference
- Review **TECHNICAL_OVERVIEW.md** for cryptographic details
- Run **examples/demo.py** with verbose output
- Check error messages - they're descriptive!

## Example Output

```
================================================================================
HYBRID CRYPTOGRAPHY SYSTEM - DEMONSTRATION
================================================================================

[STEP 1] Generating RSA-4096 Key Pairs
...
✓ Sender's private key saved (encrypted)
✓ Receiver's private key saved (encrypted)

[STEP 2] Creating Sample Plaintext File
✓ Sample plaintext file created

[STEP 3] ENCRYPTION
✓ Encryption successful!

[STEP 4] DECRYPTION
✓ Decryption successful!
✓ Signature verification PASSED
✓ Authentication tag verification PASSED

[STEP 5] VERIFICATION
✓ SUCCESS: Decrypted message matches original plaintext exactly!
```

---

**You're ready to use the Hybrid Cryptography System!**
