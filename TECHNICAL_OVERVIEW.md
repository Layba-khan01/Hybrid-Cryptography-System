# Hybrid Cryptography System - Technical Overview

## System Architecture

### Core Cryptographic Protocols

#### 1. **AES-256-GCM (Symmetric Encryption)**
- **Mode**: Galois/Counter Mode (GCM)
- **Key Size**: 256 bits
- **Nonce/IV**: 16 bytes (randomly generated per encryption)
- **Output Components**:
  - **C (Ciphertext)**: Encrypted plaintext
  - **IV (Initialization Vector)**: 128-bit nonce
  - **T (Authentication Tag)**: 128-bit authentication tag for GCM

**Why GCM?**
- Provides authenticated encryption (AEAD)
- Prevents tampering via authentication tag verification
- Parallelizable and efficient

#### 2. **RSA-4096-OAEP (Asymmetric Key Exchange)**
- **Key Size**: 4096 bits
- **Padding Scheme**: OAEP (Optimal Asymmetric Encryption Padding)
- **Hash Algorithm**: SHA-256
- **Purpose**: Encrypt AES session key with receiver's public key
- **Why OAEP?**
  - Resistant to padding oracle attacks
  - Provides semantic security
  - Recommended by NIST

#### 3. **RSA-4096-PSS (Digital Signatures)**
- **Key Size**: 4096 bits
- **Padding Scheme**: PSS (Probabilistic Signature Scheme)
- **Hash Algorithm**: SHA-256
- **Signed Data**: Ciphertext (C)
- **Output**: Digital signature for non-repudiation and authenticity

**Why PSS?**
- Probabilistic (randomized) for semantic security
- More resistant to attacks than PKCS#1 v1.5
- NIST/FIPS 186-4 compliant

#### 4. **PBKDF2-SHA256 (Key Derivation)**
- **Algorithm**: PBKDF2 (Password-Based Key Derivation Function 2)
- **Hash Function**: SHA-256
- **Iterations**: 100,000
- **Salt**: 16 bytes (randomly generated per derivation)
- **Output Key Length**: 32 bytes (256 bits for AES-256)

**Purpose**: Derive encryption key from user passphrase for private key storage

## Encryption Protocol Flow

### Step 1: Key Generation
```
User provides passphrase
    ↓
PBKDF2(passphrase, salt, 100k iterations, SHA256) → Master Key (32 bytes)
    ↓
Encrypt: AES-256-GCM(private_key_pem, master_key) → Encrypted Private Key
    ↓
Store: {iv, ciphertext, auth_tag, salt} → JSON file
```

### Step 2: File Encryption (Sender)
```
Plaintext File
    ↓
[1] Generate random session key (Ks): 32 bytes
    ↓
[2] Encrypt with AES-256-GCM
    Input: Plaintext + Session Key (Ks) + Random IV
    Output: Ciphertext (C), IV, Authentication Tag (T)
    ↓
[3] Encrypt session key with RSA-4096-OAEP
    Input: Session Key (Ks) + Receiver's Public Key
    Output: Encrypted Session Key (Ks_enc)
    ↓
[4] Sign ciphertext with RSA-4096-PSS
    Input: SHA256(Ciphertext) + Sender's Private Key
    Output: Signature (Sig)
    ↓
Package: {
    ciphertext: C (hex),
    iv: IV (hex),
    auth_tag: T (hex),
    encrypted_session_key: Ks_enc (hex),
    signature: Sig (hex),
    metadata: {filename, size, hash_algorithm}
}
```

### Step 3: File Decryption (Receiver)
```
Encrypted Package
    ↓
[1] VERIFY: RSA-4096-PSS Signature
    Input: Signature + Ciphertext + Sender's Public Key
    Action: Verify signature or REJECT
    ↓
[2] DECRYPT: RSA-4096-OAEP Session Key
    Input: Encrypted Session Key + Receiver's Private Key
    Output: Session Key (Ks) or FAIL
    ↓
[3] DECRYPT & VERIFY: AES-256-GCM Ciphertext
    Input: Ciphertext + IV + Session Key + Authentication Tag
    Action: Decrypt and verify tag or REJECT
    ↓
Output: Plaintext (if all verifications pass)
```

## File Structure

### `crypto_engine/hybrid_crypto.py`
Main cryptographic engine with 8 core functions:

1. **`derive_key_from_passphrase()`**
   - PBKDF2-SHA256 key derivation
   - Input: passphrase, salt (optional), key_length, iterations
   - Output: (derived_key, salt)

2. **`generate_rsa_keypair()`**
   - Generate 4096-bit RSA key pair
   - Encrypt private key with PBKDF2-derived key
   - Store as JSON with AES-256-GCM encryption
   - Output: Dictionary with file paths and PEM format

3. **`load_private_key()`**
   - Load encrypted private key from JSON
   - Decrypt using passphrase-derived key
   - Output: Decrypted private key (bytes)

4. **`encrypt_file()`**
   - Full hybrid encryption protocol
   - Input: plaintext_path, receiver_public_key, sender_private_key
   - Output: Encrypted package dictionary

5. **`decrypt_file()`**
   - Full hybrid decryption with verification
   - Input: encrypted_package, receiver_private_key, sender_public_key
   - Output: Plaintext (bytes) or raises ValueError on verification failure

6. **`save_encrypted_file()`**
   - Serialize encrypted package to JSON file
   - Output: File path

7. **`load_encrypted_file()`**
   - Load encrypted package from JSON file
   - Output: Encrypted package dictionary

8. **`get_file_metadata()`** & **`verify_package_integrity()`**
   - Utility functions for package inspection

### `examples/demo.py`
Comprehensive demonstration script showing:
- RSA keypair generation for sender and receiver
- File encryption with full hybrid protocol
- File decryption with verification
- Tampering detection test
- Metadata extraction

## Security Properties

### Confidentiality
- **AES-256-GCM**: Only receiver with private key can decrypt
- **Session Key Encryption**: Session key protected by RSA-4096
- **Per-file Randomness**: New key, IV, salt for each operation

### Authenticity & Integrity
- **GCM Authentication Tag**: Detects any ciphertext tampering
- **RSA-PSS Signature**: Proves message from sender
- **Signature Verification**: Required before decryption

### Non-repudiation
- **Sender's Private Key Signature**: Sender cannot deny encryption
- **Sender's Public Key Verification**: Receiver verifies sender identity

### Key Security
- **PBKDF2 Derivation**: Resists dictionary/brute-force attacks
- **100,000 Iterations**: ~500ms computation per derivation
- **16-byte Salt**: Ensures uniqueness

## Threat Protection

| Threat | Protection |
|--------|-----------|
| Eavesdropping | AES-256-GCM encryption |
| Tampering | GCM authentication tag |
| Forgery | RSA-PSS digital signature |
| Brute-force | PBKDF2 with 100k iterations |
| Replay attacks | New nonce/IV per message |
| Key recovery | 4096-bit RSA + PBKDF2 |

## Performance Characteristics

### Time Complexity
- RSA-4096 Keypair: 5-15 seconds
- RSA-4096-PSS Sign: 1-2 seconds
- RSA-4096-OAEP Encrypt: ~10-50ms
- PBKDF2 Derivation: 0.5-1 second
- AES-256-GCM Encrypt: 100-200 MB/s (small files)

### Space Complexity
- RSA-4096 Private Key: ~3.3 KB (PEM format)
- RSA-4096 Public Key: ~0.9 KB (PEM format)
- Encrypted Package Overhead: ~512 bytes + encrypted session key
- Signature Size: 512 bytes (4096-bit RSA)

## Encryption Example Output

```json
{
  "ciphertext": "a1b2c3d4...",
  "iv": "deadbeef...",
  "auth_tag": "cafebabe...",
  "encrypted_session_key": "f00dba11...",
  "signature": "baadf00d...",
  "algorithm": {
    "encryption": "AES-256-GCM",
    "key_exchange": "RSA-4096-OAEP",
    "signature": "RSA-4096-PSS"
  },
  "metadata": {
    "original_filename": "document.pdf",
    "original_size": 102400,
    "hash_algorithm": "SHA256"
  }
}
```

## Error Handling

### Signature Verification Failure
```
Error: "Signature verification failed. Data may have been tampered with."
Cause: Message altered or wrong sender public key
Action: Reject decryption, investigate tampering
```

### Authentication Tag Verification Failure
```
Error: "Authentication tag verification failed. Ciphertext may be corrupted or tampered."
Cause: Ciphertext corrupted or wrong session key
Action: Reject decryption
```

### Passphrase Incorrect
```
Error: "Failed to decrypt private key. Passphrase may be incorrect."
Cause: Wrong passphrase provided
Action: Request correct passphrase
```

## Usage Pattern

```python
# 1. Generate keys once
sender_keys = generate_rsa_keypair("passphrase")
receiver_keys = generate_rsa_keypair("passphrase")

# 2. Exchange public keys
# (send sender_keys['public_key_pem'] and receiver_keys['public_key_pem'])

# 3. Sender encrypts
encrypted = encrypt_file(
    "document.txt",
    receiver_keys['public_key_pem'].encode(),
    sender_keys['private_key_pem'].encode()
)

# 4. Receiver decrypts
private_key = load_private_key(receiver_keys['private_key_file'], "passphrase")
plaintext = decrypt_file(
    encrypted,
    private_key,
    sender_keys['public_key_pem'].encode()
)
```

## Standards Compliance

- **PBKDF2**: RFC 2898, NIST SP 800-132
- **AES-GCM**: NIST SP 800-38D, FIPS 197
- **RSA-OAEP**: RFC 8017, FIPS 186-4
- **RSA-PSS**: RFC 8017, FIPS 186-4
- **SHA-256**: FIPS 180-4

## Limitations & Future Enhancements

### Current Limitations
1. Entire file loaded into memory
2. No streaming encryption for large files
3. Passphrase recovery not implemented
4. No key revocation system

### Potential Enhancements
1. Streaming cipher mode for large files
2. Certificate-based key distribution (X.509)
3. Key server integration
4. Hardware security module (HSM) support
5. Multi-recipient encryption

---

**Built with PyCryptodome** - A self-contained pure-Python implementation of cryptographic algorithms.
## Implementation Details and Function Reference

This section consolidates concrete implementation notes, function signatures and outputs to make `TECHNICAL_OVERVIEW.md` the single deep-dive reference for developers.

### Core Functions (signatures and behavior)

1. `derive_key_from_passphrase(passphrase: str, salt: Optional[bytes]=None, key_length: int=32, iterations: int=100000) -> Tuple[bytes, bytes]`
    - Derives a 32-byte key (default) using PBKDF2-HMAC-SHA256.
    - If `salt` is None a 16-byte random salt is generated.
    - Returns `(derived_key, salt)` where `derived_key` is bytes suitable for AES-256.

2. `generate_rsa_keypair(passphrase: str, key_size: int=4096, output_dir: str='./keys') -> Dict[str, str]`
    - Generates a 4096-bit RSA keypair.
    - Private key is encrypted with AES-256-GCM using a PBKDF2-derived key from the provided `passphrase`.
    - Stored output includes encrypted private key JSON and public key PEM file.
    - Returns dictionary with keys: `private_key_file`, `public_key_file`, `private_key_pem`, `public_key_pem`, `salt`.

3. `load_private_key(private_key_file: str, passphrase: str) -> bytes`
    - Loads the encrypted private key JSON, derives the AES key via PBKDF2, decrypts the private key with AES-256-GCM and returns the private key bytes (PEM).

4. `encrypt_file(plaintext_path: str, receiver_public_key_pem: bytes, sender_private_key_pem: bytes) -> Dict[str, Any]`
    - Implements the hybrid protocol:
      - Generate random 32-byte session key Ks
      - AES-256-GCM encrypt plaintext → ciphertext (hex), iv (hex), auth_tag (hex)
      - RSA-4096-OAEP encrypt session key → encrypted_session_key (hex)
      - RSA-4096-PSS sign ciphertext → signature (hex)
    - Returns JSON-serializable dictionary with fields: `ciphertext`, `iv`, `auth_tag`, `encrypted_session_key`, `signature`, `algorithm`, `metadata`.

5. `decrypt_file(encrypted_package: Dict[str, Any], receiver_private_key_pem: bytes, sender_public_key_pem: bytes) -> bytes`
    - Verification-first decryption flow:
      - Verify RSA-PSS signature against ciphertext using `sender_public_key_pem`. If verification fails, raise `ValueError("Signature verification failed")`.
      - Decrypt encrypted session key using RSA-OAEP with `receiver_private_key_pem`.
      - Decrypt ciphertext with AES-256-GCM using the session key, iv and auth_tag. If tag verification fails raise `ValueError("Authentication tag verification failed")`.
      - Return plaintext bytes on success.

6. Utility functions: `save_encrypted_file()`, `load_encrypted_file()`, `get_file_metadata()`, `verify_package_integrity()`

### File Formats

- Encrypted private key JSON: `{ "iv": ..., "ciphertext": ..., "auth_tag": ..., "salt": ..., "algorithm": "AES-256-GCM" }`
- Encrypted package: fields described in `encrypt_file()` above; binary blobs are hex-encoded for JSON portability.

### Testing and Demonstration

- The `examples/demo.py` (or `examples/run_full_protocol_demo.py` for an alternate runner) scripts exercise the full flow: key generation, sample plaintext creation, encryption, decryption, tamper test, and verification outputs.
- The demo asserts plaintext equality after decrypting and demonstrates explicit handling of signature failures and GCM tag failures.

### Performance Notes

- RSA-4096 key generation dominates runtime for one-time setup (5–15s typical). Consider generating keys offline.
- PBKDF2 with 100k iterations is intentionally slowed to resist brute-force; tune only with awareness of security trade-offs.

### Code Quality and Security Practices (summary)

- Clear separation of responsibilities (KDF, key storage, encryption, verification).
- Defensive programming: all verification steps raise descriptive exceptions; plaintext never returned if any verification fails.
- Use of hex-encoding for JSON portability; binary-safe storage recommended for production (e.g., base64 or binary blobs in a secure store).

---

## CLI Interface (app.py)

The system provides a command-line wrapper built with the Click framework for user-friendly interaction without direct Python programming.

### Command Structure

```
python app.py COMMAND [OPTIONS]
python app.py --help              # Show all commands
```

### Commands and Options

#### 1. generate-keys
Generates an RSA-4096 keypair and saves it (encrypted with passphrase) to disk.

**Usage:**
```bash
python app.py generate-keys --output ./keys --role sender
```

**Options:**
- `--output` (Required): Directory where keypair will be stored
- `--role` (Required): One of `sender` or `receiver`
- `--passphrase`: Interactive prompt for passphrase (hidden input, confirmation required)

**Output:**
- Creates subdirectory: `./keys/{role}/`
- Files: `private_key_encrypted.json`, `public_key.pem`

**Error Handling:**
- Exit code 1: Invalid directory or permission denied
- Exit code 2: Unexpected system error

---

#### 2. encrypt
Encrypts a plaintext file using hybrid encryption (AES-256-GCM + RSA-4096-OAEP + RSA-4096-PSS signatures).

**Usage:**
```bash
python app.py encrypt \
  --plaintext-file examples/sample_message.txt \
  --receiver-public-key ./keys/receiver/public_key.pem \
  --sender-private-key ./keys/sender/private_key_encrypted.json \
  --output-file examples/message_encrypted.json
```

**Options:**
- `--plaintext-file` (Required): Path to file containing message to encrypt
- `--receiver-public-key` (Required): Path to receiver's public key (PEM format)
- `--sender-private-key` (Required): Path to sender's encrypted private key (JSON)
- `--output-file` (Required): Where to save encrypted package (JSON)
- `--passphrase`: Interactive prompt for sender's private key passphrase (hidden input)

**Output:**
- JSON file containing: `ciphertext`, `iv`, `auth_tag`, `encrypted_key`, `signature`
- All binary data hex-encoded for JSON portability

**Error Handling:**
- Exit code 1: File I/O error, key format error
- Exit code 2: Key import failed
- Exit code 3: Should not occur during encryption (validation only)

---

#### 3. decrypt
Decrypts a ciphertext file and verifies sender's signature and data authenticity.

**Usage:**
```bash
python app.py decrypt \
  --ciphertext-file examples/message_encrypted.json \
  --receiver-private-key ./keys/receiver/private_key_encrypted.json \
  --sender-public-key ./keys/sender/public_key.pem \
  --output-file examples/message_decrypted.txt
```

**Options:**
- `--ciphertext-file` (Required): Path to encrypted package (JSON)
- `--receiver-private-key` (Required): Path to receiver's encrypted private key (JSON)
- `--sender-public-key` (Required): Path to sender's public key (PEM)
- `--output-file` (Required): Where to save decrypted message
- `--passphrase`: Interactive prompt for receiver's private key passphrase (hidden input)

**Output:**
- Plaintext file with decrypted message

**Error Handling:**
- Exit code 1: File I/O error, key format error, invalid JSON
- Exit code 2: Key import failed
- Exit code 3: **Critical tamper detection** — Raised when:
  - RSA-PSS signature verification fails (sender authentication failed)
  - AES-256-GCM authentication tag verification fails (data was modified)
  - Message: `ERROR: Data Tampered or Invalid Signature!`

---

### Passphrase Handling

**Security Features:**
- Passphrases entered interactively are hidden from terminal display (no echo)
- No passphrase arguments accepted on command line (prevents shell history exposure)
- Confirmation required on `generate-keys` to prevent typos
- Passphrases are never logged or displayed in error messages

**Workflow:**
```bash
$ python app.py encrypt --plaintext-file msg.txt --receiver-public-key bob_pub.pem --sender-private-key alice_priv.json --output-file out.json
Enter passphrase (for alice_priv.json): <hidden>
Encrypting...
Done!
```

---

### Exit Codes

| Code | Meaning | Common Causes |
|------|---------|---------------|
| 0 | Success | Operation completed without errors |
| 1 | General error | File not found, invalid format, permission denied, I/O error |
| 2 | Import/key error | Private key passphrase incorrect, corrupted key file, invalid PEM |
| 3 | Tampering detected | Signature verification failed OR authentication tag mismatch |

---

### Integration with Python API

The CLI commands call the same underlying `crypto_engine` functions as direct Python code:
- `generate_keys()` → `generate_rsa_keypair()`
- `encrypt()` → `load_private_key()` + `encrypt_file()` + `save_encrypted_file()`
- `decrypt()` → `load_private_key()` + `load_encrypted_file()` + `decrypt_file()`

---

For more concrete examples and usage patterns, consult `examples/demo.py` and the `crypto_engine/hybrid_crypto.py` docstrings.
