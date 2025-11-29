"""
Hybrid Cryptography System - Core Engine
Implements AES-256-GCM, RSA-4096-OAEP, RSA-4096-PSS, and PBKDF2
"""

import os
import json
import base64
from typing import Tuple, Dict, Any, Optional
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Signature import pss
from Cryptodome.Random import get_random_bytes


# ============================================================================
# HELPER FUNCTION: PBKDF2 Key Derivation
# ============================================================================

def derive_key_from_passphrase(
    passphrase: str,
    salt: Optional[bytes] = None,
    key_length: int = 32,
    iterations: int = 100000
) -> Tuple[bytes, bytes]:
    """
    Derives a cryptographic key from a user passphrase using PBKDF2 with SHA256.
    
    Args:
        passphrase (str): User's passphrase for key derivation
        salt (bytes, optional): Unique salt for derivation. If None, generates a new one (16 bytes)
        key_length (int): Desired key length in bytes (default: 32 for AES-256)
        iterations (int): Number of PBKDF2 iterations (default: 100000 for security)
    
    Returns:
        Tuple[bytes, bytes]: (derived_key, salt) - The derived key and the salt used
    
    Raises:
        ValueError: If passphrase is empty or invalid
    """
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    
    # Generate salt if not provided
    if salt is None:
        salt = get_random_bytes(16)
    
    # Derive key using PBKDF2 with SHA256
    derived_key = PBKDF2(
        password=passphrase,
        salt=salt,
        dkLen=key_length,
        count=iterations,
        hmac_hash_module=SHA256
    )
    
    return derived_key, salt


# ============================================================================
# RSA KEY PAIR GENERATION WITH ENCRYPTED STORAGE
# ============================================================================

def generate_rsa_keypair(
    passphrase: str,
    key_size: int = 4096,
    output_dir: str = "./keys"
) -> Dict[str, str]:
    """
    Generates a 4096-bit RSA key pair and securely stores the private key.
    
    The private key is encrypted using AES-256-GCM with a PBKDF2-derived key
    from the user's passphrase. The public key is stored in plain PEM format.
    
    Args:
        passphrase (str): User's passphrase for encrypting the private key
        key_size (int): RSA key size in bits (default: 4096)
        output_dir (str): Directory to store key files
    
    Returns:
        Dict[str, str]: Dictionary containing:
            - 'private_key_pem': Encrypted private key (PEM format, then encrypted)
            - 'public_key_pem': Public key in PEM format
            - 'private_key_file': Path to encrypted private key file
            - 'public_key_file': Path to public key file
            - 'salt': Base64-encoded salt used for PBKDF2 (stored with encrypted key)
    
    Raises:
        ValueError: If passphrase is empty
        OSError: If output directory cannot be created or written to
    """
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate RSA key pair
    key = RSA.generate(key_size)
    
    # Export keys to PEM format
    private_key_pem = key.export_key(format='PEM')
    public_key_pem = key.publickey().export_key(format='PEM')
    
    # Derive encryption key from passphrase
    encryption_key, salt = derive_key_from_passphrase(passphrase)
    
    # Encrypt the private key using AES-256-GCM
    iv = get_random_bytes(16)
    cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=iv)
    ciphertext, auth_tag = cipher.encrypt_and_digest(private_key_pem)
    
    # Package encrypted private key with IV, salt, and auth tag
    encrypted_key_data = {
        'iv': iv.hex(),
        'ciphertext': ciphertext.hex(),
        'auth_tag': auth_tag.hex(),
        'salt': salt.hex(),
        'algorithm': 'AES-256-GCM'
    }
    
    # Save encrypted private key to file
    private_key_file = os.path.join(output_dir, "private_key_encrypted.json")
    with open(private_key_file, 'w') as f:
        json.dump(encrypted_key_data, f, indent=2)
    
    # Save public key to file
    public_key_file = os.path.join(output_dir, "public_key.pem")
    with open(public_key_file, 'wb') as f:
        f.write(public_key_pem)
    
    return {
        'private_key_pem': private_key_pem.decode('utf-8'),
        'public_key_pem': public_key_pem.decode('utf-8'),
        'private_key_file': private_key_file,
        'public_key_file': public_key_file,
        'salt': salt.hex()
    }


def load_private_key(
    private_key_file: str,
    passphrase: str
) -> bytes:
    """
    Loads and decrypts a private key from an encrypted file.
    
    Args:
        private_key_file (str): Path to the encrypted private key JSON file
        passphrase (str): User's passphrase for decryption
    
    Returns:
        bytes: Decrypted private key in PEM format
    
    Raises:
        ValueError: If passphrase is incorrect or file is corrupted
        FileNotFoundError: If the key file doesn't exist
    """
    # Load encrypted key data from file
    with open(private_key_file, 'r') as f:
        encrypted_key_data = json.load(f)
    
    # Extract components
    iv = bytes.fromhex(encrypted_key_data['iv'])
    ciphertext = bytes.fromhex(encrypted_key_data['ciphertext'])
    auth_tag = bytes.fromhex(encrypted_key_data['auth_tag'])
    salt = bytes.fromhex(encrypted_key_data['salt'])
    
    # Derive decryption key from passphrase and salt
    decryption_key, _ = derive_key_from_passphrase(passphrase, salt=salt)
    
    # Decrypt the private key
    cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=iv)
    try:
        private_key_pem = cipher.decrypt_and_verify(ciphertext, auth_tag)
    except ValueError as e:
        raise ValueError("Failed to decrypt private key. Passphrase may be incorrect.") from e
    
    return private_key_pem


# ============================================================================
# FILE ENCRYPTION: Full Hybrid Protocol
# ============================================================================

def encrypt_file(
    plaintext_path: str,
    receiver_public_key_pem: bytes,
    sender_private_key_pem: bytes
) -> Dict[str, Any]:
    """
    Encrypts a file using the full hybrid cryptography protocol:
    
    1. Generates a random AES-256 session key (Ks)
    2. Encrypts plaintext with AES-256-GCM (produces C, IV, T)
    3. Encrypts session key with RSA-4096-OAEP (produces Ks_enc)
    4. Signs the ciphertext with RSA-4096-PSS (produces Sig)
    
    Args:
        plaintext_path (str): Path to the file to encrypt
        receiver_public_key_pem (bytes): Receiver's public key in PEM format
        sender_private_key_pem (bytes): Sender's private key in PEM format
    
    Returns:
        Dict[str, Any]: Encrypted package containing:
            - 'ciphertext': Encrypted data (Base64-encoded)
            - 'iv': Initialization vector for AES-GCM (Base64-encoded)
            - 'auth_tag': GCM authentication tag (Base64-encoded)
            - 'encrypted_session_key': RSA-OAEP encrypted session key (Base64-encoded)
            - 'signature': RSA-PSS signature of ciphertext (Base64-encoded)
            - 'algorithm': Algorithm identifiers
            - 'metadata': File metadata
    
    Raises:
        FileNotFoundError: If plaintext file doesn't exist
        ValueError: If key files are invalid
    """
    # Read plaintext file
    if not os.path.exists(plaintext_path):
        raise FileNotFoundError(f"Plaintext file not found: {plaintext_path}")
    
    with open(plaintext_path, 'rb') as f:
        plaintext = f.read()
    
    # STEP 1: Generate random AES-256 session key (256-bit / 32 bytes)
    session_key = get_random_bytes(32)
    
    # STEP 2: Encrypt plaintext with AES-256-GCM
    iv = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=iv)
    ciphertext, auth_tag = cipher_aes.encrypt_and_digest(plaintext)
    
    # STEP 3: Encrypt session key with RSA-4096-OAEP using receiver's public key
    receiver_public_key = RSA.import_key(receiver_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(
        receiver_public_key,
        hashAlgo=SHA256
    )
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    
    # STEP 4: Sign the ciphertext with RSA-4096-PSS using sender's private key
    sender_private_key = RSA.import_key(sender_private_key_pem)
    hash_obj = SHA256.new(ciphertext)
    signature = pss.new(sender_private_key).sign(hash_obj)
    
    # Package the encrypted data (all binary data as Base64)
    encrypted_package = {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'auth_tag': base64.b64encode(auth_tag).decode('utf-8'),
        'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
        'signature': base64.b64encode(signature).decode('utf-8'),
        'algorithm': {
            'encryption': 'AES-256-GCM',
            'key_exchange': 'RSA-4096-OAEP',
            'signature': 'RSA-4096-PSS'
        },
        'metadata': {
            'original_filename': os.path.basename(plaintext_path),
            'original_size': len(plaintext),
            'hash_algorithm': 'SHA256'
        }
    }
    
    return encrypted_package


def save_encrypted_file(
    encrypted_package: Dict[str, Any],
    output_path: str
) -> str:
    """
    Saves an encrypted package to a JSON file.
    
    Args:
        encrypted_package (Dict[str, Any]): Encrypted data package from encrypt_file()
        output_path (str): Path where to save the encrypted file
    
    Returns:
        str: Path to the saved encrypted file
    """
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(encrypted_package, f, indent=2)
    return output_path


# ============================================================================
# FILE DECRYPTION: Full Hybrid Protocol with Verification
# ============================================================================

def decrypt_file(
    encrypted_package: Dict[str, Any],
    receiver_private_key_pem: bytes,
    sender_public_key_pem: bytes
) -> bytes:
    """
    Decrypts a file using the full hybrid cryptography protocol:
    
    1. Verifies the RSA-4096-PSS signature on the ciphertext
    2. Decrypts the session key with RSA-4096-OAEP using receiver's private key
    3. Decrypts ciphertext with AES-256-GCM and verifies authentication tag
    
    This function strictly checks both the PSS signature and GCM tag before
    releasing any plaintext data.
    
    Args:
        encrypted_package (Dict[str, Any]): Encrypted data package (from encrypt_file)
        receiver_private_key_pem (bytes): Receiver's private key in PEM format
        sender_public_key_pem (bytes): Sender's public key in PEM format
    
    Returns:
        bytes: Decrypted plaintext
    
    Raises:
        ValueError: If signature verification fails, tag verification fails, or decryption fails
    """
    # Extract components from encrypted package and decode from Base64
    ciphertext = base64.b64decode(encrypted_package['ciphertext'])
    iv = base64.b64decode(encrypted_package['iv'])
    auth_tag = base64.b64decode(encrypted_package['auth_tag'])
    encrypted_session_key = base64.b64decode(encrypted_package['encrypted_session_key'])
    signature = base64.b64decode(encrypted_package['signature'])
    
    # STEP 1: Verify RSA-PSS signature on ciphertext
    sender_public_key = RSA.import_key(sender_public_key_pem)
    hash_obj = SHA256.new(ciphertext)
    try:
        pss.new(sender_public_key).verify(hash_obj, signature)
    except ValueError as e:
        raise ValueError("Signature verification failed. Data may have been tampered with.") from e
    
    # STEP 2: Decrypt session key with RSA-OAEP using receiver's private key
    receiver_private_key = RSA.import_key(receiver_private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(
        receiver_private_key,
        hashAlgo=SHA256
    )
    try:
        session_key = cipher_rsa.decrypt(encrypted_session_key)
    except ValueError as e:
        raise ValueError("Failed to decrypt session key.") from e
    
    # STEP 3: Decrypt ciphertext with AES-GCM and verify authentication tag
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=iv)
    try:
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, auth_tag)
    except ValueError as e:
        raise ValueError("Authentication tag verification failed. Ciphertext may be corrupted or tampered.") from e
    
    return plaintext


def load_encrypted_file(
    encrypted_file_path: str
) -> Dict[str, Any]:
    """
    Loads an encrypted package from a JSON file.
    
    Args:
        encrypted_file_path (str): Path to the encrypted JSON file
    
    Returns:
        Dict[str, Any]: Encrypted data package
    
    Raises:
        FileNotFoundError: If the file doesn't exist
        json.JSONDecodeError: If the file is not valid JSON
    """
    if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")
    
    with open(encrypted_file_path, 'r') as f:
        encrypted_package = json.load(f)
    
    return encrypted_package


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_file_metadata(encrypted_package: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts metadata from an encrypted package without decryption.
    
    Args:
        encrypted_package (Dict[str, Any]): Encrypted data package
    
    Returns:
        Dict[str, Any]: Metadata including original filename and size
    """
    return encrypted_package.get('metadata', {})


def verify_package_integrity(encrypted_package: Dict[str, Any]) -> bool:
    """
    Verifies that an encrypted package has all required fields.
    
    Args:
        encrypted_package (Dict[str, Any]): Encrypted data package
    
    Returns:
        bool: True if all required fields are present
    
    Raises:
        ValueError: If required fields are missing
    """
    required_fields = [
        'ciphertext',
        'iv',
        'auth_tag',
        'encrypted_session_key',
        'signature',
        'algorithm',
        'metadata'
    ]
    
    missing_fields = [field for field in required_fields if field not in encrypted_package]
    
    if missing_fields:
        raise ValueError(f"Encrypted package missing required fields: {missing_fields}")
    
    return True
