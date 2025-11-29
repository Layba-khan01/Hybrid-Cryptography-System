"""
Hybrid Cryptography System Package
Secure AES-256-GCM encryption with RSA-4096-OAEP key exchange and RSA-4096-PSS signatures
"""

from .hybrid_crypto import (
    derive_key_from_passphrase,
    generate_rsa_keypair,
    load_private_key,
    encrypt_file,
    decrypt_file,
    save_encrypted_file,
    load_encrypted_file,
    get_file_metadata,
    verify_package_integrity
)

__version__ = "1.0.0"
__author__ = "Hybrid Cryptography System"

__all__ = [
    'derive_key_from_passphrase',
    'generate_rsa_keypair',
    'load_private_key',
    'encrypt_file',
    'decrypt_file',
    'save_encrypted_file',
    'load_encrypted_file',
    'get_file_metadata',
    'verify_package_integrity'
]
