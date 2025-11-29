#!/usr/bin/env python
"""
CLI wrapper for the Hybrid Cryptography System using Click framework.

Commands:
  - generate-keys: Generate RSA-4096 keypair with encrypted private key
  - encrypt: Encrypt a file using hybrid protocol (AES-256-GCM + RSA-4096-OAEP + RSA-4096-PSS)
  - decrypt: Decrypt and authenticate a ciphertext file
"""

import json
import sys
from pathlib import Path

import click

try:
    from crypto_engine import (
        generate_rsa_keypair,
        load_private_key,
        encrypt_file,
        decrypt_file,
        save_encrypted_file,
        load_encrypted_file,
    )
except ImportError as e:
    click.echo(f"ERROR: Failed to import crypto_engine: {e}", err=True)
    click.echo("Ensure the crypto_engine package is installed and accessible.", err=True)
    sys.exit(2)


@click.group()
def cli():
    """Hybrid Cryptography System CLI

    A production-grade CLI for secure file encryption and decryption using:
    - AES-256-GCM for authenticated encryption
    - RSA-4096-OAEP for session key exchange
    - RSA-4096-PSS for digital signatures
    - PBKDF2-SHA256 for passphrase-based key derivation
    """
    pass


@cli.command("generate-keys")
@click.option(
    "--passphrase",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="Passphrase to encrypt the private key."
)
@click.option(
    "--output",
    required=True,
    type=click.Path(file_okay=False, dir_okay=True, writable=True),
    help="Output directory where keys will be saved."
)
@click.option(
    "--role",
    required=True,
    type=click.Choice(["sender", "receiver"], case_sensitive=False),
    help="Role label for the generated keys (sender or receiver)."
)
def generate_keys(passphrase: str, output: str, role: str):
    """Generate an RSA-4096 key pair and store it encrypted.

    The private key is encrypted using a PBKDF2-derived key from the provided passphrase.
    Both the public key (PEM) and encrypted private key (JSON) are written to the output directory.
    """
    output_dir = Path(output) / role
    output_dir.mkdir(parents=True, exist_ok=True)

    click.echo(f"Generating RSA-4096 key pair for role '{role}'...")
    try:
        result = generate_rsa_keypair(passphrase=passphrase, output_dir=str(output_dir))
    except Exception as e:
        click.echo(f"ERROR: Key generation failed: {e}", err=True)
        sys.exit(1)

    click.echo("Keys generated successfully.")
    if isinstance(result, dict):
        pub_path = result.get("public_key_file") or result.get("public_key_pem")
        priv_path = result.get("private_key_file") or result.get("private_key_pem")
        if pub_path:
            click.echo(f"  Public key: {pub_path}")
        if priv_path:
            click.echo(f"  Encrypted private key: {priv_path}")


@cli.command("encrypt")
@click.option(
    "--plaintext-file",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to the plaintext file to encrypt."
)
@click.option(
    "--receiver-public-key",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to the receiver's public key (PEM format)."
)
@click.option(
    "--sender-private-key",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to the sender's encrypted private key (JSON format)."
)
@click.option(
    "--output-file",
    required=True,
    type=click.Path(file_okay=True, dir_okay=False, writable=True),
    help="Path to write the encrypted package (JSON)."
)
@click.option(
    "--passphrase",
    prompt=True,
    hide_input=True,
    help="Sender's passphrase to decrypt their private key."
)
def encrypt(
    plaintext_file: str,
    receiver_public_key: str,
    sender_private_key: str,
    output_file: str,
    passphrase: str
):
    """Encrypt a file using the hybrid protocol.

    Process:
    1. Load sender's private key using the provided passphrase.
    2. Read the receiver's public key.
    3. Encrypt the plaintext using AES-256-GCM with a random session key.
    4. Encrypt the session key with RSA-4096-OAEP using the receiver's public key.
    5. Sign the ciphertext with RSA-4096-PSS using the sender's private key.
    6. Package and save as JSON.
    """
    click.echo("Starting encryption process...")

    # Load sender's private key
    try:
        click.echo(f"Loading sender's private key from: {sender_private_key}")
        sender_priv = load_private_key(sender_private_key, passphrase)
    except Exception as e:
        click.echo(f"ERROR: Failed to load sender private key: {e}", err=True)
        sys.exit(1)

    # Read receiver's public key
    try:
        with open(receiver_public_key, "rb") as f:
            receiver_pub = f.read()
    except Exception as e:
        click.echo(f"ERROR: Failed to read receiver public key: {e}", err=True)
        sys.exit(1)

    # Perform encryption
    try:
        click.echo(f"Encrypting file: {plaintext_file}")
        encrypted_pkg = encrypt_file(plaintext_file, receiver_pub, sender_priv)
    except Exception as e:
        click.echo(f"ERROR: Encryption failed: {e}", err=True)
        sys.exit(1)

    # Save the encrypted package
    try:
        click.echo(f"Saving encrypted package to: {output_file}")
        save_encrypted_file(encrypted_pkg, output_file)
    except Exception as e:
        click.echo(f"ERROR: Failed to save encrypted package: {e}", err=True)
        sys.exit(1)

    click.echo("Encryption successful.")
    click.echo(f"Output: {output_file}")


@cli.command("decrypt")
@click.option(
    "--ciphertext-file",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to the encrypted package file (JSON)."
)
@click.option(
    "--receiver-private-key",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to the receiver's encrypted private key (JSON format)."
)
@click.option(
    "--sender-public-key",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to the sender's public key (PEM format)."
)
@click.option(
    "--output-file",
    required=True,
    type=click.Path(file_okay=True, dir_okay=False, writable=True),
    help="Path to write the decrypted plaintext."
)
@click.option(
    "--passphrase",
    prompt=True,
    hide_input=True,
    help="Receiver's passphrase to decrypt their private key."
)
def decrypt(
    ciphertext_file: str,
    receiver_private_key: str,
    sender_public_key: str,
    output_file: str,
    passphrase: str
):
    """Decrypt and authenticate a ciphertext file.

    Process:
    1. Load the encrypted package from JSON.
    2. Load receiver's private key using the provided passphrase.
    3. Read the sender's public key.
    4. Verify the RSA-4096-PSS signature on the ciphertext.
    5. Decrypt the session key with RSA-4096-OAEP using receiver's private key.
    6. Decrypt the ciphertext with AES-256-GCM and verify the authentication tag.
    7. Save the plaintext if all verifications pass.

    CRITICAL: If decryption or authentication fails, output a clear error and exit with non-zero status.
    """
    click.echo("Starting decryption process...")

    # Load encrypted package
    try:
        click.echo(f"Loading encrypted package from: {ciphertext_file}")
        encrypted_pkg = load_encrypted_file(ciphertext_file)
    except Exception as e:
        click.echo(f"ERROR: Failed to load encrypted package: {e}", err=True)
        sys.exit(1)

    # Load receiver's private key
    try:
        click.echo(f"Loading receiver's private key from: {receiver_private_key}")
        receiver_priv = load_private_key(receiver_private_key, passphrase)
    except Exception as e:
        click.echo(f"ERROR: Failed to load receiver private key: {e}", err=True)
        sys.exit(1)

    # Read sender's public key
    try:
        with open(sender_public_key, "rb") as f:
            sender_pub = f.read()
    except Exception as e:
        click.echo(f"ERROR: Failed to read sender public key: {e}", err=True)
        sys.exit(1)

    # Decrypt with full verification
    try:
        click.echo("Decrypting and verifying package...")
        plaintext = decrypt_file(encrypted_pkg, receiver_priv, sender_pub)
    except ValueError as e:
        # Signature or authentication verification failed
        click.echo("ERROR: Data Tampered or Invalid Signature! Decryption aborted.", err=True)
        click.echo(f"Details: {e}", err=True)
        sys.exit(3)
    except Exception as e:
        click.echo(f"ERROR: Decryption failed: {e}", err=True)
        sys.exit(1)

    # Save plaintext
    try:
        click.echo(f"Saving plaintext to: {output_file}")
        with open(output_file, "wb") as f:
            if isinstance(plaintext, str):
                f.write(plaintext.encode("utf-8"))
            else:
                f.write(plaintext)
    except Exception as e:
        click.echo(f"ERROR: Failed to write plaintext: {e}", err=True)
        sys.exit(1)

    click.echo("Decryption successful.")
    click.echo(f"Output: {output_file}")


if __name__ == "__main__":
    cli()
