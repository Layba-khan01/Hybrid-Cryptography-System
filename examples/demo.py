"""Simple demo of hybrid cryptography system"""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from crypto_engine import *

def main():
    print("="*80)
    print("HYBRID CRYPTOGRAPHY SYSTEM - DEMONSTRATION")
    print("="*80)
    print()
    
    keys_dir = Path("./keys")
    examples_dir = Path("./examples")
    keys_dir.mkdir(exist_ok=True)
    examples_dir.mkdir(exist_ok=True)
    
    print("[STEP 1] Generating RSA-4096 Key Pairs")
    print("-"*80)
    sender_keys = generate_rsa_keypair("sender_pass", output_dir=str(keys_dir/"sender"))
    print("[OK] Sender keys generated")
    receiver_keys = generate_rsa_keypair("receiver_pass", output_dir=str(keys_dir/"receiver"))
    print("[OK] Receiver keys generated")
    print()
    
    print("[STEP 2] Creating Sample File")
    print("-"*80)
    sample_file = examples_dir / "sample_message.txt"
    plaintext = "SECRET MESSAGE: Hybrid cryptography system test"
    with open(sample_file, "w", encoding="utf-8") as f:
        f.write(plaintext)
    print(f"[OK] File created: {len(plaintext)} bytes")
    print()
    
    print("[STEP 3] ENCRYPTION")
    print("-"*80)
    encrypted = encrypt_file(str(sample_file), receiver_keys['public_key_pem'].encode(), sender_keys['private_key_pem'].encode())
    encrypted_file = examples_dir / "message_encrypted.json"
    save_encrypted_file(encrypted, str(encrypted_file))
    print("[OK] Encryption successful")
    print()
    
    print("[STEP 4] DECRYPTION")
    print("-"*80)
    receiver_priv = load_private_key(receiver_keys['private_key_file'], "receiver_pass")
    loaded_pkg = load_encrypted_file(str(encrypted_file))
    decrypted = decrypt_file(loaded_pkg, receiver_priv, sender_keys['public_key_pem'].encode())
    decrypted_file = examples_dir / "message_decrypted.txt"
    with open(decrypted_file, "wb") as f:
        f.write(decrypted)
    print("[OK] Decryption successful")
    print()
    
    print("DECRYPTED MESSAGE:")
    print("-"*80)
    print(decrypted.decode("utf-8"))
    print("-"*80)
    print()
    
    if decrypted.decode("utf-8") == plaintext:
        print("[OK] SUCCESS: Messages match perfectly!")
    else:
        print("[FAIL] Messages do not match!")
    print()
    print("="*80)
    print("DEMONSTRATION COMPLETE")
    print("="*80)

if __name__ == "__main__":
    main()
