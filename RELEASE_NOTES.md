# Release Notes: DB-Backed Multi-User GUI & Documentation Updates

## Summary
Refactored the Hybrid Cryptography System GUI to support multi-user workflows via SQLite-backed authentication and key management. Removed CLI/`app.py` references and simplified documentation to reflect the new architecture.

## Major Changes

### GUI Architecture
- **Login / Register Tab**: New authentication tab replacing Key Management. Users register with a username/passphrase; registration generates per-user RSA-4096 keypairs under `./keys/<username>/` and stores paths in a local SQLite database.
- **DB-Backed Key Lookup**: Encrypt & Decrypt tabs now use comboboxes populated from the database instead of manual file path entry.
- **Automatic Key Resolution**: Decrypt tab automatically looks up sender public key via username or extracts embedded key from encrypted package.
- **Per-User Encryption**: Encrypt tab requires login; sender private key is derived from the logged-in user state.

### Database Integration
- **New Module**: `crypto_engine/db_manager.py` — Minimal SQLite manager for user registration, passphrase verification (PBKDF2-HMAC-SHA256), and key path lookups.
- **Key Storage**: Public keys are read on-demand from PEM files; private key paths and passphrases are securely managed in-memory after login.

### Documentation
- **Removed**: All CLI (`app.py`), Click dependency, and role-based key generation instructions.
- **Updated**: README, QUICKSTART, TECHNICAL_OVERVIEW, and DELIVERABLES to reflect GUI-first workflow and per-user key organization.
- **Dependencies**: Removed `click>=7.0` from `requirements.txt`.

### Code Cleanup
- Removed Key Management tab from GUI.
- Updated docstrings and comments to reference Login/Register instead of Key Management.
- Simplified project structure descriptions (sender/receiver role dirs → per-username dirs).

## Migration Guide (for users)

### From CLI to GUI
- **Old**: `python app.py generate-keys --output ./keys --role sender`  
- **New**: Launch GUI, click Login/Register tab, click "Register", enter username and passphrase.

### From Manual Key Paths to Database
- **Old**: Browse for receiver's public key PEM file manually on Encrypt tab.  
- **New**: Select receiver from combobox (populated from DB on login).

### Per-User Key Organization
- **Old**: Keys stored under `./keys/sender/` and `./keys/receiver/`.  
- **New**: Keys stored under `./keys/<username>/`.

## Technical Details

### New Database Schema
```sql
CREATE TABLE users (
    username TEXT PRIMARY KEY,
    salt BLOB,
    passphrase_hash BLOB,
    private_key_path TEXT,
    public_key_path TEXT
);
```

### Encryption & Decryption (unchanged)
- Core cryptography remains identical: AES-256-GCM, RSA-4096-OAEP, RSA-4096-PSS, PBKDF2-SHA256.
- Sender public key is embedded (Base64) in encrypted packages for seamless verification.
- All binary fields are Base64-encoded for JSON safety.

## Testing
- GUI registration creates per-user directories and DB entries.
- Encrypt tab combobox auto-populates from DB after login.
- Decrypt tab can resolve sender public key via username lookup or embedded package key.
- Passphrase prompts required for signing and decryption operations.

## Files Modified
- `crypto_engine/gui_app.py` – Major refactor (DB integration, Login/Register tab, comboboxes).
- `crypto_engine/db_manager.py` – New file.
- `README.md`, `QUICKSTART.md`, `TECHNICAL_OVERVIEW.md`, `DELIVERABLES.md` – Documentation updates.
- `requirements.txt` – Removed Click.

## Breaking Changes
- **Key Organization**: Existing keys under `./keys/sender/` and `./keys/receiver/` should be manually migrated to `./keys/<username>/` if continuing to use them programmatically.
- **CLI Removed**: `app.py` and all Click-based commands are no longer available; use GUI or Python API.

## Backward Compatibility
- Core `crypto_engine/hybrid_crypto.py` functions remain unchanged.
- Python API is fully compatible with existing scripts.
- Encrypted packages from previous versions can still be decrypted (sender public key can be provided manually or embedded).

## Future Enhancements
- Integration with external LDAP/OAuth for multi-environment deployments.
- Key expiration and rotation policies.
- Public key server for key distribution across teams.
- Audit logging for encryption/decryption operations.
