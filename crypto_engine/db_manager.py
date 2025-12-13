"""Simple DBManager for user registration, authentication and key lookup.

This is a minimal, secure-enough implementation to support the GUI integration.

API provided:
- DBManager(db_path)
- register_user(username, passphrase, private_key_path, public_key_path)
- get_user_data(username) -> dict
- verify_passphrase(username, passphrase) -> bool
- get_all_usernames() -> list[str]
- get_public_key_by_username(username) -> bytes (reads PEM file)

Note: For production use, harden this (encryption at rest, secure backup, better key storage).
"""
import os
import sqlite3
import hashlib
import hmac
from typing import Optional, List


class DBManager:
    def __init__(self, db_path: str = "user_data/app.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._ensure_tables()

    def _ensure_tables(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                pass_salt BLOB NOT NULL,
                pass_hash BLOB NOT NULL,
                private_key_path TEXT,
                public_key_path TEXT
            )
            """
        )
        self.conn.commit()

    def _derive(self, passphrase: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'), salt, 100000, dklen=32)

    def register_user(self, username: str, passphrase: str, private_key_path: str, public_key_path: str):
        """Register or update a user record."""
        if not username:
            raise ValueError("username required")
        salt = os.urandom(16)
        ph = self._derive(passphrase, salt)
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO users (username, pass_salt, pass_hash, private_key_path, public_key_path) VALUES (?, ?, ?, ?, ?)",
            (username, salt, ph, private_key_path, public_key_path),
        )
        self.conn.commit()

    def get_user_data(self, username: str) -> Optional[dict]:
        cur = self.conn.cursor()
        cur.execute("SELECT username, private_key_path, public_key_path FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            return None
        return {"username": row[0], "private_key_path": row[1], "public_key_path": row[2]}

    def verify_passphrase(self, username: str, passphrase: str) -> bool:
        cur = self.conn.cursor()
        cur.execute("SELECT pass_salt, pass_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            return False
        salt, stored = row[0], row[1]
        derived = self._derive(passphrase, salt)
        return hmac.compare_digest(derived, stored)

    def get_all_usernames(self) -> List[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT username FROM users ORDER BY username COLLATE NOCASE")
        return [r[0] for r in cur.fetchall()]

    def get_public_key_by_username(self, username: str) -> Optional[bytes]:
        cur = self.conn.cursor()
        cur.execute("SELECT public_key_path FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            return None
        pub_path = row[0]
        if not pub_path:
            return None
        try:
            with open(pub_path, 'rb') as f:
                return f.read()
        except Exception:
            return None
