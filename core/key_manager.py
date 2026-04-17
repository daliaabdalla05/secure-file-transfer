from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import sqlite3
import os

class KeyManager:
    KEY_SIZE = 32
    SALT_SIZE = 16
    PBKDF2_ITERATIONS = 200_000

    def __init__(self, db_path: str = 'database/keys.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Creates the keys table if it doesn't exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS keys (
                    key_id TEXT PRIMARY KEY,
                    salt BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

    def generate_key(self) -> bytes:
        """Generates a random 256-bit key."""
        return get_random_bytes(self.KEY_SIZE)

    def derive_key_from_password(self, password: str, salt: bytes = None):
        """Derives a key from a password using PBKDF2. Returns (key, salt)."""
        if salt is None:
            salt = get_random_bytes(self.SALT_SIZE)
        key = PBKDF2(password, salt, dkLen=self.KEY_SIZE,
                     count=self.PBKDF2_ITERATIONS, prf=None)
        return key, salt

    def store_key_salt(self, key_id: str, salt: bytes):
        """Stores a key's salt in the database (never store the key itself)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                'INSERT OR REPLACE INTO keys (key_id, salt) VALUES (?, ?)',
                (key_id, salt)
            )

    def retrieve_salt(self, key_id: str) -> bytes:
        """Retrieves the salt for a given key ID."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                'SELECT salt FROM keys WHERE key_id = ?', (key_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"No key found with ID: {key_id}")
        return row[0]