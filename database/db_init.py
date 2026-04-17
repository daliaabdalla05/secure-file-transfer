import sqlite3
import os

def init_database(db_path: str = 'database/app.db'):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:

        # Encryption keys table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                key_id TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # DLP policies table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS dlp_policies (
                policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_name TEXT NOT NULL,
                blocked_extensions TEXT,
                sensitive_patterns TEXT,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Audit log table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                operation TEXT NOT NULL,
                file_path TEXT,
                outcome TEXT NOT NULL,
                details TEXT
            )
        ''')

        # Sharing links table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sharing_links (
                token TEXT PRIMARY KEY,
                file_path TEXT NOT NULL,
                expiry TIMESTAMP NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Insert default DLP policy if none exist
        existing = conn.execute('SELECT COUNT(*) FROM dlp_policies').fetchone()[0]
        if existing == 0:
            conn.execute('''
                INSERT INTO dlp_policies (policy_name, blocked_extensions, sensitive_patterns)
                VALUES (?, ?, ?)
            ''', (
                'Default Policy',
                '.exe,.bat,.sh,.ps1,.cmd',
                'credit_card,email,phone,national_id'
            ))

    print(f"Database initialised at {db_path}")

if __name__ == '__main__':
    init_database()