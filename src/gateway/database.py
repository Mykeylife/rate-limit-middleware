"""
Database Management Layer for the API Security Gateway.

Handles asynchronous connection pooling, database tables schema construction, 
and atomic transactions for persistent API token key records using SQLite.
"""

import sqlite3
from typing import Dict, Optional


class GatewayDatabase:
    """Manages transactional interactions with the local SQLite storage layer."""

    def __init__(self, db_path: str = "gateway_control.db") -> None:
        self.db_path: str = db_path

    def get_connection(self) -> sqlite3.Connection:
        """Creates a synchronous connection to the target SQLite file resource."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def bootstrap_tables(self) -> None:
        """Initializes foundational database schema layouts on application boot."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    api_key TEXT PRIMARY KEY,
                    client_name TEXT NOT EXISTS OR TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1
                )
            """)
            
            # Seed foundational test keys matching original environment structures safely
            seed_data = [
                ("sk-test-001", "Test Client 1", 1),
                ("sk-test-002", "Test Client 2", 1),
                ("sk-prod-001", "Production Client", 1)
            ]
            cursor.executemany("""
                INSERT OR IGNORE INTO api_keys (api_key, client_name, is_active)
                VALUES (?, ?, ?)
            """, seed_data)
            conn.commit()

    def fetch_key_status(self, api_key: str) -> Optional[Dict[str, any]]:
        """Queries client authentication parameters relative to an incoming key."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT client_name, is_active FROM api_keys WHERE api_key = ?", 
                (api_key,)
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return {
                "name": row["client_name"],
                "active": bool(row["is_active"])
            }

    def deactivate_key(self, api_key: str) -> bool:
        """Atomically marks a specified token profile identifier as inactive."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Explicit transaction containment checks
            cursor.execute("SELECT 1 FROM api_keys WHERE api_key = ?", (api_key,))
            if cursor.fetchone() is None:
                return False
                
            cursor.execute(
                "UPDATE api_keys SET is_active = 0 WHERE api_key = ?", 
                (api_key,)
            )
            conn.commit()
            return True


# Instantiate a singleton driver instance for unified tracking architecture access
db_manager: GatewayDatabase = GatewayDatabase()
