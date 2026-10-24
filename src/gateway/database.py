"""Database Management Layer for the API Security Gateway.

Handles asynchronous connection pooling, database tables schema construction,
and atomic transactions for persistent API token key records using SQLite.
"""

import os
import sqlite3
from typing import Any, Dict, List, Optional


class GatewayDatabase:
    """Manages transactional interactions with the local SQLite storage layer."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        # Respect isolated path configurations passed down via environmental parameters
        self.db_path: str = db_path or os.getenv(
            "DATABASE_PATH", "gateway_control.db"
        )

    def get_connection(self) -> sqlite3.Connection:
        """Creates a synchronous connection to the target SQLite file resource."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def bootstrap_tables(self) -> None:
        """Initializes foundational database schema layouts on application boot."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    api_key TEXT PRIMARY KEY,
                    client_name TEXT NOT NULL,
                    requests_limit INTEGER NOT NULL DEFAULT 5,
                    window_size_seconds INTEGER NOT NULL DEFAULT 10,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            seed_data = [
                ("sk-test-001", "Developer One", 5, 10, 1),
                ("sk-test-002", "Developer Two", 5, 10, 1),
                ("sk-prod-001", "Admin Card", 5, 10, 1),
            ]
            cursor.executemany(
                """
                INSERT OR IGNORE INTO api_keys
                (api_key, client_name, requests_limit, window_size_seconds, is_active)
                VALUES (?, ?, ?, ?, ?)
                """,
                seed_data,
            )
            conn.commit()

    def fetch_key_status(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Queries client authentication parameters relative to an incoming key."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT client_name, requests_limit, window_size_seconds, is_active
                FROM api_keys WHERE api_key = ?
                """,
                (api_key,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return {
                # New administrative router tracking keys
                "owner": row["client_name"],
                "requests_limit": row["requests_limit"],
                "window_size_seconds": row["window_size_seconds"],
                "is_active": bool(row["is_active"]),
                # Legacy middleware tracking keys to resolve 401 Unauthorized errors
                "name": row["client_name"],
                "active": bool(row["is_active"]),
            }

    def create_api_key(
        self, api_key: str, owner: str, requests_limit: int, window_size: int
    ) -> bool:
        """Saves a new system credential payload inside the local storage file."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO api_keys
                    (api_key, client_name, requests_limit, window_size_seconds, is_active)
                    VALUES (?, ?, ?, ?, 1)
                    """,
                    (api_key, owner, requests_limit, window_size),
                )
                conn.commit()
                return True
        except sqlite3.Error:
            return False

    def fetch_all_keys(self) -> List[Dict[str, Any]]:
        """Extracts every registered authorization log mapping within database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT api_key, client_name, requests_limit, window_size_seconds,
                       is_active, created_at FROM api_keys
                """
            )
            rows = cursor.fetchall()
            return [
                {
                    "api_key": r["api_key"],
                    "owner": r["client_name"],
                    "requests_limit": r["requests_limit"],
                    "window_size_seconds": r["window_size_seconds"],
                    "is_active": bool(r["is_active"]),
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

    def deactivate_key(self, api_key: str) -> bool:
        """Atomically marks a specified token profile identifier as inactive."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM api_keys WHERE api_key = ?", (api_key,)
            )
            if cursor.fetchone() is None:
                return False

            cursor.execute(
                "UPDATE api_keys SET is_active = 0 WHERE api_key = ?",
                (api_key,),
            )
            conn.commit()
            return True


# Instantiate a singleton driver instance for unified tracking architecture access
db_manager: GatewayDatabase = GatewayDatabase()
