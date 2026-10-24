"""
Database Manager Core Layer.

Handles SQLite connections, API key provisioning, and revocation status.
"""

import sqlite3
import os
from typing import Dict, Optional, List

DB_PATH = os.getenv("DATABASE_PATH", "gateway.db")


def get_connection():
    """Create a thread-safe connection to the SQLite database instance."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def bootstrap_tables() -> None:
    """Initialize the local persistent SQLite tables layout on system boot cleanly."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                api_key TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                requests_limit INTEGER NOT NULL,
                window_size_seconds INTEGER NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


def create_api_key(api_key: str, owner: str, requests_limit: int, window_size: int) -> bool:
    """Provision a new API key configuration inside the persistent storage layer."""
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO api_keys (api_key, owner, requests_limit, window_size_seconds, is_active, created_at)
                VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
                """,
                (api_key, owner, requests_limit, window_size)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def fetch_all_keys() -> List[Dict]:
    """Retrieve metadata records for all tracked API keys across the gateway environment."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT api_key, owner, requests_limit, window_size_seconds, is_active, created_at FROM api_keys")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def fetch_key_status(api_key: str) -> Optional[Dict]:
    """Look up schema constraints and verification status flags for an input key token string."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT is_active, owner, requests_limit, window_size_seconds FROM api_keys WHERE api_key = ?",
            (api_key,)
        )
        row = cursor.fetchone()
        if row:
            return {
                "active": bool(row["is_active"]),
                "owner": row["owner"],
                "requests_limit": row["requests_limit"],
                "window_size_seconds": row["window_size_seconds"]
            }
        return None


def deactivate_key(api_key: str) -> bool:
    """Mark a given API key token string as inactive to permanently block incoming traffic routes."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET is_active = 0 WHERE api_key = ?", (api_key,))
        conn.commit()
        return cursor.rowcount > 0
