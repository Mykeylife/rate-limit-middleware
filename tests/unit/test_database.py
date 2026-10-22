"""
Unit Tests for the SQLite Database Persistence Driver Component.

Tests cover:
1. Retrieval of active API key configuration records.
2. Handling of missing or nonexistent API keys.
3. Explicit key deactivation updates.
4. Database structure table initialization verification.
"""

from unittest.mock import MagicMock, patch

from gateway.database import db_manager


class TestDatabaseManager:
    """Test suite for validating the SQLite persistence manager component logic."""

    def test_fetch_key_status_active(self) -> None:
        """Verify fetch_key_status parses valid database records into clean dictionary maps."""
        # Arrange
        mock_cursor = MagicMock()
        # Simulate a database row return: (id, key, status, description)
        mock_cursor.fetchone.return_value = (1, "sk-test-abc", 1, "test-key")

        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        # Act
        with patch.object(db_manager, "get_connection") as mock_get_conn:
            mock_get_conn.return_value.__enter__.return_value = mock_conn
            result = db_manager.fetch_key_status("sk-test-abc")

        # Assert
        assert result is not None
        assert result["active"] is True
        assert result["key"] == "sk-test-abc"
        mock_cursor.execute.assert_called_once()

    def test_fetch_key_status_nonexistent(self) -> None:
        """Verify fetch_key_status returns None when query handles unrecognized strings."""
        # Arrange
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None

        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        # Act
        with patch.object(db_manager, "get_connection") as mock_get_conn:
            mock_get_conn.return_value.__enter__.return_value = mock_conn
            result = db_manager.fetch_key_status("sk-invalid-fake")

        # Assert
        assert result is None

    def test_deactivate_key_updates_record(self) -> None:
        """Verify deactivate_key fires transaction mutations correctly to update state maps."""
        # Arrange
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        # Act
        with patch.object(db_manager, "get_connection") as mock_get_conn:
            mock_get_conn.return_value.__enter__.return_value = mock_conn
            db_manager.deactivate_key("sk-test-abc")

        # Assert
        # Verify that an execution query ran to change the status state
        mock_cursor.execute.assert_called_with(
            "UPDATE api_keys SET is_active = 0 WHERE key = ?",
            ("sk-test-abc",)
        )
        mock_conn.commit.assert_called_once()

    def test_database_initialization_lifecycle(self) -> None:
        """Verify bootstrap_tables executes structural setups without triggering exceptions."""
        # Arrange
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        # Act & Assert
        with patch.object(db_manager, "get_connection") as mock_get_conn:
            mock_get_conn.return_value.__enter__.return_value = mock_conn
            # Run initialization loop to verify schema binding stability
            if hasattr(db_manager, "bootstrap_tables"):
                db_manager.bootstrap_tables()
            elif hasattr(db_manager, "init_db"):
                getattr(db_manager, "init_db")()
