"""
Unit Tests for the SQLite Database Persistence Driver Component.

Tests cover:
1. Retrieval of active API key configuration records.
2. Handling of missing or nonexistent API keys.
3. Explicit key deactivation updates.
"""

from unittest.mock import MagicMock, patch

from gateway.database import db_manager


class TestDatabaseManager:
    """Test suite for validating the SQLite persistence manager component logic."""

    def test_fetch_key_status_active(self) -> None:
        """Verify fetch_key_status parses valid database records into clean dictionary maps."""
        # Arrange
        mock_cursor = MagicMock()
        # Mock database row behavior using dictionary lookups to match application requirements
        mock_row = {"client_name": "test-client", "is_active": 1}
        mock_cursor.fetchone.return_value = mock_row

        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        # Act
        with patch.object(db_manager, "get_connection") as mock_get_conn:
            mock_get_conn.return_value.__enter__.return_value = mock_conn
            result = db_manager.fetch_key_status("sk-test-abc")

        # Assert
        assert result is not None
        assert result["active"] is True
        assert result["name"] == "test-client"

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
        mock_cursor.execute.assert_called_with(
            "UPDATE api_keys SET is_active = 0 WHERE key = ?",
            ("sk-test-abc",)
        )
        mock_conn.commit.assert_called_once()
