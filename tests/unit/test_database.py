"""
Unit Tests for Database Manager Component.
"""

from unittest.mock import MagicMock, patch

from gateway.database import db_manager


class TestDatabaseManager:
    """Test suite for verifying database engine behaviors."""

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
            "UPDATE api_keys SET is_active = 0 WHERE api_key = ?",
            ("sk-test-abc",)
        )
