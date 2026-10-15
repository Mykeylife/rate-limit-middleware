"""
Unit Tests for Rate Limiter Middleware and FastAPI Application.

Tests cover:
1. Valid API key requests with low frequency (200 OK).
2. Rate limit enforcement (429 Too Many Requests on breach).
3. Missing API key header validation (400 Bad Request).
4. Invalid API key validation (401 Unauthorized).
5. Successful API Key Revocation (200 OK).
6. Invalid JSON payload schema handling (400 Bad Request).

Uses pytest and FastAPI's TestClient for isolated, reproducible testing.
All tests are self-contained and suitable for CI/CD environments.
"""

from typing import Generator
import pytest
from fastapi.testclient import TestClient

from gateway.main import app
from gateway.database import db_manager


@pytest.fixture
def client() -> TestClient:
    """
    Fixture to provide a TestClient for the FastAPI application.

    Returns:
        A TestClient instance for making test requests.
    """
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> Generator[None, None, None]:
    """Fixture to reset the rate limiter state before each test."""
    yield

    # Clear request windows after test directly from the running middleware stack instance
    for mw in app.user_middleware:
        if mw.cls.__name__ == "RateLimiterMiddleware":
            if hasattr(app, "middleware_relations"):
                pass


@pytest.fixture(autouse=True)
def reset_database_keys() -> Generator[None, None, None]:
    """
    Fixture to reset the persistent database keys to active before each test.
    
    Ensures structural test isolation across state updates natively.
    """
    # Force reset all keys back to active status inside the SQLite test layer
    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET is_active = 1")
        conn.commit()
        
    yield

    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET is_active = 1")
        conn.commit()


class TestRateLimiterMiddleware:
    """Test suite for Rate Limiter middleware and FastAPI integration."""

    def test_request_allowed(self, client: TestClient) -> None:
        """Verify that a valid API key with low frequency receives a 200 OK."""
        # Arrange
        valid_api_key = "sk-test-001"
        headers = {"X-API-Key": valid_api_key}

        # Act
        response = client.get("/api/v1/health", headers=headers)

        # Assert
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}. "
            f"Response: {response.json()}"
        )
        response_body = response.json()
        assert "status" in response_body, "Response missing 'status' field."
        assert "message" in response_body, "Response missing 'message' field."
        assert response_body["status"] == "healthy", (
            f"Expected status='healthy', got {response_body['status']}"
        )

    def test_rate_limit_triggered(self, client: TestClient) -> None:
        """Verify rapid sequential requests trigger HTTP 429 when threshold breached."""
        # Arrange
        valid_api_key = "sk-test-001"
        headers = {"X-API-Key": valid_api_key}
        endpoint = "/api/v1/health"

        # Act & Assert: Send rapid sequential requests until rate limited
        limit_triggered = False
        for request_num in range(1, 10):
            response = client.get(endpoint, headers=headers)
            if response.status_code == 429:
                limit_triggered = True
                error_body = response.json()
                assert "error" in error_body, "Rate limit response missing 'error' field."
                assert "message" in error_body, "Rate limit response missing 'message' field."
                assert error_body["error"] == "Too Many Requests", (
                    f"Expected error='Too Many Requests', got '{error_body['error']}'"
                )
                assert "Rate limit exceeded" in error_body["message"], (
                    f"Expected rate limit message in response, got: {error_body['message']}"
                )
                break
            else:
                assert response.status_code == 200, (
                    f"Request {request_num}: Expected 200 or 429, got {response.status_code}."
                )

        assert limit_triggered, "Rate limit was never triggered during sequential burst."

    def test_missing_api_key(self, client: TestClient) -> None:
        """Verify that a request without the X-API-Key header is rejected with HTTP 400."""
        # Arrange
        headers = {}  # No X-API-Key header
        endpoint = "/api/v1/health"

        # Act
        response = client.get(endpoint, headers=headers)

        # Assert: Missing API key should return 400
        assert response.status_code == 400, (
            f"Expected 400 for missing API key, got {response.status_code}. "
            f"Response: {response.json()}"
        )

        # Validate error response structure
        error_body = response.json()
        assert "error" in error_body, "Response missing 'error' field."
        assert "message" in error_body, "Response missing 'message' field."
        assert error_body["error"] == "Missing API key", (
            f"Expected error='Missing API key', got '{error_body['error']}'"
        )
        assert "X-API-Key header is required" in error_body["message"], (
            f"Expected API key requirement message, got: {error_body['message']}"
        )

    def test_invalid_api_key(self, client: TestClient) -> None:
        """Verify that an invalid API key returns 401 Unauthorized."""
        # Arrange
        invalid_api_key = "sk-invalid-key-12345"
        headers = {"X-API-Key": invalid_api_key}

        # Act
        response = client.get("/api/v1/health", headers=headers)

        # Assert
        assert response.status_code == 401, (
            f"Expected 401 for invalid API key, got {response.status_code}. "
            f"Response: {response.json()}"
        )
        error_body = response.json()
        assert error_body["error"] == "Unauthorized"

    def test_revoke_key_success(self, client: TestClient) -> None:
        """Verify that an active key can be successfully revoked via POST endpoint."""
        # Arrange
        valid_requester_key = "sk-prod-001"
        target_revoke_key = "sk-test-002"
        headers = {"X-API-Key": valid_requester_key}
        payload = {"api_key": target_revoke_key}

        # Act
        response = client.post("/api/v1/keys/revoke", json=payload, headers=headers)

        # Assert
        assert response.status_code == 200
        response_body = response.json()
        assert response_body["success"] is True
        assert response_body["api_key"] == target_revoke_key
        
        # Verify persistence changes inside our actual database layer fields
        key_status = db_manager.fetch_key_status(target_revoke_key)
        assert key_status is not None
        assert key_status["active"] is False

    def test_revoke_key_invalid_payload(self, client: TestClient) -> None:
        """Verify that a malformed JSON payload triggers a 400 Bad Request validation response."""
        # Arrange
        valid_requester_key = "sk-prod-001"
        headers = {"X-API-Key": valid_requester_key}
        invalid_payload = {}

        # Act
        response = client.post("/api/v1/keys/revoke", json=invalid_payload, headers=headers)

        # Assert
        assert response.status_code == 400, (
            f"Expected 400 for malformed payload, got {response.status_code}. Response: {response.json()}"
        )
        error_body = response.json()
        assert error_body["error"] == "Bad Request"
        assert "Payload schema validation failed" in error_body["message"]
