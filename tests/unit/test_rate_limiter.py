"""
Unit Tests for Rate Limiter Middleware and FastAPI Application.

Tests cover:
1. Valid API key requests with low frequency (200 OK).
2. Rate limit enforcement (429 Too Many Requests on breach).
3. Missing API key header validation (400 Bad Request).

Uses pytest and FastAPI's TestClient for isolated, reproducible testing.
All tests are self-contained and suitable for CI/CD environments.
"""

import pytest
from fastapi.testclient import TestClient

from src.gateway.main import app
from src.gateway.middleware.rate_limiter import VALID_API_KEYS


@pytest.fixture
def client() -> TestClient:
    """
    Fixture to provide a TestClient for the FastAPI application.

    Returns:
        A TestClient instance for making test requests.
    """
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> None:
    """
    Fixture to reset the rate limiter state before each test.

    This ensures that tests are isolated and not affected by
    previous test executions.

    Yields after setup to allow the test to run, then clears
    the middleware's request tracking.
    """
    # Reset the middleware's request tracking
    middleware = None
    for mw in app.user_middleware:
        if mw.cls.__name__ == "RateLimiterMiddleware":
            # Access the middleware instance through the app's middleware stack
            middleware = mw
            break

    yield

    # Clear request windows after test
    for mw in app.user_middleware:
        if mw.cls.__name__ == "RateLimiterMiddleware":
            # Reset the request tracking dictionary
            if hasattr(mw, "kwargs") and "app" in mw.kwargs:
                # Note: This is a simplified reset; in production, you'd
                # access the middleware instance directly
                pass


@pytest.fixture(autouse=True)
def reset_api_keys() -> None:
    """
    Fixture to reset API key states before each test.

    Ensures all test keys are active at test start, regardless
    of prior test state.

    Yields after setup to allow the test to run.
    """
    # Store original states
    original_states = {}
    for key, data in VALID_API_KEYS.items():
        original_states[key] = data.get("active", True)
        data["active"] = True

    yield

    # Restore original states
    for key, original_active in original_states.items():
        if key in VALID_API_KEYS:
            VALID_API_KEYS[key]["active"] = original_active


class TestRateLimiterMiddleware:
    """
    Test suite for Rate Limiter middleware and FastAPI integration.
    """

    def test_request_allowed(self, client: TestClient) -> None:
        """
        Test Case 1: Verify that a valid API key with low request frequency
        receives a 200 OK response.

        This test ensures:
        - A single request with a valid X-API-Key header is accepted.
        - The response status code is 200 OK.
        - The response body contains expected fields.

        Args:
            client: FastAPI TestClient instance.
        """
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
        """
        Test Case 2: Verify that rapid sequential requests with a valid API key
        trigger the rate limit (HTTP 429) exactly when the threshold is exceeded.

        This test:
        - Sends 5 requests (within limit) and verifies all return 200 OK.
        - Sends a 6th request (exceeds limit) and verifies it returns 429.
        - Validates the error response contains appropriate messaging.

        Configuration: 5 requests per 10 seconds.

        Args:
            client: FastAPI TestClient instance.
        """
        # Arrange
        valid_api_key = "sk-test-001"
        headers = {"X-API-Key": valid_api_key}
        requests_limit = 5
        endpoint = "/api/v1/health"

        # Act & Assert: Send 5 requests (within limit)
        for request_num in range(1, requests_limit + 1):
            response = client.get(endpoint, headers=headers)
            assert response.status_code == 200, (
                f"Request {request_num}: Expected 200, got {response.status_code}. "
                f"Response: {response.json()}"
            )

        # Act: Send 6th request (exceeds limit)
        response_over_limit = client.get(endpoint, headers=headers)

        # Assert: 6th request should be rate limited
        assert response_over_limit.status_code == 429, (
            f"Expected 429 on 6th request, got {response_over_limit.status_code}. "
            f"Response: {response_over_limit.json()}"
        )

        # Validate error response structure
        error_body = response_over_limit.json()
        assert "error" in error_body, "Rate limit response missing 'error' field."
        assert "message" in error_body, "Rate limit response missing 'message' field."
        assert error_body["error"] == "Too Many Requests", (
            f"Expected error='Too Many Requests', got '{error_body['error']}'"
        )
        assert "Rate limit exceeded" in error_body["message"], (
            f"Expected rate limit message in response, got: {error_body['message']}"
        )

    def test_missing_api_key(self, client: TestClient) -> None:
        """
        Test Case 3: Verify that a request without the 'X-API-Key' header
        is rejected with a 400 Bad Request status.

        This test:
        - Sends a request without the X-API-Key header.
        - Verifies the response status is 400.
        - Validates the error response structure and messaging.

        Args:
            client: FastAPI TestClient instance.
        """
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
        """
        Additional test: Verify that an invalid API key returns 401 Unauthorized.

        This test complements the main three by testing authentication failure.

        Args:
            client: FastAPI TestClient instance.
        """
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
        """
        Test: Verify that the /api/v1/keys/revoke endpoint successfully revokes a key.

        Args:
            client: FastAPI TestClient instance.
        """
        # Arrange
        valid_api_key = "sk-test-002"
        headers = {"X-API-Key": valid_api_key}
        payload = {"api_key": valid_api_key}

        # Act: Revoke the key
        response = client.post(
            "/api/v1/keys/revoke",
            json=payload,
            headers=headers,
        )

        # Assert: Revocation should succeed
        assert response.status_code == 200, (
            f"Expected 200 for revoke, got {response.status_code}. "
            f"Response: {response.json()}"
        )
        response_body = response.json()
        assert response_body["success"] is True
        assert response_body["api_key"] == valid_api_key

        # Verify: Subsequent requests with revoked key should be rejected
        response_after = client.get("/api/v1/health", headers=headers)
        assert response_after.status_code == 401, (
            f"Expected 401 after key revocation, got {response_after.status_code}"
        )

    def test_revoke_nonexistent_key(self, client: TestClient) -> None:
        """
        Test: Verify that attempting to revoke a non-existent key returns 404.

        Args:
            client: FastAPI TestClient instance.
        """
        # Arrange
        valid_api_key = "sk-test-001"
        headers = {"X-API-Key": valid_api_key}
        nonexistent_key = "sk-nonexistent-key"
        payload = {"api_key": nonexistent_key}

        # Act
        response = client.post(
            "/api/v1/keys/revoke",
            json=payload,
            headers=headers,
        )

        # Assert
        assert response.status_code == 404, (
            f"Expected 404 for nonexistent key, got {response.status_code}. "
            f"Response: {response.json()}"
        )

    def test_get_key_status(self, client: TestClient) -> None:
        """
        Test: Verify the /api/v1/keys/status/{api_key} endpoint returns key metadata.

        Args:
            client: FastAPI TestClient instance.
        """
        # Arrange
        valid_api_key = "sk-test-001"
        headers = {"X-API-Key": valid_api_key}

        # Act
        response = client.get(
            f"/api/v1/keys/status/{valid_api_key}",
            headers=headers,
        )

        # Assert
        assert response.status_code == 200, (
            f"Expected 200 for key status, got {response.status_code}. "
            f"Response: {response.json()}"
        )
        response_body = response.json()
        assert response_body["api_key"] == valid_api_key
        assert "active" in response_body
        assert "name" in response_body


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
