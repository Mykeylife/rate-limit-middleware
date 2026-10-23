"""
Unit Tests for Rate Limiter Middleware and FastAPI Application.

Uses pytest and FastAPI's TestClient for isolated, reproducible testing.
"""

from typing import Generator
import unittest.mock
import pytest
from fastapi.testclient import TestClient

from gateway.main import app
from gateway.database import db_manager


@pytest.fixture
def client() -> TestClient:
    """Fixture to provide a TestClient for the FastAPI application."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_database_and_windows() -> Generator[None, None, None]:
    """Fixture to reset database status and clear middleware state."""
    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET is_active = 1")
        conn.commit()

    for middleware in app.user_middleware:
        if hasattr(middleware.cls, "request_windows"):
            middleware.options.get("request_windows", {}).clear()

    yield

    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET is_active = 1")
        conn.commit()


class TestRateLimiterMiddleware:
    """Test suite for Rate Limiter middleware and FastAPI integration."""

    def test_request_allowed(self, client: TestClient) -> None:
        """Verify that a valid API key with low frequency receives a 200 OK."""
        headers = {"X-API-Key": "sk-test-001"}
        response = client.get("/api/v1/health", headers=headers)
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_rate_limit_triggered(self, client: TestClient) -> None:
        """Verify rapid sequential requests trigger HTTP 429."""
        headers = {"X-API-Key": "sk-test-002"}
        limit_triggered = False
        for _ in range(15):
            response = client.get("/api/v1/health", headers=headers)
            if response.status_code == 429:
                limit_triggered = True
                error_body = response.json()
                assert "error" in error_body
                assert error_body["error"] == "Too Many Requests"
                break
        assert limit_triggered, "Rate limit window was not breached."

    def test_missing_api_key(self, client: TestClient) -> None:
        """Verify that a request without X-API-Key header is rejected."""
        response = client.get("/api/v1/health")
        assert response.status_code == 400
        assert response.json()["error"] == "Missing API key"

    def test_invalid_api_key(self, client: TestClient) -> None:
        """Verify that an invalid API key returns 401 Unauthorized."""
        headers = {"X-API-Key": "sk-invalid-key-12345"}
        response = client.get("/api/v1/health", headers=headers)
        assert response.status_code == 401
        assert response.json()["error"] == "Unauthorized"

    def test_revoke_key_success(self, client: TestClient) -> None:
        """Verify that an active key can be successfully revoked."""
        headers = {"X-API-Key": "sk-prod-001"}
        payload = {"api_key": "sk-test-002"}
        response = client.post("/api/v1/keys/revoke", json=payload, headers=headers)
        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_revoke_key_invalid_payload(self, client: TestClient) -> None:
        """Verify that a malformed JSON payload triggers a 400 response."""
        headers = {"X-API-Key": "sk-prod-001"}
        response = client.post("/api/v1/keys/revoke", json={}, headers=headers)
        assert response.status_code == 400
        assert "error" in response.json()

    def test_infrastructure_health_probe(self, client: TestClient) -> None:
        """Verify infrastructure health probe response ranges."""
        headers = {"X-API-Key": "sk-prod-001"}
        response = client.get("/api/v1/health", headers=headers)
        assert response.status_code in [200, 429]

    def test_global_server_error_interceptor(self, client: TestClient) -> None:
        """Verify global server exception handling interceptors."""
        headers = {"X-API-Key": "sk-test-001"}
        with unittest.mock.patch("gateway.database.db_manager.fetch_key_status", side_effect=Exception("Database crash")):
            response = client.get("/api/v1/health", headers=headers)
            assert response.status_code == 500
            json_data = response.json()
            assert json_data["error"] == "Internal Server Error"
            assert json_data["message"] == "Database crash"

    def test_missing_dashboard_template_fallback(self, client: TestClient) -> None:
        """Verify fallback routing behaviors on resource lookups."""
        headers = {"X-API-Key": "sk-test-001"}
        response = client.get("/api/v1/missing-endpoint-not-found-route", headers=headers)
        assert response.status_code in [400, 404]

    def test_database_edge_lookup_parameters(self, client: TestClient) -> None:
        """Verify handling of nonexistent key strings inside storage."""
        key_status = db_manager.fetch_key_status("sk-non-existent-key-string-validation")
        assert key_status is None

    # ============================================================================
    # API Key Administrative Lifecycle Tests (Option C Coverage Upgrades)
    # ============================================================================

    def test_generate_new_api_key(self, client: TestClient) -> None:
        """Verify the administrative endpoint generates new secure keys successfully."""
        payload = {
            "owner": "Test Enterprise Client",
            "requests_limit": 100,
            "window_size_seconds": 60
        }
        response = client.post("/api/v1/keys/create", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert "api_key" in data
        assert data["owner"] == "Test Enterprise Client"
        assert data["requests_limit"] == 100
        assert data["is_active"] is True

    def test_list_managed_gateway_keys(self, client: TestClient) -> None:
        """Verify system tracking configurations can be listed."""
        response = client.get("/api/v1/keys/list")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if len(data) > 0:
            assert "api_key" in data[0]
            assert "owner" in data[0]

    def test_rotate_active_api_key_success(self, client: TestClient) -> None:
        """Verify secure replacement tracking logic works on active keys."""
        payload = {"old_api_key": "sk-test-001"}
        response = client.post("/api/v1/keys/rotate", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "api_key" in data
        assert data["api_key"] != "sk-test-001"
        assert data["is_active"] is True

    def test_rotate_active_api_key_not_found(self, client: TestClient) -> None:
        """Verify rotation fails gracefully when searching for missing keys."""
        payload = {"old_api_key": "sk-non-existent-ghost-key"}
        response = client.post("/api/v1/keys/rotate", json=payload)
        assert response.status_code == 404
        assert response.json()["detail"] == "Target API key configuration tracking record not found."
