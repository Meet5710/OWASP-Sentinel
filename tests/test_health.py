"""OWASP Sentinel - Health Endpoint and Middleware Tests

Verifies application liveness and baseline security header enforcement.
"""

from fastapi import status
from fastapi.testclient import TestClient


def test_root_endpoint(client: TestClient) -> None:
    """Ensure root path returns service identity and phase details."""
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["name"] == "OWASP Sentinel"
    assert "version" in data
    assert data["status"] == "online"
    assert "Phase 1" in data["phase"]


def test_health_check_endpoint(client: TestClient) -> None:
    """Ensure /api/v1/health endpoint confirms service health."""
    response = client.get("/api/v1/health")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "OWASP Sentinel"
    assert "version" in data
    assert "timestamp" in data


def test_security_headers_middleware(client: TestClient) -> None:
    """Ensure global security headers are applied to HTTP responses."""
    response = client.get("/api/v1/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "Strict-Transport-Security" in response.headers


def test_frontend_dashboard_endpoint(client: TestClient) -> None:
    """Ensure /app serves the single-page application dashboard."""
    response = client.get("/app")
    assert response.status_code == status.HTTP_200_OK
    assert "OWASP Sentinel" in response.text
