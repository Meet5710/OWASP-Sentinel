"""OWASP Sentinel - Ngrok Tunnel Endpoint Tests

Verifies /api/v1/tunnel endpoints for status check, authtoken validation, and process control.
"""

from unittest.mock import patch

from fastapi import status
from fastapi.testclient import TestClient


def test_tunnel_status_endpoint(client: TestClient) -> None:
    """Ensure /api/v1/tunnel/status returns valid status schema."""
    response = client.get("/api/v1/tunnel/status")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "is_running" in data
    assert "authtoken_configured" in data
    assert "tunnels" in data
    assert isinstance(data["tunnels"], list)


def test_tunnel_authtoken_empty_validation(client: TestClient) -> None:
    """Ensure /api/v1/tunnel/authtoken rejects empty string."""
    response = client.post("/api/v1/tunnel/authtoken", json={"authtoken": "   "})
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_tunnel_stop_endpoint(client: TestClient) -> None:
    """Ensure /api/v1/tunnel/stop returns valid stopped status."""
    response = client.post("/api/v1/tunnel/stop")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["is_running"] is False


@patch("app.api.v1.endpoints.tunnel.is_authtoken_configured", return_value=False)
def test_tunnel_start_without_auth(mock_auth, client: TestClient) -> None:
    """Ensure starting tunnel without authtoken returns an informative authentication message."""
    response = client.post("/api/v1/tunnel/start", json={"authtoken": ""})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["is_running"] is False
    assert "authtoken" in data["error"].lower() or "authenticated" in data["error"].lower()

