"""Unit tests for api_server.py module."""

from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest

from api_server import app


@pytest.fixture
def client() -> TestClient:
    """Fixture providing a test client for the FastAPI app."""
    return TestClient(app)


def test_status_endpoint(client: TestClient) -> None:
    """GET /api/status returns online status with HTTP 200."""
    response = client.get("/api/status")
    assert response.status_code == 200
    assert response.json() == {"status": "online"}


def test_cors_headers(client: TestClient) -> None:
    """CORS middleware returns appropriate Access-Control-Allow-Origin header."""
    # Test localhost with port 5173 (standard Vite dev server)
    response = client.get(
        "/api/status",
        headers={"Origin": "http://localhost:5173"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"

    # Test 127.0.0.1 with port 3000
    response2 = client.get(
        "/api/status",
        headers={"Origin": "http://127.0.0.1:3000"},
    )
    assert response2.status_code == 200
    assert response2.headers.get("access-control-allow-origin") == "http://127.0.0.1:3000"


def test_scan_endpoint_valid_request(client: TestClient) -> None:
    """POST /api/scan invokes scanner_main.scan and returns findings."""
    mock_scan_result = {
        "target": "https://target.local",
        "findings": [
            {
                "owasp_id": "A02",
                "title": "Missing Security Header: Content-Security-Policy",
                "severity": "medium",
                "evidence": "CSP header missing",
                "source": "scanner",
            }
        ],
        "summary": {
            "total": 1,
            "by_owasp": {"A01": 0, "A02": 1},
        },
    }

    payload = {
        "target_url": "https://target.local",
        "selected_checks": ["A01", "A02"],
    }

    with patch("api_server.scan", return_value=mock_scan_result) as mock_scan:
        response = client.post("/api/scan", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "https://target.local"
    assert len(data["findings"]) == 1
    assert data["summary"]["total"] == 1

    mock_scan.assert_called_once_with(
        target_url="https://target.local",
        selected_ids=["A01", "A02"],
        auth={},
    )


def test_scan_endpoint_invalid_payload(client: TestClient) -> None:
    """POST /api/scan returns HTTP 422 Unprocessable Entity when fields are missing."""
    # Missing selected_checks
    response = client.post("/api/scan", json={"target_url": "https://target.local"})
    assert response.status_code == 422

    # Missing target_url
    response2 = client.post("/api/scan", json={"selected_checks": ["A01"]})
    assert response2.status_code == 422

