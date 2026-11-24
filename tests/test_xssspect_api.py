"""Integration tests for XSSSpect assessment API endpoints."""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.models.db.asset import AuthorizedAsset
from app.db.session import SessionLocal


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def test_asset():
    with SessionLocal() as db:
        asset = db.query(AuthorizedAsset).filter(AuthorizedAsset.host == "testfire.net").first()
        if not asset:
            asset = AuthorizedAsset(
                host="testfire.net",
                canonical_url="https://testfire.net",
                approval_status="APPROVED",
                description="Test fixture target",
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)
        return asset


def test_xssspect_scan_outside_scope_forbidden(client):
    response = client.post(
        "/api/v1/xssspect/scan",
        json={
            "url": "https://unauthorized-domain-999.com/search?q=test",
        },
    )
    assert response.status_code == 403
    assert "Scope clearance failed" in response.json()["detail"]


@patch("app.api.v1.endpoints.xssspect.scan_url")
def test_xssspect_scan_authorized_success(mock_scan, client, test_asset):
    mock_scan.return_value = {
        "url": "https://testfire.net/search?q=test",
        "parameters_tested": ["q"],
        "findings": [
            {
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
                "executed": True,
                "reflected": True,
                "dialog_message": "1",
            }
        ],
        "vulnerable": True,
    }

    response = client.post(
        "/api/v1/xssspect/scan",
        json={
            "url": "https://testfire.net/search?q=test",
            "target_id": test_asset.id,
            "delay": 0.1,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["vulnerable"] is True
    assert data["parameters_tested"] == ["q"]
    assert len(data["findings"]) == 1
    assert data["findings"][0]["executed"] is True
    assert data["findings"][0]["dialog_message"] == "1"

