"""OWASP Sentinel - Layer 3: Scanning and Classification Tests

Validates dork file insertion, search engine selection, injection detection,
and 5-tab classification (URL's Queue, Exploitables, Injectables, Non-Injectables, Trash Collector).
"""

from fastapi.testclient import TestClient
import pytest
from app.main import app

client = TestClient(app)


def test_list_dork_files():
    """Verify available dork files are discovered."""
    resp = client.get("/api/v1/sql/dork-files")
    assert resp.status_code == 200
    files = resp.json()
    assert isinstance(files, list)


def test_layer3_scan_and_classification():
    """Verify Layer 3 scanner runs and classifies targets into the 5 required tabs."""
    payload = {
        "dork_lines": ['inurl:.php?id= intitle:"product"'],
        "search_engine": "duckduckgo",
        "urls": [
            "https://smarttrichy.in/detail.php?id=10",
            "http://127.0.0.1:9/unreachable_port",
        ],
        "use_proxy_pool": False,
        "test_depth": "standard",
    }
    resp = client.post("/api/v1/sql/layer3/scan", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    # Verify counts and categories exist
    assert data["total_scanned"] >= 2
    assert "queue_count" in data
    assert "exploitables_count" in data
    assert "injectables_count" in data
    assert "non_injectables_count" in data
    assert "trash_count" in data

    # Verify results list contains items in all five tabs
    categories = set(r["category"] for r in data["results"])
    assert "injectables" in categories
    assert "exploitables" in categories
    assert "trash" in categories

    # Verify Injectables tab items have required actionable fields
    injectables = [r for r in data["results"] if r["category"] == "injectables"]
    assert len(injectables) > 0
    first_inj = injectables[0]
    assert first_inj["url"]
    assert first_inj["http_method"] in ("GET", "POST")
    assert first_inj["database_type"] is not None
    assert first_inj["database_version"] is not None
    assert first_inj["database_user"] is not None


def test_layer3_results_summary_and_clear_trash():
    """Verify results endpoint and clearing of trash collector."""
    resp = client.get("/api/v1/sql/layer3/results")
    assert resp.status_code == 200
    summary = resp.json()
    assert summary["total_count"] > 0
    assert summary["injectables_count"] > 0

    # Clear trash
    trash_resp = client.post("/api/v1/sql/layer3/clear-trash")
    assert trash_resp.status_code == 200
    trash_data = trash_resp.json()
    assert trash_data["status"] == "success"


def test_layer3_scan_multiple_authorized_targets():
    """Verify Layer 3 scanner audits multiple authorized asset inventory targets concurrently and yields categorized results for each target."""
    payload = {
        "search_engine": "duckduckgo",
        "urls": [
            "https://sandbox.vuln-bank.test/detail.php?id=99",
            "https://sandbox.vuln-bank.test/cart.php?cartID=4501",
            "https://api.sandbox.vuln-bank.test/v1/user.php?id=501",
        ],
        "use_proxy_pool": False,
        "test_depth": "standard",
    }
    resp = client.post("/api/v1/sql/layer3/scan", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    # Results must include findings for both distinct hosts
    results = data["results"]
    hosts = set(r["host"] for r in results)
    assert "sandbox.vuln-bank.test" in hosts
    assert "api.sandbox.vuln-bank.test" in hosts

    # Each target must have injectables categorized
    inj_hosts = set(r["host"] for r in results if r["category"] == "injectables")
    assert "sandbox.vuln-bank.test" in inj_hosts
    assert "api.sandbox.vuln-bank.test" in inj_hosts


