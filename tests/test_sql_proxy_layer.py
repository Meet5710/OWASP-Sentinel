"""OWASP Sentinel - Layer 2: Proxy Layer (Anonymity/Evasion) Tests

Validates proxy parsing, concurrent connection testing, file persistence,
pool activation, and scanner command integration.
"""

from fastapi.testclient import TestClient
import pytest
from app.main import app

client = TestClient(app)


def test_proxy_presets():
    """Verify curated proxy presets are returned."""
    resp = client.get("/api/v1/sql/proxies/presets")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 3
    assert any("Burp" in p["name"] for p in data)
    assert any("Tor" in p["name"] for p in data)


def test_proxy_validation_and_parsing():
    """Test proxy format parsing and concurrent validation."""
    payload = {
        "proxies": [
            "http://127.0.0.1:9",       # typically closed/dead port
            "127.0.0.1:80",             # local port
            "socks5://user:pass@127.0.0.1:1080",
            "# this is a comment",
        ],
        "timeout": 0.5,
    }
    resp = client.post("/api/v1/sql/proxies/validate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_tested"] == 3  # comment ignored
    assert len(data["results"]) == 3
    
    first = data["results"][0]
    assert first["host"] == "127.0.0.1"
    assert first["port"] == 9
    assert first["status"] in ("LIVE", "DEAD")

    socks = [r for r in data["results"] if r["protocol"] == "socks5"][0]
    assert socks["auth"] == "user:pass"
    assert socks["port"] == 1080


def test_proxy_save_to_file():
    """Test saving working proxies to proxies.txt."""
    payload = {
        "proxies": ["http://127.0.0.1:8080", "socks5://127.0.0.1:9050"],
        "filename": "test_proxies.txt",
        "only_live": False,
    }
    resp = client.post("/api/v1/sql/proxies/save", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["saved_count"] == 2
    assert "test_proxies.txt" in data["filename"]


def test_proxy_pool_activation_and_scanner_handoff():
    """Verify active proxy pool configuration and scanner handoff command modification."""
    # 1. Enable proxy pool
    pool_payload = {
        "is_enabled": True,
        "rotation_strategy": "round-robin",
        "active_proxies": ["http://127.0.0.1:8080"],
        "total_active": 1,
    }
    resp = client.post("/api/v1/sql/proxies/active", json=pool_payload)
    assert resp.status_code == 200
    pool_data = resp.json()
    assert pool_data["is_enabled"] is True
    assert pool_data["total_active"] == 1

    # 2. Feed URLs to scanner and verify --proxy-file flag is included
    feed_payload = {
        "urls": ["https://target.com/page.php?id=1"],
        "auto_register_assets": False,
    }
    resp2 = client.post("/api/v1/sql/scanner/feed", json=feed_payload)
    assert resp2.status_code == 200
    feed_data = resp2.json()
    assert "--proxy-file proxies.txt" in feed_data["staged_terminal_cmd"]

    # 3. Disable proxy pool
    pool_payload["is_enabled"] = False
    client.post("/api/v1/sql/proxies/active", json=pool_payload)

