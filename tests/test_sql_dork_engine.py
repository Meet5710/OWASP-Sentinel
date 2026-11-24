"""OWASP Sentinel - Tests for SQL Target Discovery & Dork Engine API."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_get_dork_presets(client: TestClient):
    """Verify predefined dork reconnaissance presets are returned."""
    response = client.get("/api/v1/sql/dorks/presets")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 5

    preset_ids = [p["id"] for p in data]
    assert "ecommerce" in preset_ids
    assert "news_media" in preset_ids
    assert "cms_portals" in preset_ids

    # Check structure
    sample = data[0]
    assert "keywords" in sample
    assert "formats" in sample
    assert "page_types" in sample
    assert len(sample["keywords"]) > 0
    assert len(sample["formats"]) > 0
    assert len(sample["page_types"]) > 0


def test_generate_dorks_default(client: TestClient):
    """Verify default generation synthesizes structured dorks."""
    response = client.post("/api/v1/sql/dorks/generate", json={})
    assert response.status_code == 200
    data = response.json()
    assert "total_generated" in data
    assert data["total_generated"] > 0
    assert "dorks" in data
    assert len(data["dorks"]) == data["total_generated"]

    first_dork = data["dorks"][0]
    assert "dork_query" in first_dork
    assert "search_urls" in first_dork
    assert "google" in first_dork["search_urls"]
    assert "bing" in first_dork["search_urls"]
    assert "duckduckgo" in first_dork["search_urls"]
    assert "sqlmap_example" in first_dork
    assert "sqlmap" in first_dork["sqlmap_example"]


def test_generate_dorks_with_target_domain(client: TestClient):
    """Verify dorks scope properly with site: when target domain is provided."""
    payload = {
        "keywords": ["products"],
        "formats": [".php"],
        "page_types": ["id="],
        "target_domain": "smarttrichy.in",
    }
    response = client.post("/api/v1/sql/dorks/generate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_generated"] == 1
    dork = data["dorks"][0]
    assert dork["dork_query"].startswith("site:smarttrichy.in")
    assert "inurl:.php?id=" in dork["dork_query"]
    assert 'intitle:"products"' in dork["dork_query"]


def test_generate_dorks_operators(client: TestClient):
    """Verify format operators and keyword operators behave correctly."""
    payload = {
        "keywords": ["article"],
        "formats": [".asp"],
        "page_types": ["cartID="],
        "keyword_operator": "intext",
        "format_operator": "filetype",
    }
    response = client.post("/api/v1/sql/dorks/generate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_generated"] == 1
    dork = data["dorks"][0]
    assert "filetype:asp" in dork["dork_query"]
    assert "inurl:cartID=" in dork["dork_query"]
    assert 'intext:"article"' in dork["dork_query"]


def test_generate_dorks_max_limit(client: TestClient):
    """Verify max_dorks cap works properly."""
    payload = {
        "keywords": ["a", "b", "c", "d"],
        "formats": [".php", ".asp", ".aspx"],
        "page_types": ["id=", "cat=", "item="],
        "max_dorks": 5,
    }
    response = client.post("/api/v1/sql/dorks/generate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_generated"] == 5
    assert len(data["dorks"]) == 5


def test_get_dork_presets_expanded(client: TestClient):
    """Verify expanded industry presets are present."""
    response = client.get("/api/v1/sql/dorks/presets")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 12
    preset_ids = [p["id"] for p in data]
    expected = [
        "ecommerce",
        "news_media",
        "cms_portals",
        "user_accounts",
        "search_reports",
        "admin_auth",
        "api_endpoints",
        "db_dumps_backup",
        "banking_fintech",
        "file_doc_viewers",
        "sqli_error_signatures",
        "healthcare_edu",
    ]
    for exp in expected:
        assert exp in preset_ids


def test_generate_dorks_expanded_operators_and_engines(client: TestClient):
    """Verify expanded allinurl / allintitle operators and search engines."""
    payload = {
        "keywords": ["admin"],
        "formats": [".php"],
        "page_types": ["login="],
        "keyword_operator": "allintitle",
        "format_operator": "allinurl",
    }
    response = client.post("/api/v1/sql/dorks/generate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_generated"] == 1
    dork = data["dorks"][0]
    assert "allinurl:.php login=" in dork["dork_query"]
    assert 'allintitle:"admin"' in dork["dork_query"]
    assert "yandex" in dork["search_urls"]
    assert "startpage" in dork["search_urls"]
    assert "github" in dork["search_urls"]
    assert "shodan" in dork["search_urls"]
    assert dork["category"] == "Admin & Auth Consoles"


