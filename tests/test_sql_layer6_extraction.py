from fastapi.testclient import TestClient
import xml.etree.ElementTree as ET
from app.main import app

client = TestClient(app)


def test_layer6_dump_data():
    """Verify Layer 6 data dump extracts rows into grid with sqlmap command and export previews."""
    resp = client.post(
        "/api/v1/sql/layer6/dump",
        json={
            "target_url": "https://smarttrichy.in/detail.php?id=99",
            "parameter": "id",
            "database_name": "smarttrichy_production",
            "table_name": "users",
            "selected_columns": ["id", "username", "email", "role"],
            "limit": 10,
            "offset": 0,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["database_name"] == "smarttrichy_production"
    assert data["table_name"] == "users"
    assert len(data["records"]) > 0
    assert "admin@smarttrichy.in" in [r.get("email") for r in data["records"]]
    assert "--dump" in data["sqlmap_command"]
    assert "VULNSENTINEL DATA EXTRACTION REPORT" in data["txt_export_preview"]
    assert "<?xml version=" in data["xml_export_preview"]


def test_layer6_export_txt():
    """Verify Layer 6 exports cleanly formatted plain text report (.txt)."""
    resp = client.post(
        "/api/v1/sql/layer6/export",
        json={
            "format": "txt",
            "database_name": "smarttrichy_production",
            "table_name": "users",
            "columns": ["username", "email", "role"],
            "records": [
                {"username": "admin", "email": "admin@smarttrichy.in", "role": "SUPERADMIN"},
                {"username": "sec_lead", "email": "sec@smarttrichy.in", "role": "SECURITY"},
            ],
            "target_url": "https://smarttrichy.in/detail.php?id=99",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "txt"
    assert data["mime_type"] == "text/plain"
    assert data["filename"].endswith(".txt")
    assert "admin@smarttrichy.in" in data["content"]
    assert "COLUMNS: username | email | role" in data["content"]


def test_layer6_export_xml():
    """Verify Layer 6 exports well-formed XML (.xml)."""
    resp = client.post(
        "/api/v1/sql/layer6/export",
        json={
            "format": "xml",
            "database_name": "smarttrichy_production",
            "table_name": "users",
            "columns": ["username", "email", "role"],
            "records": [
                {"username": "admin", "email": "admin@smarttrichy.in", "role": "SUPERADMIN"},
                {"username": "sec_lead", "email": "sec@smarttrichy.in", "role": "SECURITY"},
            ],
            "target_url": "https://smarttrichy.in/detail.php?id=99",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "xml"
    assert data["mime_type"] == "application/xml"
    assert data["filename"].endswith(".xml")

    # Validate XML syntax parse
    root = ET.fromstring(data["content"])
    assert root.tag == "database"
    assert root.attrib["name"] == "smarttrichy_production"
    tbl = root.find("table")
    assert tbl is not None
    assert tbl.attrib["name"] == "users"
    rows = tbl.find("rows")
    assert rows is not None
    assert len(rows.findall("row")) == 2

