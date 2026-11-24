from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_layer5_get_databases():
    """Verify Layer 5 enumerates database instances hierarchically."""
    resp = client.post(
        "/api/v1/sql/layer5/enumerate",
        json={
            "target_url": "https://smarttrichy.in/detail.php?id=99",
            "parameter": "id",
            "action": "get_databases",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["action_executed"] == "get_databases"
    assert len(data["databases"]) >= 4
    db_names = [d["name"] for d in data["databases"]]
    assert "smarttrichy_production" in db_names
    assert "information_schema" in db_names
    assert "--dbs" in data["sqlmap_command"]


def test_layer5_get_tables():
    """Verify Layer 5 enumerates tables for a selected database."""
    resp = client.post(
        "/api/v1/sql/layer5/enumerate",
        json={
            "target_url": "https://smarttrichy.in/detail.php?id=99",
            "parameter": "id",
            "action": "get_tables",
            "database_name": "smarttrichy_production",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["action_executed"] == "get_tables"
    assert len(data["tables"]) >= 4
    table_names = [t["name"] for t in data["tables"]]
    assert "users" in table_names
    assert "customer_orders" in table_names
    assert "-D smarttrichy_production --tables" in data["sqlmap_command"]


def test_layer5_get_columns():
    """Verify Layer 5 enumerates schema columns for a selected table."""
    resp = client.post(
        "/api/v1/sql/layer5/enumerate",
        json={
            "target_url": "https://smarttrichy.in/detail.php?id=99",
            "parameter": "id",
            "action": "get_columns",
            "database_name": "smarttrichy_production",
            "table_name": "users",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["action_executed"] == "get_columns"
    assert len(data["columns"]) >= 6
    col_names = [c["name"] for c in data["columns"]]
    assert "username" in col_names
    assert "email" in col_names
    assert "password_hash" in col_names
    assert "-T users --columns" in data["sqlmap_command"]


def test_layer5_dump_records_filtered_columns():
    """Verify Layer 5 dumps records with column selection and pagination."""
    resp = client.post(
        "/api/v1/sql/layer5/enumerate",
        json={
            "target_url": "https://smarttrichy.in/detail.php?id=99",
            "parameter": "id",
            "action": "dump_records",
            "database_name": "smarttrichy_production",
            "table_name": "users",
            "selected_columns": ["username", "email", "role"],
            "limit": 5,
            "offset": 0,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["action_executed"] == "dump_records"
    assert len(data["records"]) <= 5
    assert len(data["records"]) > 0
    # First record must only contain requested columns
    first = data["records"][0]
    assert "username" in first
    assert "email" in first
    assert "role" in first
    assert "password_hash" not in first  # Masked because not selected
    assert "--dump" in data["sqlmap_command"]
    assert "-C \"username,email,role\"" in data["sqlmap_command"]

