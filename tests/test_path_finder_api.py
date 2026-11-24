"""OWASP Sentinel - Path Finder (Authorized Endpoint Discovery) API Integration Tests."""

from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.db.asset import AuthorizedAsset
from sqlalchemy import select

client = TestClient(app)


def test_path_finder_api_crud_flow():
    # 1. Fetch an existing authorized asset
    with SessionLocal() as db:
        asset = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.approval_status == "APPROVED"))
        assert asset is not None
        asset_id = asset.id

    # 2. Test scan creation with nonexistent asset (should fail with 404)
    resp_404 = client.post(
        "/api/v1/path-finder/scans",
        json={"target_id": "nonexistent-target-id", "mode": "QUICK", "config_json": {}},
    )
    assert resp_404.status_code == 404

    # 3. Create scan for approved target
    create_resp = client.post(
        "/api/v1/path-finder/scans",
        json={
            "target_id": asset_id,
            "mode": "QUICK",
            "config_json": {"wordlist": "common.txt", "threads": 25, "extensions": [".php", ".json"]},
        },
    )
    assert create_resp.status_code == 201
    scan_data = create_resp.json()
    assert scan_data["id"] is not None
    assert scan_data["target_id"] == asset_id
    assert scan_data["mode"] == "QUICK"
    assert scan_data["status"] == "PENDING"
    scan_id = scan_data["id"]

    # 4. List scans
    list_resp = client.get("/api/v1/path-finder/scans", params={"target_id": asset_id})
    assert list_resp.status_code == 200
    scans_list = list_resp.json()
    assert any(s["id"] == scan_id for s in scans_list)

    # 5. Record discovered paths
    paths_payload = [
        {
            "path": "/api/v1/health",
            "full_url": f"https://{asset.host}/api/v1/health",
            "status_code": 200,
            "content_length": 45,
            "content_type": "application/json",
            "response_time_ms": 32.5,
        },
        {
            "path": "/admin/dashboard",
            "full_url": f"https://{asset.host}/admin/dashboard",
            "status_code": 403,
            "content_length": 512,
            "content_type": "text/html",
            "response_time_ms": 28.1,
        },
    ]
    add_paths_resp = client.post(f"/api/v1/path-finder/scans/{scan_id}/paths", json=paths_payload)
    assert add_paths_resp.status_code == 201
    added_paths = add_paths_resp.json()
    assert len(added_paths) == 2

    # 6. Query discovered paths with status_code filter
    filter_200_resp = client.get(
        f"/api/v1/path-finder/scans/{scan_id}/paths",
        params={"status_code": 200},
    )
    assert filter_200_resp.status_code == 200
    filtered_200 = filter_200_resp.json()
    assert len(filtered_200) == 1
    assert filtered_200[0]["path"] == "/api/v1/health"

    # 7. Update status to RUNNING then COMPLETED
    patch_resp = client.patch(
        f"/api/v1/path-finder/scans/{scan_id}/status",
        json={"status": "RUNNING", "progress_percent": 50.0},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "RUNNING"
    assert patch_resp.json()["progress_percent"] == 50.0

    complete_resp = client.patch(
        f"/api/v1/path-finder/scans/{scan_id}/status",
        json={"status": "COMPLETED", "progress_percent": 100.0},
    )
    assert complete_resp.status_code == 200
    assert complete_resp.json()["status"] == "COMPLETED"
    assert complete_resp.json()["completed_at"] is not None

    # 8. Get scan detail
    detail_resp = client.get(f"/api/v1/path-finder/scans/{scan_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["total_discovered_paths"] == 2
    assert len(detail["discovered_paths"]) == 2

    # 9. Delete scan
    del_resp = client.delete(f"/api/v1/path-finder/scans/{scan_id}")
    assert del_resp.status_code == 204

    # Verify deleted
    get_del = client.get(f"/api/v1/path-finder/scans/{scan_id}")
    assert get_del.status_code == 404

