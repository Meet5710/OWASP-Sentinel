"""OWASP Sentinel - Comprehensive Path Finder (Authorized Endpoint Discovery) API Tests.

Verifies:
1. Endpoints:
   - POST /api/pathfinder/scans
   - GET /api/pathfinder/scans
   - GET /api/pathfinder/scans/:id
   - POST /api/pathfinder/scans/:id/control
   - GET /api/pathfinder/scans/:id/export
2. Strict Scope Enforcement:
   - Reject unverified target_id (404)
   - Reject non-approved assets (403)
   - Client cannot supply raw unverified URLs
3. Server-side SSRF Protection:
   - Target resolving to loopback (127.0.0.1), private (10.0.0.1, 192.168.1.1),
     or metadata (169.254.169.254) is rejected with HTTP 400 when is_private_ip is False.
4. Non-blocking Immediate Scan Response:
   - Returns scan_id immediately with 201 Created and status PENDING.
"""

from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.db.session import SessionLocal
from app.models.db.asset import AuthorizedAsset
from app.models.db.path_finder import DiscoveredPath, PathFinderScan
from app.models.schemas.path_finder import PathFinderStatus

from unittest.mock import patch

client = TestClient(app)


@pytest.fixture(autouse=True)
def mock_enqueue_scan():
    """Mocks background job queue dispatch to prevent FastAPI TestClient from executing 1200+ network probes synchronously."""
    with patch("app.api.v1.endpoints.path_finder.enqueue_path_finder_scan") as mock_eq:
        mock_eq.return_value = "async_worker"
        yield mock_eq


@pytest.fixture(scope="module")
def setup_test_assets():
    """Sets up approved public asset, non-approved asset, and private SSRF test assets."""
    with SessionLocal() as db:
        # Borrow valid foreign keys from existing assets
        sample_asset = db.scalar(select(AuthorizedAsset))
        assert sample_asset is not None, "At least one sample asset must exist in database"
        org_id = sample_asset.organization_id
        scope_id = sample_asset.scope_grant_id

        # 1. Approved public asset (testfire.net)
        approved_public = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.host == "testfire.net"))
        if not approved_public:
            approved_public = AuthorizedAsset(
                id=str(uuid.uuid4()),
                organization_id=org_id,
                scope_grant_id=scope_id,
                target_input="https://testfire.net/",
                host="testfire.net",
                scheme="https",
                port=443,
                path="/",
                canonical_url="https://testfire.net/",
                approval_status="APPROVED",
                is_private_ip=False,
                is_ip_address=False,
                resolved_ips=["65.61.137.117"],
            )
            db.add(approved_public)

        # 2. Non-approved asset
        pending_asset = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.host == "unapproved-target.example.org"))
        if not pending_asset:
            pending_asset = AuthorizedAsset(
                id=str(uuid.uuid4()),
                organization_id=org_id,
                scope_grant_id=scope_id,
                target_input="https://unapproved-target.example.org/",
                host="unapproved-target.example.org",
                scheme="https",
                port=443,
                path="/",
                canonical_url="https://unapproved-target.example.org/",
                approval_status="PENDING_REVIEW",
                is_private_ip=False,
                is_ip_address=False,
                resolved_ips=[],
            )
            db.add(pending_asset)

        # 3. Disallowed SSRF loopback asset (is_private_ip=False)
        loopback_asset = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.host == "127.0.0.1"))
        if not loopback_asset:
            loopback_asset = AuthorizedAsset(
                id=str(uuid.uuid4()),
                organization_id=org_id,
                scope_grant_id=scope_id,
                target_input="http://127.0.0.1:8080/",
                host="127.0.0.1",
                scheme="http",
                port=8080,
                path="/",
                canonical_url="http://127.0.0.1:8080/",
                approval_status="APPROVED",
                is_private_ip=False,
                is_ip_address=True,
                resolved_ips=["127.0.0.1"],
            )
            db.add(loopback_asset)

        # 4. Disallowed SSRF metadata asset (169.254.169.254)
        metadata_asset = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.host == "169.254.169.254"))
        if not metadata_asset:
            metadata_asset = AuthorizedAsset(
                id=str(uuid.uuid4()),
                organization_id=org_id,
                scope_grant_id=scope_id,
                target_input="http://169.254.169.254/latest/meta-data/",
                host="169.254.169.254",
                scheme="http",
                port=80,
                path="/latest/meta-data/",
                canonical_url="http://169.254.169.254/latest/meta-data/",
                approval_status="APPROVED",
                is_private_ip=False,
                is_ip_address=True,
                resolved_ips=["169.254.169.254"],
            )
            db.add(metadata_asset)

        # 5. Disallowed SSRF private RFC 1918 asset (10.0.0.1)
        private_asset = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.host == "10.0.0.1"))
        if not private_asset:
            private_asset = AuthorizedAsset(
                id=str(uuid.uuid4()),
                organization_id=org_id,
                scope_grant_id=scope_id,
                target_input="http://10.0.0.1/",
                host="10.0.0.1",
                scheme="http",
                port=80,
                path="/",
                canonical_url="http://10.0.0.1/",
                approval_status="APPROVED",
                is_private_ip=False,
                is_ip_address=True,
                resolved_ips=["10.0.0.1"],
            )
            db.add(private_asset)

        # 6. Whitelisted private lab asset (is_private_ip=True)
        whitelisted_lab = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.host == "192.168.1.50"))
        if not whitelisted_lab:
            whitelisted_lab = AuthorizedAsset(
                id=str(uuid.uuid4()),
                organization_id=org_id,
                scope_grant_id=scope_id,
                target_input="http://192.168.1.50:8000/",
                host="192.168.1.50",
                scheme="http",
                port=8000,
                path="/",
                canonical_url="http://192.168.1.50:8000/",
                approval_status="APPROVED",
                is_private_ip=True,
                is_ip_address=True,
                resolved_ips=["192.168.1.50"],
            )
            db.add(whitelisted_lab)

        db.commit()

        db.commit()

        yield {
            "approved_public_id": approved_public.id,
            "pending_asset_id": pending_asset.id,
            "loopback_id": loopback_asset.id,
            "metadata_id": metadata_asset.id,
            "private_id": private_asset.id,
            "whitelisted_lab_id": whitelisted_lab.id,
        }


def test_scope_enforcement_rejects_unregistered_target():
    """Requirement 2: Reject any request where target_id does not exist in inventory (404)."""
    fake_id = str(uuid.uuid4())
    resp = client.post(
        "/api/pathfinder/scans",
        json={"target_id": fake_id, "mode": "QUICK"},
    )
    assert resp.status_code == 404
    assert "not found in authorized inventory" in resp.json()["detail"]


def test_scope_enforcement_rejects_unapproved_target(setup_test_assets):
    """Requirement 2: Reject any request where asset is not APPROVED (403)."""
    resp = client.post(
        "/api/pathfinder/scans",
        json={"target_id": setup_test_assets["pending_asset_id"], "mode": "QUICK"},
    )
    assert resp.status_code == 403
    assert "not APPROVED for security assessments" in resp.json()["detail"]


def test_ssrf_protection_blocks_loopback(setup_test_assets):
    """Requirement 3: Block 127.0.0.1 loopback targets."""
    resp = client.post(
        "/api/pathfinder/scans",
        json={"target_id": setup_test_assets["loopback_id"], "mode": "QUICK"},
    )
    assert resp.status_code == 400
    assert "SSRF" in resp.text or "loopback" in resp.text


def test_ssrf_protection_blocks_cloud_metadata(setup_test_assets):
    """Requirement 3: Block 169.254.169.254 cloud metadata targets."""
    resp = client.post(
        "/api/pathfinder/scans",
        json={"target_id": setup_test_assets["metadata_id"], "mode": "QUICK"},
    )
    assert resp.status_code == 400
    assert "SSRF" in resp.text or "metadata" in resp.text


def test_ssrf_protection_blocks_rfc1918_private(setup_test_assets):
    """Requirement 3: Block 10.0.0.1 private IP targets when not whitelisted."""
    resp = client.post(
        "/api/pathfinder/scans",
        json={"target_id": setup_test_assets["private_id"], "mode": "QUICK"},
    )
    assert resp.status_code == 400
    assert "SSRF" in resp.text or "restricted" in resp.text


def test_ssrf_whitelisted_internal_lab_allowed(setup_test_assets):
    """Internal target with is_private_ip=True is allowed to be scanned."""
    resp = client.post(
        "/api/pathfinder/scans",
        json={"target_id": setup_test_assets["whitelisted_lab_id"], "mode": "QUICK"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["id"] is not None
    assert data["status"] in ("PENDING", "RUNNING")


def test_post_scans_returns_immediately_non_blocking(setup_test_assets):
    """Requirement 1 & 4: POST /api/pathfinder/scans returns created scan_id immediately."""
    resp = client.post(
        "/api/pathfinder/scans",
        json={
            "target_id": setup_test_assets["approved_public_id"],
            "mode": "QUICK",
            "config_json": {"threads": 10},
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data
    assert data["target_id"] == setup_test_assets["approved_public_id"]
    assert data["status"] in ("PENDING", "RUNNING")
    assert data["progress_percent"] >= 0.0


def test_get_scans_with_pagination(setup_test_assets):
    """Requirement 1: GET /api/pathfinder/scans with pagination parameters."""
    resp = client.get("/api/pathfinder/scans", params={"limit": 5, "offset": 0})
    assert resp.status_code == 200
    assert "X-Total-Count" in resp.headers
    assert "X-Limit" in resp.headers
    assert "X-Offset" in resp.headers
    scans = resp.json()
    assert isinstance(scans, list)
    assert len(scans) <= 5

    # Page-based pagination
    resp_page = client.get("/api/pathfinder/scans", params={"page": 1, "page_size": 2})
    assert resp_page.status_code == 200
    assert len(resp_page.json()) <= 2


def test_get_scan_detail_and_query_filters(setup_test_assets):
    """Requirement 1: GET /api/pathfinder/scans/:id with status_code and search filters."""
    # 1. Create a scan
    create_resp = client.post(
        "/api/pathfinder/scans",
        json={"target_id": setup_test_assets["approved_public_id"], "mode": "QUICK"},
    )
    scan_id = create_resp.json()["id"]

    # 2. Insert test discovered paths directly
    with SessionLocal() as db:
        p1 = DiscoveredPath(
            scan_id=scan_id,
            path="/api/v1/health",
            full_url="https://testfire.net/api/v1/health",
            status_code=200,
            content_length=50,
            content_type="application/json",
            response_time_ms=25.0,
            discovered_at=datetime.now(timezone.utc),
        )
        p2 = DiscoveredPath(
            scan_id=scan_id,
            path="/admin/login",
            full_url="https://testfire.net/admin/login",
            status_code=403,
            content_length=120,
            content_type="text/html",
            response_time_ms=30.0,
            discovered_at=datetime.now(timezone.utc),
        )
        p3 = DiscoveredPath(
            scan_id=scan_id,
            path="/api/v2/users",
            full_url="https://testfire.net/api/v2/users",
            status_code=200,
            content_length=80,
            content_type="application/json",
            response_time_ms=22.0,
            discovered_at=datetime.now(timezone.utc),
        )
        db.add_all([p1, p2, p3])
        db.commit()

    # 3. Query scan metadata
    detail_resp = client.get(f"/api/pathfinder/scans/{scan_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == scan_id
    assert detail["total_discovered_paths"] >= 3
    assert len(detail["discovered_paths"]) >= 3

    # 4. Filter by status_code=403
    filter_status_resp = client.get(f"/api/pathfinder/scans/{scan_id}", params={"status_code": 403})
    assert filter_status_resp.status_code == 200
    filtered_by_code = filter_status_resp.json()["discovered_paths"]
    assert len(filtered_by_code) >= 1
    assert all(p["status_code"] == 403 for p in filtered_by_code)

    # 5. Filter by search="admin"
    filter_search_resp = client.get(f"/api/pathfinder/scans/{scan_id}", params={"search": "admin/login"})
    assert filter_search_resp.status_code == 200
    filtered_by_search = filter_search_resp.json()["discovered_paths"]
    assert len(filtered_by_search) >= 1
    assert all("admin/login" in p["path"] for p in filtered_by_search)


def test_post_scan_control_pause_resume_cancel(setup_test_assets):
    """Requirement 1: POST /api/pathfinder/scans/:id/control handles pause, resume, cancel."""
    # Create scan
    create_resp = client.post(
        "/api/pathfinder/scans",
        json={"target_id": setup_test_assets["approved_public_id"], "mode": "QUICK"},
    )
    scan_id = create_resp.json()["id"]

    # Ensure status is RUNNING
    client.patch(f"/api/pathfinder/scans/{scan_id}/status", json={"status": "RUNNING"})

    # 1. Pause
    pause_resp = client.post(f"/api/pathfinder/scans/{scan_id}/control", json={"action": "pause"})
    assert pause_resp.status_code == 200
    assert pause_resp.json()["status"] == "PAUSED"

    # 2. Resume
    resume_resp = client.post(f"/api/pathfinder/scans/{scan_id}/control", json={"action": "resume"})
    assert resume_resp.status_code == 200
    assert resume_resp.json()["status"] == "RUNNING"

    # 3. Cancel
    cancel_resp = client.post(f"/api/pathfinder/scans/{scan_id}/control", json={"action": "cancel"})
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "CANCELLED"
    assert cancel_resp.json()["completed_at"] is not None

    # 4. Invalid action
    invalid_resp = client.post(f"/api/pathfinder/scans/{scan_id}/control", json={"action": "restart_unknown"})
    assert invalid_resp.status_code == 400


def test_export_scan_json_and_csv(setup_test_assets):
    """Requirement 1: GET /api/pathfinder/scans/:id/export as JSON or CSV."""
    # Create scan and seed a path
    create_resp = client.post(
        "/api/pathfinder/scans",
        json={"target_id": setup_test_assets["approved_public_id"], "mode": "QUICK"},
    )
    scan_id = create_resp.json()["id"]

    with SessionLocal() as db:
        p = DiscoveredPath(
            scan_id=scan_id,
            path="/robots.txt",
            full_url="https://testfire.net/robots.txt",
            status_code=200,
            content_length=150,
            content_type="text/plain",
            response_time_ms=18.5,
            discovered_at=datetime.now(timezone.utc),
        )
        db.add(p)
        db.commit()

    # 1. Export as JSON
    json_resp = client.get(f"/api/pathfinder/scans/{scan_id}/export", params={"format": "json"})
    assert json_resp.status_code == 200
    assert json_resp.headers["content-type"].startswith("application/json")
    assert f'filename="pathfinder-scan-{scan_id}.json"' in json_resp.headers["content-disposition"]
    export_json = json_resp.json()
    assert export_json["scan_id"] == scan_id
    assert export_json["total_records"] >= 1
    assert any(item["path"] == "/robots.txt" for item in export_json["paths"])

    # 2. Export as CSV
    csv_resp = client.get(f"/api/pathfinder/scans/{scan_id}/export", params={"format": "csv"})
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert f'filename="pathfinder-scan-{scan_id}.csv"' in csv_resp.headers["content-disposition"]
    csv_text = csv_resp.text
    assert "id,path,full_url,status_code" in csv_text
    assert "/robots.txt" in csv_text


def test_path_finder_state_store_and_control_flags():
    """Requirement 3: Verify fast state store tracks live control flags (PAUSED, CANCELLED) and metrics."""
    from app.services.path_finder_state import state_store

    test_scan_id = str(uuid.uuid4())
    state_store.set_control_flag(test_scan_id, "RUNNING")
    assert state_store.get_control_flag(test_scan_id) == "RUNNING"

    state_store.set_control_flag(test_scan_id, "PAUSED")
    assert state_store.get_control_flag(test_scan_id) == "PAUSED"

    state_store.set_control_flag(test_scan_id, "CANCELLED")
    assert state_store.get_control_flag(test_scan_id) == "CANCELLED"

    # Test metrics tracking
    metrics = {
        "progress_percent": 65.5,
        "requests_per_second": 34.2,
        "total_discovered": 14,
        "status": "RUNNING",
    }
    state_store.set_metrics(test_scan_id, metrics)
    stored = state_store.get_metrics(test_scan_id)
    assert stored["progress_percent"] == 65.5
    assert stored["requests_per_second"] == 34.2
    assert stored["total_discovered"] == 14

    state_store.clear_scan(test_scan_id)
    assert state_store.get_control_flag(test_scan_id) == "RUNNING"


def test_stream_path_finder_scan_sse(setup_test_assets):
    """Requirement 4: Verify SSE endpoint (/api/pathfinder/scans/:id/stream) streams real-time events."""
    create_resp = client.post(
        "/api/pathfinder/scans",
        json={"target_id": setup_test_assets["approved_public_id"], "mode": "QUICK"},
    )
    scan_id = create_resp.json()["id"]

    # Mark completed in DB so stream delivers snapshot + finalized status and closes cleanly
    with SessionLocal() as db:
        s = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
        if s:
            s.status = "COMPLETED"
            db.commit()

    # Request SSE stream with stream context
    with client.stream("GET", f"/api/pathfinder/scans/{scan_id}/stream") as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        lines = [line for line in response.iter_lines() if line]
        full_stream_preview = "\n".join(lines)
        assert "snapshot" in full_stream_preview
        assert "event:" in full_stream_preview or "data:" in full_stream_preview
