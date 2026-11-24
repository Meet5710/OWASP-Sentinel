"""OWASP Sentinel - Path Finder (Authorized Endpoint Discovery) Persistence Tests.

Validates scans and discovered_paths ORM models, foreign key linkage to Authorized Assets,
status updates, and database index fast filtering.
"""

from datetime import datetime, timezone
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.db.asset import AuthorizedAsset
from app.models.db.organization import Organization
from app.models.db.path_finder import DiscoveredPath, PathFinderScan, Scan
from app.models.db.scope import ScopeGrant
from app.models.db.user import User


@pytest.fixture
def db_session():
    """Yield a database session and clean up created fixtures afterwards."""
    session: Session = SessionLocal()
    yield session
    session.close()


def test_path_finder_scan_and_discovered_paths_lifecycle(db_session: Session):
    """Verify creation, relationship linking, indexing, and cascade deletion."""
    # 1. Fetch or create an organization, scope grant, and authorized asset
    asset = db_session.scalars(select(AuthorizedAsset)).first()
    if not asset:
        org = Organization(name="PathFinder Test Org", contact_email="audit@test.com")
        db_session.add(org)
        db_session.flush()

        scope = ScopeGrant(
            organization_id=org.id,
            scope_code="PF-SCOPE-01",
            title="PathFinder Scope",
            authorized_by="Admin",
            valid_from=datetime.now(timezone.utc),
            valid_until=datetime.now(timezone.utc),
        )
        db_session.add(scope)
        db_session.flush()

        asset = AuthorizedAsset(
            organization_id=org.id,
            scope_grant_id=scope.id,
            target_input="https://audit-target.internal",
            canonical_url="https://audit-target.internal/",
            host="audit-target.internal",
            scheme="https",
            port=443,
            path="/",
            approval_status="APPROVED",
        )
        db_session.add(asset)
        db_session.commit()

    # 2. Create a PathFinderScan (or Scan) model linked to target_id
    scan = PathFinderScan(
        target_id=asset.id,
        mode="QUICK",
        config_json={
            "wordlist": "common.txt",
            "threads": 20,
            "extensions": [".php", ".html", ".json"],
            "status_filters": [200, 301, 302, 403],
        },
        status="RUNNING",
        progress_percent=25.0,
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    assert scan.id is not None
    assert scan.target_id == asset.id
    assert scan.mode == "QUICK"
    assert scan.status == "RUNNING"
    assert scan.progress_percent == 25.0
    assert scan.config_json["threads"] == 20
    assert scan.target.host == asset.host

    # 3. Create DiscoveredPath entries linked to scan_id
    path_200 = DiscoveredPath(
        scan_id=scan.id,
        path="/admin/login.php",
        full_url=f"https://{asset.host}/admin/login.php",
        status_code=200,
        content_length=1420,
        content_type="text/html; charset=UTF-8",
        response_time_ms=45.2,
    )
    path_301 = DiscoveredPath(
        scan_id=scan.id,
        path="/dashboard",
        full_url=f"https://{asset.host}/dashboard",
        status_code=301,
        content_length=0,
        content_type="text/html",
        redirect_url=f"https://{asset.host}/dashboard/",
        response_time_ms=32.1,
    )
    path_403 = DiscoveredPath(
        scan_id=scan.id,
        path="/.git/config",
        full_url=f"https://{asset.host}/.git/config",
        status_code=403,
        content_length=280,
        content_type="text/html",
        response_time_ms=18.5,
    )

    db_session.add_all([path_200, path_301, path_403])
    db_session.commit()

    # 4. Fast filtering queries using scan_id and status_code indexes
    stmt_all = (
        select(DiscoveredPath)
        .where(DiscoveredPath.scan_id == scan.id)
        .order_by(DiscoveredPath.status_code)
    )
    all_paths = db_session.scalars(stmt_all).all()
    assert len(all_paths) == 3

    stmt_200 = (
        select(DiscoveredPath)
        .where(
            DiscoveredPath.scan_id == scan.id,
            DiscoveredPath.status_code == 200,
        )
    )
    found_200 = db_session.scalars(stmt_200).all()
    assert len(found_200) == 1
    assert found_200[0].path == "/admin/login.php"
    assert found_200[0].content_length == 1420

    # 5. Update scan progress & complete
    scan.progress_percent = 100.0
    scan.status = "COMPLETED"
    scan.completed_at = datetime.now(timezone.utc)
    db_session.commit()
    db_session.refresh(scan)

    assert scan.status == "COMPLETED"
    assert scan.progress_percent == 100.0
    assert scan.completed_at is not None

    # 6. Verify relationship navigation
    assert len(scan.discovered_paths) == 3

    # 7. Clean up scan and verify cascade deletion of discovered paths
    scan_id = scan.id
    db_session.delete(scan)
    db_session.commit()

    remaining_paths = db_session.scalars(
        select(DiscoveredPath).where(DiscoveredPath.scan_id == scan_id)
    ).all()
    assert len(remaining_paths) == 0

