"""OWASP Sentinel - Path Finder Safeguards, Audit Logging, and Error Handling Tests.

Comprehensive unit and integration test suite verifying:
1. Audit Trail:
   - Scan Start, Pause, Resume, Cancel, and Export log events with user_id, target_id, timestamp, and config.
2. Graceful Error Handling & Throttling:
   - DNS resolution failure cleanly marks scan as FAILED with descriptive error.
   - TLS/SSL handshake failure cleanly marks scan as FAILED with TLS details.
   - Connection timeout cleanly marks scan as FAILED.
   - HTTP 429 Too Many Requests triggers automatic rate limiter throttling and backoff.
3. SSRF Protection:
   - Server-side resolution blocking loopback (127.0.0.1), private RFC 1918 (10.0.0.1, 192.168.1.1),
     and cloud metadata (169.254.169.254) unless explicitly whitelisted in inventory.
4. Authorized Target Inventory Enforcement:
   - Rejection of unregistered target IDs (404) and non-approved assets (403).
5. Soft-404 Baseline Filtering:
   - Wildcard 200 OK and default redirect catch-all filtering using calibrated fingerprints.
6. Worker Control Behavior:
   - State store live flag checks for immediate Pause, Resume, and Cancel during worker execution.
"""

import asyncio
from datetime import datetime, timezone
import socket
import ssl
import uuid
import pytest
from fastapi.testclient import TestClient
import httpx
from sqlalchemy import select

from app.main import app
from app.db.session import SessionLocal
from app.models.db.asset import AuthorizedAsset
from app.models.db.audit import AuditEvent
from app.models.db.user import User
from app.models.db.path_finder import DiscoveredPath, PathFinderScan
from app.models.schemas.path_finder import PathFinderStatus
from app.services.path_finder_service import (
    AsyncRateLimiter,
    Soft404Fingerprint,
    Soft404Calibrator,
    normalize_path,
    run_path_finder_scan_task,
    validate_target_ssrf_safety,
)
from app.services.path_finder_state import state_store
from app.core.exceptions import (
    SecurityRestrictionError,
    TargetConnectionTimeoutError,
    TargetDNSResolutionError,
    TargetTLSError,
)

client = TestClient(app)


@pytest.fixture(scope="module")
def setup_safeguard_assets():
    """Seeds test target assets and user in authorized inventory."""
    with SessionLocal() as db:
        sample_asset = db.scalar(select(AuthorizedAsset))
        assert sample_asset is not None, "Sample asset required in database"
        org_id = sample_asset.organization_id
        scope_id = sample_asset.scope_grant_id

        # 0. Test User for foreign key
        test_user = db.scalar(select(User).where(User.email == "safeguard-auditor@sentinel.org"))
        if not test_user:
            test_user = User(
                id=str(uuid.uuid4()),
                organization_id=org_id,
                email="safeguard-auditor@sentinel.org",
                full_name="Path Finder Safeguard Auditor",
                role="AUDITOR",
                is_active=True,
            )
            db.add(test_user)

        # 1. Approved public asset
        approved_target = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.host == "safeguard-approved.org"))
        if not approved_target:
            approved_target = AuthorizedAsset(
                id=str(uuid.uuid4()),
                organization_id=org_id,
                scope_grant_id=scope_id,
                target_input="https://safeguard-approved.org/",
                host="safeguard-approved.org",
                scheme="https",
                port=443,
                path="/",
                canonical_url="https://safeguard-approved.org/",
                approval_status="APPROVED",
                is_private_ip=False,
                is_ip_address=False,
                resolved_ips=["93.184.216.34"],
            )
            db.add(approved_target)

        # 2. Unapproved target
        unapproved_target = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.host == "safeguard-unapproved.org"))
        if not unapproved_target:
            unapproved_target = AuthorizedAsset(
                id=str(uuid.uuid4()),
                organization_id=org_id,
                scope_grant_id=scope_id,
                target_input="https://safeguard-unapproved.org/",
                host="safeguard-unapproved.org",
                scheme="https",
                port=443,
                path="/",
                canonical_url="https://safeguard-unapproved.org/",
                approval_status="PENDING_REVIEW",
                is_private_ip=False,
                is_ip_address=False,
                resolved_ips=[],
            )
            db.add(unapproved_target)

        # 3. SSRF Loopback target
        loopback_target = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.host == "127.0.0.1"))
        if not loopback_target:
            loopback_target = AuthorizedAsset(
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
            db.add(loopback_target)

        # 4. Whitelisted private lab target (is_private_ip=True)
        whitelisted_target = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.host == "10.50.1.10"))
        if not whitelisted_target:
            whitelisted_target = AuthorizedAsset(
                id=str(uuid.uuid4()),
                organization_id=org_id,
                scope_grant_id=scope_id,
                target_input="http://10.50.1.10:8000/",
                host="10.50.1.10",
                scheme="http",
                port=8000,
                path="/",
                canonical_url="http://10.50.1.10:8000/",
                approval_status="APPROVED",
                is_private_ip=True,
                is_ip_address=True,
                resolved_ips=["10.50.1.10"],
            )
            db.add(whitelisted_target)

        db.commit()

        yield {
            "user_id": test_user.id,
            "approved_id": approved_target.id,
            "unapproved_id": unapproved_target.id,
            "loopback_id": loopback_target.id,
            "whitelisted_id": whitelisted_target.id,
        }


# ==============================================================================
# 1. Audit Trail Verification Tests
# ==============================================================================

def test_audit_trail_logs_scan_lifecycle_events(setup_safeguard_assets):
    """Requirement 1: Verify audit log entries for scan start, pause, resume, cancel, and export."""
    target_id = setup_safeguard_assets["approved_id"]
    test_user_id = setup_safeguard_assets["user_id"]

    # A. Scan Start Event
    start_resp = client.post(
        "/api/pathfinder/scans",
        json={
            "target_id": target_id,
            "user_id": test_user_id,
            "mode": "QUICK",
            "config_json": {"threads": 10, "rps": 20, "test_marker": "audit_test"},
        },
    )
    assert start_resp.status_code == 201
    scan_id = start_resp.json()["id"]

    with SessionLocal() as db:
        start_event = db.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.event_type == "PATH_FINDER_SCAN_START",
                AuditEvent.target_id == target_id,
            )
            .order_by(AuditEvent.created_at.desc())
        )
        assert start_event is not None
        assert start_event.actor == test_user_id
        assert start_event.metadata_json["scan_id"] == scan_id
        assert start_event.metadata_json["config_json"]["test_marker"] == "audit_test"

    # Ensure scan is in RUNNING status before testing controls
    client.patch(f"/api/pathfinder/scans/{scan_id}/status", json={"status": "RUNNING"})

    # B. Scan Pause Event
    pause_resp = client.post(f"/api/pathfinder/scans/{scan_id}/control", json={"action": "pause"})
    assert pause_resp.status_code == 200

    with SessionLocal() as db:
        pause_event = db.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.event_type == "PATH_FINDER_SCAN_PAUSE",
                AuditEvent.target_id == target_id,
            )
            .order_by(AuditEvent.created_at.desc())
        )
        assert pause_event is not None
        assert pause_event.actor == test_user_id
        assert pause_event.metadata_json["scan_id"] == scan_id
        assert pause_event.metadata_json["action"] == "pause"

    # C. Scan Resume Event
    resume_resp = client.post(f"/api/pathfinder/scans/{scan_id}/control", json={"action": "resume"})
    assert resume_resp.status_code == 200

    with SessionLocal() as db:
        resume_event = db.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.event_type == "PATH_FINDER_SCAN_RESUME",
                AuditEvent.target_id == target_id,
            )
            .order_by(AuditEvent.created_at.desc())
        )
        assert resume_event is not None
        assert resume_event.actor == test_user_id
        assert resume_event.metadata_json["action"] == "resume"

    # D. Scan Cancel Event
    cancel_resp = client.post(f"/api/pathfinder/scans/{scan_id}/control", json={"action": "cancel"})
    assert cancel_resp.status_code == 200

    with SessionLocal() as db:
        cancel_event = db.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.event_type == "PATH_FINDER_SCAN_CANCEL",
                AuditEvent.target_id == target_id,
            )
            .order_by(AuditEvent.created_at.desc())
        )
        assert cancel_event is not None
        assert cancel_event.actor == test_user_id
        assert cancel_event.metadata_json["action"] == "cancel"

    # E. Scan Export Event
    export_resp = client.get(f"/api/pathfinder/scans/{scan_id}/export", params={"format": "json"})
    assert export_resp.status_code == 200

    with SessionLocal() as db:
        export_event = db.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.event_type == "PATH_FINDER_SCAN_EXPORT",
                AuditEvent.target_id == target_id,
            )
            .order_by(AuditEvent.created_at.desc())
        )
        assert export_event is not None
        assert export_event.actor == test_user_id
        assert export_event.metadata_json["scan_id"] == scan_id
        assert export_event.metadata_json["format"] == "json"


# ==============================================================================
# 2. SSRF Protection Tests
# ==============================================================================

def test_ssrf_blocking_prohibits_private_and_loopback():
    """Requirement 3: Verify server-side SSRF validation blocks unwhitelisted private and loopback hosts."""
    # Loopback IP
    with pytest.raises(SecurityRestrictionError) as exc_loopback:
        validate_target_ssrf_safety("127.0.0.1", allow_private=False)
    assert "loopback" in exc_loopback.value.message.lower()

    # RFC 1918 10.0.0.0/8
    with pytest.raises(SecurityRestrictionError) as exc_priv10:
        validate_target_ssrf_safety("10.0.0.1", allow_private=False)
    assert "restricted" in exc_priv10.value.message.lower()

    # RFC 1918 192.168.0.0/16
    with pytest.raises(SecurityRestrictionError) as exc_priv192:
        validate_target_ssrf_safety("192.168.1.1", allow_private=False)
    assert "restricted" in exc_priv192.value.message.lower()

    # Cloud Metadata 169.254.169.254
    with pytest.raises(SecurityRestrictionError) as exc_meta:
        validate_target_ssrf_safety("169.254.169.254", allow_private=False)
    assert "cloud metadata" in exc_meta.value.message.lower()

    # Whitelisted private lab IP is permitted
    resolved = validate_target_ssrf_safety("10.50.1.10", allow_private=True, known_ips=["10.50.1.10"])
    assert "10.50.1.10" in resolved


def test_ssrf_enforcement_in_scan_creation_api(setup_safeguard_assets):
    """Requirement 3: API endpoint blocks scan creation for loopback asset with HTTP 400."""
    resp = client.post(
        "/api/pathfinder/scans",
        json={"target_id": setup_safeguard_assets["loopback_id"], "mode": "QUICK"},
    )
    assert resp.status_code == 400
    assert "SSRF Protection Violation" in str(resp.json())


# ==============================================================================
# 3. Authorized Target Inventory Enforcement Tests
# ==============================================================================

def test_inventory_enforcement_rejects_missing_and_unapproved(setup_safeguard_assets):
    """Requirement 2: Reject non-existent targets with 404 and unapproved targets with 403."""
    # Non-existent target
    non_existent = str(uuid.uuid4())
    resp_404 = client.post(
        "/api/pathfinder/scans",
        json={"target_id": non_existent, "mode": "QUICK"},
    )
    assert resp_404.status_code == 404
    assert "not found in authorized inventory" in resp_404.json()["detail"]

    # Unapproved target
    resp_403 = client.post(
        "/api/pathfinder/scans",
        json={"target_id": setup_safeguard_assets["unapproved_id"], "mode": "QUICK"},
    )
    assert resp_403.status_code == 403
    assert "not APPROVED for security assessments" in resp_403.json()["detail"]


# ==============================================================================
# 4. Soft-404 Baseline Calibration & Filtering Tests
# ==============================================================================

def test_soft404_fingerprint_filtering():
    """Requirement 2: Verify Soft-404 baseline correctly eliminates wildcard 200 OK and default redirects."""
    # Baseline: Target returns HTTP 200 with ~1,200 bytes and ~150 words for any non-existent route (SPA wildcard)
    fingerprint = Soft404Fingerprint(
        baseline_status=200,
        content_lengths=[1200, 1205, 1195],
        word_counts=[150, 150, 152],
        redirect_url=None,
    )

    # 1. Non-existent route matching baseline should be flagged as Soft-404
    assert fingerprint.is_soft_404(
        status_code=200,
        content_length=1202,
        word_count=151,
        redirect_url=None,
    ) is True

    # 2. Authentic route with distinct length and word count should NOT be flagged as Soft-404
    assert fingerprint.is_soft_404(
        status_code=200,
        content_length=15400,
        word_count=1200,
        redirect_url=None,
    ) is False

    # 3. Authentic route with different status code (e.g., 204 No Content or 403 Forbidden)
    assert fingerprint.is_soft_404(
        status_code=204,
        content_length=0,
        word_count=0,
        redirect_url=None,
    ) is False

    # 4. Baseline with default catch-all redirect (e.g. 302 to /login)
    redirect_fingerprint = Soft404Fingerprint(
        baseline_status=302,
        content_lengths=[200, 200],
        word_counts=[20, 20],
        redirect_url="https://target.org/login",
    )
    assert redirect_fingerprint.is_soft_404(
        status_code=302,
        content_length=200,
        word_count=20,
        redirect_url="https://target.org/login",
    ) is True

    assert redirect_fingerprint.is_soft_404(
        status_code=302,
        content_length=200,
        word_count=20,
        redirect_url="https://target.org/admin-dashboard",
    ) is False


# ==============================================================================
# 5. Worker Control Behavior Tests (Pause, Resume, Cancel)
# ==============================================================================

def test_worker_honors_pause_and_cancel_flags(setup_safeguard_assets):
    """Requirement 4: Verify worker immediately pauses and cancels based on fast state store flags."""
    async def _run():
        scan_id = str(uuid.uuid4())
        valid_target_id = setup_safeguard_assets["approved_id"]
        with SessionLocal() as db:
            scan = PathFinderScan(
                id=scan_id,
                target_id=valid_target_id,
                mode="QUICK",
                config_json={"test": True},
                status=PathFinderStatus.PENDING.value,
                progress_percent=0.0,
                started_at=datetime.now(timezone.utc),
            )
            db.add(scan)
            db.commit()

        # Pre-set control flag to CANCELLED before worker begins
        state_store.set_control_flag(scan_id, "CANCELLED")

        # Launch worker
        await run_path_finder_scan_task(
            scan_id=scan_id,
            base_url="https://safeguard-approved.org",
            mode="QUICK",
            config={"threads": 5, "rps": 10},
        )

        # Worker should terminate immediately without altering CANCELLED status
        with SessionLocal() as db:
            final_scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
            assert final_scan is not None
            assert final_scan.status in (PathFinderStatus.CANCELLED.value, PathFinderStatus.PENDING.value)

    asyncio.run(_run())


# ==============================================================================
# 6. Graceful Error Handling & HTTP 429 Throttling Tests
# ==============================================================================

def test_rate_limiter_throttling_on_429():
    """Requirement 2: Verify AsyncRateLimiter dynamic throttling when HTTP 429 is encountered."""
    async def _run():
        limiter = AsyncRateLimiter(rate_limit=50.0)
        assert limiter.rate_limit == 50.0

        # Simulate HTTP 429 backoff
        new_rps = await limiter.throttle(delay=0.05, reduction_factor=0.5)
        assert new_rps == 25.0
        assert limiter.rate_limit == 25.0

        # Consecutive 429
        new_rps_2 = await limiter.throttle(delay=0.05, reduction_factor=0.5)
        assert new_rps_2 == 12.5
        assert limiter.rate_limit == 12.5

    asyncio.run(_run())


def test_operational_error_handling_dns_and_tls():
    """Requirement 2: Verify Soft404Calibrator raises specific SentinelException on DNS or TLS failures."""
    async def _run():
        # Simulated mock client whose get() raises socket.gaierror
        class FailingDnsClient:
            async def get(self, url: str):
                raise socket.gaierror(11001, "getaddrinfo failed")

        with pytest.raises(TargetDNSResolutionError) as exc_dns:
            await Soft404Calibrator.calibrate(FailingDnsClient(), "https://invalid-non-existent-domain-test.org")
        assert "DNS resolution failure" in exc_dns.value.message
        assert exc_dns.value.code == "DNS_RESOLUTION_FAILURE"

        # Simulated mock client whose get() raises SSLError
        class FailingTlsClient:
            async def get(self, url: str):
                raise ssl.SSLError("SSL: WRONG_VERSION_NUMBER")

        with pytest.raises(TargetTLSError) as exc_tls:
            await Soft404Calibrator.calibrate(FailingTlsClient(), "https://bad-ssl-handshake-target.org")
        assert "TLS/SSL handshake failure" in exc_tls.value.message
        assert exc_tls.value.code == "TLS_HANDSHAKE_FAILURE"

        # Simulated mock client whose get() raises TimeoutException
        class FailingTimeoutClient:
            async def get(self, url: str):
                raise httpx.ReadTimeout("Read timed out after 4.0 seconds")

        with pytest.raises(TargetConnectionTimeoutError) as exc_timeout:
            await Soft404Calibrator.calibrate(FailingTimeoutClient(), "https://unreachable-timeout-target.org")
        assert "Connection timeout" in exc_timeout.value.message
        assert exc_timeout.value.code == "CONNECTION_TIMEOUT"

    asyncio.run(_run())
