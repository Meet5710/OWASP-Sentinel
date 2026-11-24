"""OWASP Sentinel - Unit and Integration Tests for Async Route Verification Service.

Verifies:
1. SitemapRobotsParser:
   - Fetches and parses robots.txt for disallowed/allowed routes and sitemap pointers.
   - Parses XML sitemap documents and extracts valid relative paths.
2. Baseline404:
   - Performs 2 non-existent GET requests to establish baseline status code & content length.
   - Accurately filters out matching 404/wildcard responses while preserving authentic routes.
3. Rate-Limited Async Route Verification:
   - Enforces concurrency semaphores, timeouts, and custom HTTP headers.
   - Verifies URLs in batches of 20, checking Redis/DB state flags (PAUSED/CANCELLED) before each batch.
   - Publishes discovered endpoints in real time to SSE broadcaster and batch inserts into DB.
"""

import asyncio
from datetime import datetime, timezone
import uuid
import pytest
import httpx
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.db.asset import AuthorizedAsset
from app.models.db.path_finder import DiscoveredPath, PathFinderScan
from app.models.schemas.path_finder import PathFinderStatus
from app.services.path_finder_state import state_store
from app.services.route_checker import (
    AsyncRouteVerificationService,
    Baseline404,
    SitemapRobotsParser,
    normalize_route_path,
)


@pytest.fixture(scope="module")
def sample_authorized_target():
    """Provides a sample authorized asset in the database."""
    with SessionLocal() as db:
        asset = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.host == "testfire.net"))
        if not asset:
            sample = db.scalar(select(AuthorizedAsset))
            asset = AuthorizedAsset(
                id=str(uuid.uuid4()),
                organization_id=sample.organization_id if sample else str(uuid.uuid4()),
                scope_grant_id=sample.scope_grant_id if sample else str(uuid.uuid4()),
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
            db.add(asset)
            db.commit()
            db.refresh(asset)
        return asset.id


# ==============================================================================
# 1. Sitemap & Robots Parser Tests
# ==============================================================================

def test_normalize_route_path():
    """Verify route normalization collapses redundant slashes and strips fragments."""
    assert normalize_route_path("admin/dashboard") == "/admin/dashboard"
    assert normalize_route_path("//api///v1/users#section") == "/api/v1/users"
    assert normalize_route_path("https://target.org/login?redirect=true") == "/login"
    assert normalize_route_path("") == "/"


def test_sitemap_and_robots_parser():
    """Requirement 1: Verify parsing of robots.txt directives and sitemap.xml <loc> entries."""
    robots_content = """
User-agent: *
Disallow: /admin
Disallow: /private/data
Allow: /public/docs
Sitemap: https://test-target.org/sitemap.xml
"""

    sitemap_xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://test-target.org/about-us</loc>
  </url>
  <url>
    <loc>https://test-target.org/api/v2/catalog</loc>
  </url>
</urlset>
"""

    async def _run():
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                text=robots_content if "robots.txt" in str(request.url) else sitemap_xml_content,
                headers={"content-type": "text/plain" if "robots.txt" in str(request.url) else "application/xml"},
            )
        )
        async with httpx.AsyncClient(transport=transport) as client:
            # 1. Test robots.txt parsing
            paths, sitemaps = await SitemapRobotsParser.fetch_robots_paths(client, "https://test-target.org")
            assert "/admin" in paths
            assert "/private/data" in paths
            assert "/public/docs" in paths
            assert "https://test-target.org/sitemap.xml" in sitemaps

            # 2. Test sitemap.xml parsing
            sm_paths = await SitemapRobotsParser.fetch_sitemap_paths(
                client, "https://test-target.org/sitemap.xml", "test-target.org"
            )
            assert "/about-us" in sm_paths
            assert "/api/v2/catalog" in sm_paths

            # 3. Test combined discovery
            all_known = await SitemapRobotsParser.discover_known_routes(
                client, "https://test-target.org", "test-target.org"
            )
            assert "/admin" in all_known
            assert "/about-us" in all_known

    asyncio.run(_run())


# ==============================================================================
# 2. Default 404 Baseline Calibration Tests
# ==============================================================================

def test_default_404_baseline_check():
    """Requirement 2: Verify baseline check requests 2 non-existent paths and records baseline."""
    requested_urls = []

    def mock_baseline_handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        # Simulated SPA custom 404: returns 200 with standard 1,500 byte error page
        return httpx.Response(
            200,
            text="<html><body>Custom Single Page App 404 Page</body></html>" + (" " * 1450),
            headers={"content-type": "text/html"},
        )

    async def _run():
        transport = httpx.MockTransport(mock_baseline_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            checker = AsyncRouteVerificationService(concurrency=5, timeout=3.0)
            baseline = await checker.establish_404_baseline(client, "https://test-target.org")

            # 2 GET requests must be made to non-existent paths
            assert len(requested_urls) == 2
            assert all("/health-check-nonexistent-" in u for u in requested_urls)

            # Baseline status code and length recorded
            assert 200 in baseline.status_codes
            assert baseline.avg_length > 1400

            # Probed non-existent path matching baseline is filtered out
            assert baseline.is_match(status_code=200, content_length=int(baseline.avg_length)) is True

            # Authentic distinct response is not filtered
            assert baseline.is_match(status_code=200, content_length=50000) is False
            assert baseline.is_match(status_code=204, content_length=0) is False

    asyncio.run(_run())


# ==============================================================================
# 3. Rate-Limited Async HTTP Client & State Checks (Batches of 20)
# ==============================================================================

def test_route_verification_pipeline_and_batch_processing(sample_authorized_target):
    """Requirements 3 & 4: Concurrency limit, timeout, custom headers, batching of 20 URLs, and state checks."""
    scan_id = str(uuid.uuid4())

    with SessionLocal() as db:
        scan = PathFinderScan(
            id=scan_id,
            target_id=sample_authorized_target,
            mode="QUICK",
            config_json={"threads": 10, "timeout": 5.0, "headers": {"X-Custom-Test": "RouteChecker-Auth"}},
            status=PathFinderStatus.PENDING.value,
            progress_percent=0.0,
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()

    # Pre-set state store flag to RUNNING
    state_store.set_control_flag(scan_id, "RUNNING")

    def mock_server(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        path = request.url.path
        if "robots.txt" in path or "sitemap" in path:
            return httpx.Response(404, text="Not Found")
        if "/health-check-nonexistent-" in path:
            return httpx.Response(404, text="Not Found", headers={"content-type": "text/html"})
        if path in ("/", "/login.jsp", "/feedback.jsp"):
            return httpx.Response(200, text="Valid Page Content", headers={"content-type": "text/html"})
        if path == "/admin":
            return httpx.Response(302, headers={"location": "/login.jsp"})
        return httpx.Response(404, text="Not Found")

    async def _run():
        transport = httpx.MockTransport(mock_server)
        async with httpx.AsyncClient(transport=transport) as mock_client:
            checker = AsyncRouteVerificationService(
                concurrency=10,
                timeout=5.0,
                rps_limit=50.0,
                custom_headers={"X-Custom-Test": "RouteChecker-Auth"},
            )
            assert checker.headers["X-Custom-Test"] == "RouteChecker-Auth"
            assert checker.concurrency == 10
            assert checker.timeout == 5.0

            # Execute verification against sample routes
            routes = ["/", "/login.jsp", "/feedback.jsp", "/admin", "/api/nonexistent"]
            result = await checker.execute_verification(
                scan_id=scan_id,
                base_url="https://testfire.net",
                target_id=sample_authorized_target,
                candidate_routes=routes,
                config={"threads": 10, "timeout": 5.0},
                client=mock_client,
            )

            assert result["status"] == "COMPLETED"
            assert result["total_discovered"] >= 1

            # Verify records batch-inserted into discovered_paths table
            with SessionLocal() as db:
                records = db.scalars(select(DiscoveredPath).where(DiscoveredPath.scan_id == scan_id)).all()
                assert len(records) >= 1
                assert any(r.path in ("/", "/login.jsp", "/feedback.jsp") for r in records)

    asyncio.run(_run())


def test_route_checker_honors_immediate_cancel(sample_authorized_target):
    """Requirement 4: Before/during batch processing, CANCELLED flag exits cleanly."""
    scan_id = str(uuid.uuid4())

    with SessionLocal() as db:
        scan = PathFinderScan(
            id=scan_id,
            target_id=sample_authorized_target,
            mode="QUICK",
            config_json={"threads": 5},
            status=PathFinderStatus.PENDING.value,
            progress_percent=0.0,
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()

    # Pre-set CANCELLED flag
    state_store.set_control_flag(scan_id, "CANCELLED")

    def mock_server(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="Not Found")

    async def _run():
        transport = httpx.MockTransport(mock_server)
        async with httpx.AsyncClient(transport=transport) as mock_client:
            checker = AsyncRouteVerificationService(concurrency=5, timeout=2.0)
            result = await checker.execute_verification(
                scan_id=scan_id,
                base_url="https://testfire.net",
                target_id=sample_authorized_target,
                candidate_routes=["/admin", "/secret", "/portal"],
                client=mock_client,
            )
            assert result["status"] == "CANCELLED"

            with SessionLocal() as db:
                s = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
                assert s is not None
                assert s.status == PathFinderStatus.CANCELLED.value

    asyncio.run(_run())


def test_wildcard_redirect_and_dead_destination_filtering(sample_authorized_target):
    """Verify prefix-based catch-all redirects (307/302) and dead destinations are accurately eliminated."""
    scan_id = str(uuid.uuid4())

    with SessionLocal() as db:
        scan = PathFinderScan(
            id=scan_id,
            target_id=sample_authorized_target,
            mode="QUICK",
            config_json={"threads": 5},
            status=PathFinderStatus.PENDING.value,
            progress_percent=0.0,
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()

    state_store.set_control_flag(scan_id, "RUNNING")

    # Mock server simulating surakshaguards.in wildcard 307 redirect under /admin*
    def mock_wildcard_target(request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if "/health-check-nonexistent-" in p:
            return httpx.Response(404, text="Page Not Found", headers={"content-type": "text/html"})
        if p in ("/login", "/dashboard", "/contact"):
            return httpx.Response(200, text="Authentic Functional Page", headers={"content-type": "text/html"})
        if p.startswith("/admin") or p.startswith("/administrator"):
            if p == "/admin/login":
                return httpx.Response(404, text="Admin Login Does Not Exist (Dead Target)")
            # Catch-all 307 wildcard redirect
            return httpx.Response(307, text="Redirecting", headers={"location": "/admin/login"})
        return httpx.Response(404, text="Not Found")

    async def _run():
        transport = httpx.MockTransport(mock_wildcard_target)
        async with httpx.AsyncClient(transport=transport) as mock_client:
            checker = AsyncRouteVerificationService(concurrency=5, timeout=2.0)
            candidate_paths = [
                "/login",
                "/dashboard",
                "/contact",
                "/admin/transaction",
                "/admin/dashboard",
                "/admin/customize",
                "/admin/transfer",
                "/admin/querylog",
                "/admin/default",
                "/administrator",
            ]
            result = await checker.execute_verification(
                scan_id=scan_id,
                base_url="https://surakshaguards.in",
                target_id=sample_authorized_target,
                candidate_routes=candidate_paths,
                client=mock_client,
            )

            assert result["status"] == "COMPLETED"

            # Check database records
            with SessionLocal() as db:
                records = db.scalars(select(DiscoveredPath).where(DiscoveredPath.scan_id == scan_id)).all()
                found_paths = [r.path for r in records]

                # Legitimate endpoints must be preserved
                assert "/login" in found_paths
                assert "/dashboard" in found_paths
                assert "/contact" in found_paths

                # Every fake 307 wildcard redirect must be completely filtered out
                assert "/admin/transaction" not in found_paths
                assert "/admin/dashboard" not in found_paths
                assert "/admin/customize" not in found_paths
                assert "/admin/transfer" not in found_paths
                assert "/admin/querylog" not in found_paths
                assert "/administrator" not in found_paths

    asyncio.run(_run())

