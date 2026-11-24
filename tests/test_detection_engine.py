"""OWASP Sentinel - Detection Engine & Security Checks Tests (Phase 3)

Tests modular security rules (Headers, TLS, Cookies, Information Leakage),
rule registry, OWASP Top 10 coverage matrix, and scanner execution engine.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.schemas.asset import AssetRegisterRequest
from app.models.schemas.scope import ScopeGrantCreate
from app.scanner.context import ScanContext
from app.scanner.engine import ScannerEngine
from app.scanner.registry import rule_registry
from app.scanner.rules.cookies import CookieSecurityCheck
from app.scanner.rules.headers import HttpSecurityHeadersCheck
from app.scanner.rules.info_leak import ServerInformationLeakCheck
from app.scanner.rules.tls import TlsConfigurationCheck
from app.services import asset_service, scope_service


class TestRuleRegistryAndCoverage:
    """Verifies rule registration, metadata completeness, and OWASP coverage matrix."""

    def test_registry_contains_core_rules(self) -> None:
        rules = rule_registry.list_rules()
        assert len(rules) >= 14
        rule_ids = [r.rule_id for r in rules]
        assert "RULE-SEC-001" in rule_ids  # Headers
        assert "RULE-SEC-002" in rule_ids  # TLS
        assert "RULE-SEC-003" in rule_ids  # Cookies
        assert "RULE-SEC-004" in rule_ids  # Info Leaks
        assert "RULE-SEC-005" in rule_ids  # CORS
        assert "RULE-SEC-006" in rule_ids  # Sensitive Files
        assert "RULE-SEC-007" in rule_ids  # HTTP Methods
        assert "RULE-SEC-008" in rule_ids  # Injection
        assert "RULE-SEC-009" in rule_ids  # Insecure Design
        assert "RULE-SEC-010" in rule_ids  # Vulnerable Components
        assert "RULE-SEC-011" in rule_ids  # Auth Failures
        assert "RULE-SEC-012" in rule_ids  # Data Integrity
        assert "RULE-SEC-013" in rule_ids  # Logging & Monitoring
        assert "RULE-SEC-014" in rule_ids  # SSRF

    def test_rules_have_complete_documentation(self) -> None:
        for rule in rule_registry.list_rules():
            meta = rule.to_metadata_dict()
            assert meta["rule_id"]
            assert meta["name"]
            assert meta["description"]
            assert meta["why_it_matters"]
            assert meta["evidence_description"]
            assert len(meta["owasp_category_mappings"]) > 0
            assert meta["remediation_guidance"]
            assert len(meta["references"]) > 0

    def test_coverage_matrix_completeness(self) -> None:
        """Matrix reflects 100% full automated coverage across all 10 OWASP categories."""
        matrix = rule_registry.get_coverage_matrix(edition="2021")
        assert matrix["edition"] == "2021"
        assert matrix["total_categories"] == 10
        assert matrix["categories_with_automated_rules"] == 10
        assert matrix["categories_requiring_manual_review"] == 0
        assert matrix["uncovered_categories"] == 0

        # Verify specific categories
        cat_map = {c["category_code"]: c for c in matrix["coverage_matrix"]}
        assert cat_map["A01:2021"]["coverage_status"] == "AUTOMATED_CHECKS"
        assert cat_map["A02:2021"]["coverage_status"] == "AUTOMATED_CHECKS"
        assert cat_map["A03:2021"]["coverage_status"] == "AUTOMATED_CHECKS"
        assert cat_map["A04:2021"]["coverage_status"] == "AUTOMATED_CHECKS"
        assert cat_map["A05:2021"]["coverage_status"] == "AUTOMATED_CHECKS"
        assert cat_map["A06:2021"]["coverage_status"] == "AUTOMATED_CHECKS"
        assert cat_map["A07:2021"]["coverage_status"] == "AUTOMATED_CHECKS"
        assert cat_map["A08:2021"]["coverage_status"] == "AUTOMATED_CHECKS"
        assert cat_map["A09:2021"]["coverage_status"] == "AUTOMATED_CHECKS"
        assert cat_map["A10:2021"]["coverage_status"] == "AUTOMATED_CHECKS"

    def test_coverage_matrix_2025_completeness(self) -> None:
        """Matrix reflects 100% full automated coverage across all 10 OWASP Top 10: 2025 categories."""
        matrix = rule_registry.get_coverage_matrix(edition="2025")
        assert matrix["edition"] == "2025"
        assert matrix["total_categories"] == 10
        assert matrix["categories_with_automated_rules"] == 10
        assert matrix["categories_requiring_manual_review"] == 0
        assert matrix["uncovered_categories"] == 0

        cat_map = {c["category_code"]: c for c in matrix["coverage_matrix"]}
        for i in range(1, 11):
            code = f"A{i:02d}:2025"
            assert code in cat_map
            assert cat_map[code]["coverage_status"] == "AUTOMATED_CHECKS"
            assert cat_map[code]["automated_rule_count"] >= 1


class TestSecurityRuleLogic:
    """Unit tests for individual detection rule logic."""

    @pytest.mark.anyio
    async def test_headers_rule_detects_missing_headers(self) -> None:
        rule = HttpSecurityHeadersCheck()
        context = ScanContext(
            canonical_url="https://test.example.com/",
            host="test.example.com",
            port=443,
            scheme="https",
            path="/",
            scope_code="TEST-SCOPE",
        )

        mock_resp = httpx.Response(status_code=200, headers={"Content-Type": "text/html"})
        with patch.object(context, "get_target_response", new=AsyncMock(return_value=mock_resp)):
            findings = await rule.check(context)

        types = [f.technical_issue_type for f in findings]
        assert "MISSING_HSTS_HEADER" in types
        assert "MISSING_CSP_HEADER" in types
        assert "MISSING_ANTI_CLICKJACKING_HEADER" in types
        assert "MISSING_X_CONTENT_TYPE_OPTIONS" in types

    @pytest.mark.anyio
    async def test_headers_rule_passes_hardened_headers(self) -> None:
        rule = HttpSecurityHeadersCheck()
        context = ScanContext(
            canonical_url="https://test.example.com/",
            host="test.example.com",
            port=443,
            scheme="https",
            path="/",
            scope_code="TEST-SCOPE",
        )

        mock_resp = httpx.Response(
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
            },
        )
        with patch.object(context, "get_target_response", new=AsyncMock(return_value=mock_resp)):
            findings = await rule.check(context)

        assert len(findings) == 0

    @pytest.mark.anyio
    async def test_cookie_rule_detects_insecure_flags(self) -> None:
        rule = CookieSecurityCheck()
        context = ScanContext(
            canonical_url="https://test.example.com/",
            host="test.example.com",
            port=443,
            scheme="https",
            path="/",
            scope_code="TEST-SCOPE",
        )

        # Insecure cookie lacking Secure, HttpOnly, SameSite
        mock_resp = httpx.Response(
            status_code=200,
            headers={"set-cookie": "session_id=abc12345; Path=/"},
        )
        with patch.object(context, "get_target_response", new=AsyncMock(return_value=mock_resp)):
            findings = await rule.check(context)

        types = [f.technical_issue_type for f in findings]
        assert "COOKIE_MISSING_SECURE" in types
        assert "COOKIE_MISSING_HTTPONLY" in types
        assert "COOKIE_MISSING_SAMESITE" in types

    @pytest.mark.anyio
    async def test_cookie_rule_passes_hardened_cookies(self) -> None:
        rule = CookieSecurityCheck()
        context = ScanContext(
            canonical_url="https://test.example.com/",
            host="test.example.com",
            port=443,
            scheme="https",
            path="/",
            scope_code="TEST-SCOPE",
        )

        # Hardened cookie
        mock_resp = httpx.Response(
            status_code=200,
            headers={"set-cookie": "session_id=abc12345; Path=/; Secure; HttpOnly; SameSite=Strict"},
        )
        with patch.object(context, "get_target_response", new=AsyncMock(return_value=mock_resp)):
            findings = await rule.check(context)

        assert len(findings) == 0

    @pytest.mark.anyio
    async def test_info_leak_detects_banners(self) -> None:
        rule = ServerInformationLeakCheck()
        context = ScanContext(
            canonical_url="https://test.example.com/",
            host="test.example.com",
            port=443,
            scheme="https",
            path="/",
            scope_code="TEST-SCOPE",
        )

        mock_resp = httpx.Response(
            status_code=200,
            headers={
                "Server": "Apache/2.4.49 (Unix) OpenSSL/1.1.1",
                "X-Powered-By": "PHP/7.4.20",
            },
        )
        with patch.object(context, "get_target_response", new=AsyncMock(return_value=mock_resp)):
            findings = await rule.check(context)

        types = [f.technical_issue_type for f in findings]
        assert "SERVER_BANNER_DISCLOSURE" in types
        assert "X_POWERED_BY_DISCLOSURE" in types

    @pytest.mark.anyio
    async def test_tls_rule_flags_cleartext_http(self) -> None:
        rule = TlsConfigurationCheck()
        context = ScanContext(
            canonical_url="http://test.example.com/",
            host="test.example.com",
            port=80,
            scheme="http",
            path="/",
            scope_code="TEST-SCOPE",
        )
        findings = await rule.check(context)
        assert len(findings) == 1
        assert findings[0].technical_issue_type == "CLEARTEXT_TRANSMISSION"


class TestScannerEngineExecution:
    """Verifies end-to-end scanner execution and finding persistence."""

    @pytest.mark.anyio
    async def test_engine_blocks_unauthorized_asset(self, db_session: Session) -> None:
        # Should raise error for non-existent asset
        with pytest.raises(Exception):
            await ScannerEngine.execute_scan(db_session, asset_id="non-existent-id")

    @pytest.mark.anyio
    async def test_engine_executes_scan_on_approved_asset(self, db_session: Session) -> None:
        now = datetime.now(timezone.utc)
        # 1. Create valid Scope
        scope = scope_service.create_scope_grant(
            db_session,
            ScopeGrantCreate(
                organization_name="Scan Test Org",
                scope_code=f"SCOPE-SCAN-{int(now.timestamp())}",
                title="Scanner Engine Test Scope",
                authorized_by="qa@scantest.org",
                valid_from=now,
                valid_until=now + timedelta(days=7),
            ),
        )

        # 2. Register Approved Asset
        asset = asset_service.register_asset(
            db_session,
            AssetRegisterRequest(
                target="https://scan-target.example.com",
                scope_code=scope.scope_code,
                is_authorized=True,
                skip_dns_resolution=True,
            ),
        )

        # 3. Execute Scan with mock responses
        mock_resp = httpx.Response(
            status_code=200,
            headers={
                "Server": "nginx/1.18.0",
                "set-cookie": "tracker=xyz; Path=/",
            },
        )

        with patch.object(ScanContext, "get_target_response", new=AsyncMock(return_value=mock_resp)):
            scan_job = await ScannerEngine.execute_scan(db_session, asset_id=asset.id)

        assert scan_job.status == "COMPLETED"
        assert scan_job.total_checks >= 4
        assert len(scan_job.observations) > 0
        assert scan_job.failed_checks > 0


class TestScanAndRulesAPI:
    """HTTP API integration tests for /rules and /scans."""

    def test_api_list_rules(self, client: TestClient) -> None:
        res = client.get("/api/v1/rules")
        assert res.status_code == status.HTTP_200_OK
        rules = res.json()
        assert len(rules) >= 4
        assert any(r["rule_id"] == "RULE-SEC-001" for r in rules)

    def test_api_coverage_matrix(self, client: TestClient) -> None:
        res = client.get("/api/v1/rules/coverage/matrix?edition=2021")
        assert res.status_code == status.HTTP_200_OK
        data = res.json()
        assert data["edition"] == "2021"
        assert data["total_categories"] == 10
        assert len(data["coverage_matrix"]) == 10

    def test_api_scan_workflow(self, client: TestClient) -> None:
        now = datetime.now(timezone.utc)
        scope_code = f"API-SCAN-SCOPE-{int(now.timestamp())}"

        # 1. Create Scope
        client.post(
            "/api/v1/scopes",
            json={
                "organization_name": "API Scan Client",
                "scope_code": scope_code,
                "title": "API Scope",
                "authorized_by": "api@client.com",
                "valid_from": now.isoformat(),
                "valid_until": (now + timedelta(days=10)).isoformat(),
            },
        )

        # 2. Register Asset
        res_asset = client.post(
            "/api/v1/assets",
            json={
                "target": "https://api-target.example.com",
                "scope_code": scope_code,
                "is_authorized": True,
                "skip_dns_resolution": True,
            },
        )
        asset_id = res_asset.json()["id"]

        # 3. Trigger Scan
        mock_resp = httpx.Response(status_code=200, headers={"Content-Type": "text/html"})
        with patch.object(ScanContext, "get_target_response", new=AsyncMock(return_value=mock_resp)):
            res_scan = client.post(
                "/api/v1/scans/execute",
                json={"asset_id": asset_id},
            )

        assert res_scan.status_code == status.HTTP_201_CREATED
        scan_data = res_scan.json()
        scan_id = scan_data["id"]
        assert scan_data["status"] == "COMPLETED"

        # 4. Fetch Findings
        res_findings = client.get(f"/api/v1/scans/{scan_id}/findings")
        assert res_findings.status_code == status.HTTP_200_OK
        findings = res_findings.json()
        assert len(findings) > 0
        assert all("rule_id" in f and "evidence" in f for f in findings)

    def test_all_19_rules_registered(self) -> None:
        rules = rule_registry.list_rules()
        assert len(rules) == 19
        rule_ids = {r.rule_id for r in rules}
        for i in range(1, 20):
            assert f"RULE-SEC-{i:03d}" in rule_ids

    def test_coverage_matrix_all_four_editions(self, client: TestClient) -> None:
        for ed in ["2025", "2021", "2017", "2013"]:
            res = client.get(f"/api/v1/rules/coverage/matrix?edition={ed}")
            assert res.status_code == status.HTTP_200_OK
            data = res.json()
            assert data["edition"] == ed
            assert data["total_categories"] == 10
            assert data["categories_with_automated_rules"] == 10

    @pytest.mark.anyio
    async def test_new_detection_rules_logic(self) -> None:
        from app.scanner.rules.csrf import CsrfDefenseCheck
        from app.scanner.rules.buffer_overflow import BufferOverflowResilienceCheck
        from app.scanner.rules.dos_resilience import DosResilienceCheck
        from app.scanner.rules.redirects import UnvalidatedRedirectsCheck
        from app.scanner.rules.xxe import XxeInjectionCheck

        ctx = ScanContext(
            canonical_url="https://test.example.com",
            host="test.example.com",
            port=443,
            scheme="https",
            path="/",
            scope_code="TEST-SCOPE",
        )

        # 1. CSRF check
        mock_csrf_resp = httpx.Response(
            status_code=200,
            text='<html><form method="POST" action="/update"><input type="text" name="email"></form></html>',
            headers={"set-cookie": "session_id=12345; Path=/"},
        )
        with patch.object(ScanContext, "get_target_response", new=AsyncMock(return_value=mock_csrf_resp)):
            csrf_findings = await CsrfDefenseCheck().check(ctx)
            assert len(csrf_findings) >= 1
            assert any(f.technical_issue_type == "MISSING_CSRF_TOKEN" for f in csrf_findings)

        # 2. DoS check
        mock_dos_resp = httpx.Response(status_code=200, headers={"Server": "Custom"})
        with patch.object(ScanContext, "get_target_response", new=AsyncMock(return_value=mock_dos_resp)):
            dos_findings = await DosResilienceCheck().check(ctx)
            assert len(dos_findings) >= 1
            assert dos_findings[0].technical_issue_type == "MISSING_RATE_LIMITING_CONTROLS"

    @pytest.mark.anyio
    async def test_kali_practice_scripts_scanning_and_owasp_matching(self) -> None:
        from app.scanner.kali_practice_runner import run_kali_practice_scripts_assessment

        ctx = ScanContext(
            canonical_url="https://kali-target.local:443",
            host="kali-target.local",
            port=443,
            scheme="https",
            path="/login",
            scope_code="TEST-SCOPE",
        )

        mock_target_resp = httpx.Response(
            status_code=200,
            headers={
                "Server": "Apache/2.4.52 (Ubuntu)",
                "Set-Cookie": "session_id=insecure_token; Path=/",
            },
        )
        with patch.object(ScanContext, "get_target_response", new=AsyncMock(return_value=mock_target_resp)):
            observations = await run_kali_practice_scripts_assessment(
                context=ctx,
                scan_id="test-scan-123",
                target_id="test-target-456",
            )

        assert len(observations) >= 3
        # Check that banner, XSS/injection, and cookie/crypto bugs are found
        rule_ids = [o.rule_id for o in observations]
        assert "KALI:PRACTICE:BANNER" in rule_ids
        assert "KALI:PRACTICE:XSS" in rule_ids
        assert "KALI:PRACTICE:CRYPTO" in rule_ids

        # Check empirical evidence includes reproduction CLI command with Practice_Scripts
        for obs in observations:
            assert "Practice_Scripts" in obs.evidence["reproduction_cli"]
            assert obs.evidence["owasp_matched_code"] != ""
            assert obs.evidence["owasp_matched_title"] != ""

        # Check context logs contain Kali execution trace and OWASP correlation
        log_levels = [l["level"] for l in ctx.terminal_logs]
        assert "KALI_INIT" in log_levels
        assert "KALI_BUG" in log_levels
        assert "KALI_OWASP" in log_levels
        assert "KALI_HANDOFF" in log_levels


