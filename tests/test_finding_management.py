"""OWASP Sentinel - Finding Management & Multi-Category Mapping Tests (Phase 5)

Verifies separation of technical findings from OWASP category mappings,
multi-category linkage, validation lifecycle, timestamp tracking, and new detection rules.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.db.asset import AuthorizedAsset
from app.models.db.finding import TechnicalObservation
from app.models.db.scan import ScanJob
from app.models.schemas.asset import AssetRegisterRequest
from app.models.schemas.scope import ScopeGrantCreate
from app.scanner.context import ScanContext
from app.scanner.rules.cors import CorsConfigurationCheck
from app.scanner.rules.http_methods import HttpMethodSecurityCheck
from app.scanner.rules.sensitive_files import SensitiveEndpointExposureCheck
from app.services import asset_service, finding_service, scope_service


@pytest.fixture
def mock_asset_and_scan(db_session: Session) -> tuple[AuthorizedAsset, ScanJob]:
    """Provides a valid Scope, Asset, and ScanJob ensuring foreign key integrity."""
    now = datetime.now(timezone.utc)
    scope = scope_service.create_scope_grant(
        db_session,
        ScopeGrantCreate(
            organization_name="Mock Corp",
            scope_code=f"SCOPE-MOCK-{int(now.timestamp() * 1000)}",
            title="Mock Scope",
            authorized_by="admin@mock.com",
            valid_from=now,
            valid_until=now + timedelta(days=7),
        ),
    )
    asset = asset_service.register_asset(
        db_session,
        AssetRegisterRequest(
            target="https://mock-asset.example.com",
            scope_code=scope.scope_code,
            is_authorized=True,
            skip_dns_resolution=True,
        ),
    )
    scan_job = ScanJob(
        target_id=asset.id,
        scope_grant_id=scope.id,
        status="COMPLETED",
        started_at=now,
        completed_at=now,
    )
    db_session.add(scan_job)
    db_session.commit()
    db_session.refresh(scan_job)
    return asset, scan_job


class TestNewSecurityRules:
    """Unit tests for newly added Phase 5 detection rules."""

    @pytest.mark.anyio
    async def test_cors_rule_detects_origin_reflection(self) -> None:
        rule = CorsConfigurationCheck()
        context = ScanContext(
            canonical_url="https://api.example.com/",
            host="api.example.com",
            port=443,
            scheme="https",
            path="/",
            scope_code="TEST-SCOPE",
        )

        mock_resp = httpx.Response(
            status_code=200,
            headers={
                "access-control-allow-origin": "https://sentinel-security-audit.com",
                "access-control-allow-credentials": "true",
            },
        )
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_resp)):
            findings = await rule.check(context)

        types = [f.technical_issue_type for f in findings]
        assert "CORS_ARBITRARY_ORIGIN_REFLECTION" in types
        assert findings[0].severity == "HIGH"

    @pytest.mark.anyio
    async def test_sensitive_files_detects_git_and_env(self) -> None:
        rule = SensitiveEndpointExposureCheck()
        context = ScanContext(
            canonical_url="https://repo.example.com/",
            host="repo.example.com",
            port=443,
            scheme="https",
            path="/",
            scope_code="TEST-SCOPE",
        )

        async def mock_get(url: Any, **kwargs: Any) -> httpx.Response:
            if ".git/HEAD" in str(url):
                return httpx.Response(status_code=200, text="ref: refs/heads/main\n")
            if ".env" in str(url):
                return httpx.Response(status_code=200, text="APP_KEY=base64:xyz\nDB_PASSWORD=secret123\n")
            return httpx.Response(status_code=404)

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            findings = await rule.check(context)

        types = [f.technical_issue_type for f in findings]
        assert "EXPOSED_GIT_REPOSITORY" in types
        assert "EXPOSED_ENV_FILE" in types
        assert any(f.severity == "CRITICAL" for f in findings)

    @pytest.mark.anyio
    async def test_http_methods_detects_trace(self) -> None:
        rule = HttpMethodSecurityCheck()
        context = ScanContext(
            canonical_url="https://methods.example.com/",
            host="methods.example.com",
            port=443,
            scheme="https",
            path="/",
            scope_code="TEST-SCOPE",
        )

        opt_resp = httpx.Response(status_code=200, headers={"allow": "GET, POST, TRACE, OPTIONS"})
        with patch("httpx.AsyncClient.options", new=AsyncMock(return_value=opt_resp)):
            with patch("httpx.AsyncClient.request", new=AsyncMock(return_value=httpx.Response(status_code=405))):
                findings = await rule.check(context)

        types = [f.technical_issue_type for f in findings]
        assert "HTTP_TRACE_METHOD_ENABLED" in types


class TestFindingServiceAndMultiCategoryMapping:
    """Verifies finding creation, multi-category mapping, status history, and regression detection."""

    def test_multi_category_mapping_creation(
        self, db_session: Session, mock_asset_and_scan: tuple[AuthorizedAsset, ScanJob]
    ) -> None:
        asset, scan_job = mock_asset_and_scan
        obs = TechnicalObservation(
            scan_id=scan_job.id,
            target_id=asset.id,
            rule_id="RULE-SEC-005",  # CORS check maps to both A01 and A05
            title="CORS Origin Reflection",
            technical_issue_type="CORS_ARBITRARY_ORIGIN_REFLECTION",
            severity="HIGH",
            confidence="CERTAIN",
            evidence={"origin": "attacker.com"},
            remediation="Fix CORS allowlist",
            references=["https://owasp.org"],
        )
        db_session.add(obs)
        db_session.commit()

        findings = finding_service.process_observations_into_findings(
            db=db_session,
            scan_id=scan_job.id,
            target_id=asset.id,
            observations=[obs],
        )

        assert len(findings) == 1
        finding = findings[0]
        assert finding.validation_status == "CONFIRMED"
        assert len(finding.status_history) == 1

        # Must map to multiple categories under OWASP 2021: A01 and A05
        mappings_2021 = [m for m in finding.category_mappings if m.owasp_edition == "2021"]
        assert len(mappings_2021) >= 2
        cat_codes = [m.owasp_category_code for m in mappings_2021]
        assert "A01:2021" in cat_codes
        assert "A05:2021" in cat_codes
        assert all(len(m.justification) > 10 for m in mappings_2021)

    def test_finding_status_lifecycle_and_regression(
        self, db_session: Session, mock_asset_and_scan: tuple[AuthorizedAsset, ScanJob]
    ) -> None:
        asset, scan_job = mock_asset_and_scan
        obs = TechnicalObservation(
            scan_id=scan_job.id,
            target_id=asset.id,
            rule_id="RULE-SEC-001",
            title="Missing HSTS",
            technical_issue_type="MISSING_HSTS_HEADER",
            severity="MEDIUM",
            confidence="CERTAIN",
            evidence={"header": "Strict-Transport-Security"},
            remediation="Add HSTS",
            references=[],
        )
        db_session.add(obs)
        db_session.commit()

        # Initial finding creation
        findings = finding_service.process_observations_into_findings(
            db=db_session,
            scan_id=scan_job.id,
            target_id=asset.id,
            observations=[obs],
        )
        finding_id = findings[0].id

        # Auditor marks as MITIGATED
        updated = finding_service.update_finding_status(
            db=db_session,
            finding_id=finding_id,
            new_status="MITIGATED",
            actor="engineer@acme.com",
            note="Deployed Nginx header configuration",
        )
        assert updated.validation_status == "MITIGATED"
        assert len(updated.status_history) == 2

        # Re-scan occurs (Scan 002) and re-observes the issue!
        now2 = datetime.now(timezone.utc)
        scan_job_2 = ScanJob(
            target_id=asset.id,
            scope_grant_id=asset.scope_grant_id,
            status="COMPLETED",
            started_at=now2,
            completed_at=now2,
        )
        db_session.add(scan_job_2)
        db_session.commit()

        obs2 = TechnicalObservation(
            scan_id=scan_job_2.id,
            target_id=asset.id,
            rule_id="RULE-SEC-001",
            title="Missing HSTS",
            technical_issue_type="MISSING_HSTS_HEADER",
            severity="MEDIUM",
            confidence="CERTAIN",
            evidence={"header": "Strict-Transport-Security"},
            remediation="Add HSTS",
            references=[],
        )
        db_session.add(obs2)
        db_session.commit()

        rescan_findings = finding_service.process_observations_into_findings(
            db=db_session,
            scan_id=scan_job_2.id,
            target_id=asset.id,
            observations=[obs2],
        )

        rescan_finding = rescan_findings[0]
        # Must detect regression and transition back to CONFIRMED!
        assert rescan_finding.validation_status == "CONFIRMED"
        assert len(rescan_finding.status_history) == 3
        assert "Regression detected" in rescan_finding.status_history[-1]["note"]


class TestFindingAPIEndpoints:
    """HTTP API integration tests for /api/v1/findings."""

    def test_api_findings_flow(self, client: TestClient) -> None:
        now = datetime.now(timezone.utc)
        scope_code = f"SCOPE-FIND-{int(now.timestamp())}"

        # 1. Setup Scope & Asset
        client.post(
            "/api/v1/scopes",
            json={
                "organization_name": "Finding Test Corp",
                "scope_code": scope_code,
                "title": "Finding Scope",
                "authorized_by": "lead@finding.com",
                "valid_from": now.isoformat(),
                "valid_until": (now + timedelta(days=5)).isoformat(),
            },
        )
        res_asset = client.post(
            "/api/v1/assets",
            json={
                "target": "https://finding-target.example.com",
                "scope_code": scope_code,
                "is_authorized": True,
                "skip_dns_resolution": True,
            },
        )
        asset_id = res_asset.json()["id"]

        # 2. Trigger Scan
        mock_resp = httpx.Response(
            status_code=200,
            headers={
                "Server": "Apache/2.4.41",
                "set-cookie": "session=123; Path=/",
                "access-control-allow-origin": "https://sentinel-security-audit.com",
                "access-control-allow-credentials": "true",
            },
        )
        with patch.object(ScanContext, "get_target_response", new=AsyncMock(return_value=mock_resp)):
            with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_resp)):
                client.post("/api/v1/scans/execute", json={"asset_id": asset_id})

        # 3. List Findings with filters
        res_list = client.get("/api/v1/findings?severity=HIGH")
        assert res_list.status_code == status.HTTP_200_OK
        high_findings = res_list.json()
        assert len(high_findings) > 0
        assert all(f["severity"] == "HIGH" for f in high_findings)

        # 4. Get Finding by ID
        finding_id = high_findings[0]["id"]
        res_single = client.get(f"/api/v1/findings/{finding_id}")
        assert res_single.status_code == status.HTTP_200_OK
        single_data = res_single.json()
        assert single_data["id"] == finding_id
        assert len(single_data["category_mappings"]) > 0

        # 5. Update Status to FALSE_POSITIVE
        res_status = client.patch(
            f"/api/v1/findings/{finding_id}/status",
            json={
                "validation_status": "FALSE_POSITIVE",
                "actor": "auditor@acme.com",
                "note": "Verified internal sandbox header",
            },
        )
        assert res_status.status_code == status.HTTP_200_OK
        assert res_status.json()["validation_status"] == "FALSE_POSITIVE"

        # 6. Get OWASP Summary Stats
        res_summary = client.get("/api/v1/findings/stats/owasp-summary?edition=2021")
        assert res_summary.status_code == status.HTTP_200_OK
        summary_data = res_summary.json()
        assert summary_data["edition"] == "2021"
        assert summary_data["total_findings"] > 0
        assert len(summary_data["category_summaries"]) > 0
