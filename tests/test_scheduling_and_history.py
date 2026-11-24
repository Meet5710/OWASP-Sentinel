"""OWASP Sentinel - Scan Scheduling & Patch Verification Tests (Phase 6)

Verifies recurrence interval calculations, cron syntax, automated patch verification,
historical posture trend generation, and API endpoints.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.exceptions import SentinelException
from app.models.db.asset import AuthorizedAsset
from app.models.schemas.asset import AssetRegisterRequest
from app.models.schemas.scope import ScopeGrantCreate
from app.scanner.context import ScanContext
from app.scanner.engine import ScannerEngine
from app.services import asset_service, scheduler_service, scope_service


@pytest.fixture
def scheduled_asset(db_session: Session) -> AuthorizedAsset:
    """Creates an approved asset ready for recurring assessment schedules."""
    now = datetime.now(timezone.utc)
    scope = scope_service.create_scope_grant(
        db_session,
        ScopeGrantCreate(
            organization_name="Schedule Corp",
            scope_code=f"SCOPE-SCHED-{int(now.timestamp() * 1000)}",
            title="Scheduled Assessment Scope",
            authorized_by="scheduler@acme.com",
            valid_from=now - timedelta(days=1),
            valid_until=now + timedelta(days=60),
        ),
    )
    return asset_service.register_asset(
        db_session,
        AssetRegisterRequest(
            target="https://sched-target.example.com",
            scope_code=scope.scope_code,
            is_authorized=True,
            skip_dns_resolution=True,
        ),
    )


class TestRecurrenceCalculations:
    """Verifies interval and cron next-run time arithmetic."""

    def test_daily_interval_calculation(self) -> None:
        base = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
        next_run = scheduler_service.calculate_next_run("DAILY", base_time=base)
        assert next_run == base + timedelta(days=1)

    def test_weekly_interval_calculation(self) -> None:
        base = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
        next_run = scheduler_service.calculate_next_run("WEEKLY", base_time=base)
        assert next_run == base + timedelta(days=7)

    def test_cron_syntax_calculation(self) -> None:
        base = datetime(2026, 10, 1, 1, 0, 0, tzinfo=timezone.utc)
        # Daily at 2:00 AM UTC
        next_run = scheduler_service.calculate_next_run("CRON", cron_expr="0 2 * * *", base_time=base)
        assert next_run == datetime(2026, 10, 1, 2, 0, 0, tzinfo=timezone.utc)

    def test_invalid_cron_raises_exception(self) -> None:
        with pytest.raises(SentinelException) as exc_info:
            scheduler_service.calculate_next_run("CRON", cron_expr="invalid cron string")
        assert exc_info.value.code == "INVALID_CRON"


class TestSchedulerServiceLifecycle:
    """Tests schedule registration, pause/resume, and due scan execution."""

    def test_create_schedule_success(self, db_session: Session, scheduled_asset: AuthorizedAsset) -> None:
        schedule = scheduler_service.create_schedule(
            db=db_session,
            target_id=scheduled_asset.id,
            frequency="DAILY",
        )
        assert schedule.id is not None
        assert schedule.target_id == scheduled_asset.id
        assert schedule.frequency == "DAILY"
        assert schedule.is_active is True
        next_run = (
            schedule.next_run_at if schedule.next_run_at.tzinfo else schedule.next_run_at.replace(tzinfo=timezone.utc)
        )
        assert next_run > datetime.now(timezone.utc)

    @pytest.mark.anyio
    async def test_trigger_due_schedules_executes_scan(
        self, db_session: Session, scheduled_asset: AuthorizedAsset
    ) -> None:
        # Create schedule and backdate next_run_at to past so it is due
        schedule = scheduler_service.create_schedule(
            db=db_session,
            target_id=scheduled_asset.id,
            frequency="WEEKLY",
        )
        schedule.next_run_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db_session.commit()

        mock_resp = httpx.Response(status_code=200, headers={"Content-Type": "text/html"})
        with patch.object(ScanContext, "get_target_response", new=AsyncMock(return_value=mock_resp)):
            executed_jobs = await scheduler_service.trigger_due_schedules(db_session)

        assert len(executed_jobs) >= 1
        db_session.refresh(schedule)
        assert schedule.last_run_at is not None
        assert schedule.last_scan_id == executed_jobs[0].id
        # next_run_at must advance into the future
        next_run = (
            schedule.next_run_at if schedule.next_run_at.tzinfo else schedule.next_run_at.replace(tzinfo=timezone.utc)
        )
        assert next_run > datetime.now(timezone.utc)


class TestPatchVerificationDiffing:
    """Verifies tracking whether previously detected issues remain present or are remediated."""

    @pytest.mark.anyio
    async def test_automated_patch_remediation_and_regression(
        self, db_session: Session, scheduled_asset: AuthorizedAsset
    ) -> None:
        # Scan 1: Missing HSTS and verbose Server banner
        resp_scan1 = httpx.Response(
            status_code=200,
            headers={"Server": "Apache/2.4.41", "Content-Type": "text/html"},
        )
        with patch.object(ScanContext, "get_target_response", new=AsyncMock(return_value=resp_scan1)):
            scan1 = await ScannerEngine.execute_scan(db_session, scheduled_asset.id)

        # Baseline history record
        hist1 = scheduler_service.evaluate_patch_verification_and_history(
            db=db_session, target_id=scheduled_asset.id, current_scan_id=scan1.id
        )
        assert hist1.total_findings > 0

        # Scan 2: Target owner fixed HSTS and hardened Server banner!
        resp_scan2 = httpx.Response(
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Type": "text/html",
            },
        )
        with patch.object(ScanContext, "get_target_response", new=AsyncMock(return_value=resp_scan2)):
            scan2 = await ScannerEngine.execute_scan(db_session, scheduled_asset.id)

        # Evaluate remediation
        hist2 = scheduler_service.evaluate_patch_verification_and_history(
            db=db_session, target_id=scheduled_asset.id, current_scan_id=scan2.id
        )

        # Verified as remediated!
        assert hist2.resolved_findings_count >= 1


class TestSchedulingAndHistoryAPIEndpoints:
    """HTTP API integration tests for /api/v1/schedules and /api/v1/history."""

    def test_api_schedule_workflow(self, client: TestClient) -> None:
        now = datetime.now(timezone.utc)
        scope_code = f"SCOPE-API-SCHED-{int(now.timestamp())}"

        # 1. Create Scope & Asset
        client.post(
            "/api/v1/scopes",
            json={
                "organization_name": "API Sched Org",
                "scope_code": scope_code,
                "title": "API Scope",
                "authorized_by": "api@sched.com",
                "valid_from": now.isoformat(),
                "valid_until": (now + timedelta(days=30)).isoformat(),
            },
        )
        res_asset = client.post(
            "/api/v1/assets",
            json={
                "target": "https://api-sched.example.com",
                "scope_code": scope_code,
                "is_authorized": True,
                "skip_dns_resolution": True,
            },
        )
        asset_id = res_asset.json()["id"]

        # 2. Schedule Recurring Scan via API
        res_sched = client.post(
            "/api/v1/schedules",
            json={"target_id": asset_id, "frequency": "DAILY"},
        )
        assert res_sched.status_code == status.HTTP_201_CREATED
        sched_data = res_sched.json()
        sched_id = sched_data["id"]
        assert sched_data["frequency"] == "DAILY"
        assert sched_data["is_active"] is True

        # 3. Pause Schedule
        res_pause = client.patch(f"/api/v1/schedules/{sched_id}", json={"is_active": False})
        assert res_pause.status_code == status.HTTP_200_OK
        assert res_pause.json()["is_active"] is False

        # 4. Trigger Due Schedules via API
        res_run_due = client.post("/api/v1/schedules/run-due")
        assert res_run_due.status_code == status.HTTP_200_OK

        # 5. Fetch Target Posture Timeline via API
        res_timeline = client.get(f"/api/v1/history/timeline/{asset_id}")
        assert res_timeline.status_code == status.HTTP_200_OK
        timeline_data = res_timeline.json()
        assert timeline_data["target_id"] == asset_id
        assert "history_records" in timeline_data
        assert "recent_verifications" in timeline_data
