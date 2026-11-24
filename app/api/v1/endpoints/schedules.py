"""OWASP Sentinel - Scan Scheduling API Endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import SentinelException
from app.db.session import get_db
from app.models.db.schedule import ScheduledScan
from app.models.schemas.common import ErrorResponse
from app.models.schemas.scan import ScanJobResponse
from app.models.schemas.schedule import (
    ScheduleCreateRequest,
    ScheduleResponse,
    ScheduleUpdateRequest,
)
from app.services import scheduler_service

router = APIRouter()


@router.post(
    "",
    response_model=ScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Schedule Recurring Security Assessment",
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
        status.HTTP_404_NOT_FOUND: {"model": ErrorResponse},
    },
)
def create_schedule(
    request: ScheduleCreateRequest,
    db: Session = Depends(get_db),
) -> ScheduleResponse:
    """Register a recurring assessment schedule for an approved target asset."""
    try:
        schedule = scheduler_service.create_schedule(
            db=db,
            target_id=request.target_id,
            frequency=request.frequency,
            cron_expression=request.cron_expression,
            rule_ids=request.rule_ids,
        )
        return ScheduleResponse(
            id=schedule.id,
            target_id=schedule.target_id,
            scope_grant_id=schedule.scope_grant_id,
            frequency=schedule.frequency,
            cron_expression=schedule.cron_expression,
            is_active=schedule.is_active,
            next_run_at=schedule.next_run_at,
            last_run_at=schedule.last_run_at,
            last_scan_id=schedule.last_scan_id,
            rule_ids=schedule.rule_ids,
            schedule_metadata=schedule.schedule_metadata,
            created_at=schedule.created_at,
        )
    except SentinelException as exc:
        code = status.HTTP_404_NOT_FOUND if exc.code == "ASSET_NOT_FOUND" else status.HTTP_400_BAD_REQUEST
        raise HTTPException(
            status_code=code,
            detail={"error": "Schedule Error", "code": exc.code, "message": exc.message},
        ) from exc


@router.get(
    "",
    response_model=list[ScheduleResponse],
    summary="List Scheduled Recurring Scans",
)
def list_schedules(
    target_id: str | None = None,
    active_only: bool = False,
    db: Session = Depends(get_db),
) -> list[ScheduleResponse]:
    """Retrieve recurring assessment schedules."""
    stmt = select(ScheduledScan).order_by(ScheduledScan.next_run_at.asc())
    if target_id:
        stmt = stmt.where(ScheduledScan.target_id == target_id)
    if active_only:
        stmt = stmt.where(ScheduledScan.is_active.is_(True))

    schedules = list(db.scalars(stmt).all())
    return [
        ScheduleResponse(
            id=s.id,
            target_id=s.target_id,
            scope_grant_id=s.scope_grant_id,
            frequency=s.frequency,
            cron_expression=s.cron_expression,
            is_active=s.is_active,
            next_run_at=s.next_run_at,
            last_run_at=s.last_run_at,
            last_scan_id=s.last_scan_id,
            rule_ids=s.rule_ids,
            schedule_metadata=s.schedule_metadata,
            created_at=s.created_at,
        )
        for s in schedules
    ]


@router.patch(
    "/{schedule_id}",
    response_model=ScheduleResponse,
    summary="Update or Pause/Resume Schedule",
)
def update_schedule(
    schedule_id: str,
    request: ScheduleUpdateRequest,
    db: Session = Depends(get_db),
) -> ScheduleResponse:
    """Modify recurrence frequency or pause/resume a schedule."""
    stmt = select(ScheduledScan).where(ScheduledScan.id == schedule_id)
    s = db.scalars(stmt).first()
    if not s:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not Found", "message": f"Schedule '{schedule_id}' not found."},
        )

    if request.is_active is not None:
        s.is_active = request.is_active
    if request.frequency is not None:
        s.frequency = request.frequency.upper()
        s.next_run_at = scheduler_service.calculate_next_run(
            frequency=s.frequency, cron_expr=request.cron_expression or s.cron_expression
        )
    if request.cron_expression is not None:
        s.cron_expression = request.cron_expression
    if request.rule_ids is not None:
        s.rule_ids = request.rule_ids

    db.commit()
    db.refresh(s)
    return ScheduleResponse(
        id=s.id,
        target_id=s.target_id,
        scope_grant_id=s.scope_grant_id,
        frequency=s.frequency,
        cron_expression=s.cron_expression,
        is_active=s.is_active,
        next_run_at=s.next_run_at,
        last_run_at=s.last_run_at,
        last_scan_id=s.last_scan_id,
        rule_ids=s.rule_ids,
        schedule_metadata=s.schedule_metadata,
        created_at=s.created_at,
    )


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel / Delete Schedule",
)
def delete_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
) -> None:
    """Permanently delete a recurring scan schedule."""
    stmt = select(ScheduledScan).where(ScheduledScan.id == schedule_id)
    s = db.scalars(stmt).first()
    if not s:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not Found", "message": f"Schedule '{schedule_id}' not found."},
        )
    db.delete(s)
    db.commit()


@router.post(
    "/run-due",
    response_model=list[ScanJobResponse],
    summary="Trigger Execution of Due Schedules",
)
async def run_due_schedules(
    db: Session = Depends(get_db),
) -> list[ScanJobResponse]:
    """Execute all active schedules whose next_run_at timestamp has arrived."""
    jobs = await scheduler_service.trigger_due_schedules(db)
    return [
        ScanJobResponse(
            id=j.id,
            target_id=j.target_id,
            scope_grant_id=j.scope_grant_id,
            status=j.status,
            started_at=j.started_at,
            completed_at=j.completed_at,
            total_checks=j.total_checks,
            passed_checks=j.passed_checks,
            failed_checks=j.failed_checks,
            error_message=j.error_message,
            scan_metadata=j.scan_metadata,
            created_at=j.created_at,
        )
        for j in jobs
    ]
