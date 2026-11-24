"""OWASP Sentinel - Scan Execution & Findings API Endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import SentinelException, UnauthorizedTargetError
from app.db.session import get_db
from app.models.db.finding import TechnicalObservation
from app.models.db.scan import ScanJob
from app.models.schemas.common import ErrorResponse
from app.models.schemas.scan import (
    ScanExecuteRequest,
    ScanJobResponse,
    TechnicalObservationResponse,
)
from app.scanner.engine import ScannerEngine

router = APIRouter()


@router.post(
    "",
    response_model=ScanJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Assessment Against Authorized Asset",
    include_in_schema=False,
)
@router.post(
    "/execute",
    response_model=ScanJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Execute Assessment Against Authorized Asset",
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
        status.HTTP_403_FORBIDDEN: {"model": ErrorResponse},
        status.HTTP_404_NOT_FOUND: {"model": ErrorResponse},
    },
)
async def execute_scan(
    request: ScanExecuteRequest,
    db: Session = Depends(get_db),
) -> ScanJobResponse:
    """Trigger an on-demand security scan against an approved asset.

    Enforces pre-scan scope clearance before running checks.
    """
    try:
        if not request.asset_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Scan Error", "code": "ASSET_ID_REQUIRED", "message": "Field 'asset_id' is required to execute a scan."},
            )
        job = await ScannerEngine.execute_scan(db=db, asset_id=request.asset_id, rule_ids=request.rule_ids)
        return ScanJobResponse(
            id=job.id,
            target_id=job.target_id,
            scope_grant_id=job.scope_grant_id,
            status=job.status,
            started_at=job.started_at,
            completed_at=job.completed_at,
            total_checks=job.total_checks,
            passed_checks=job.passed_checks,
            failed_checks=job.failed_checks,
            observations_count=len(job.observations) if job.observations else job.failed_checks,
            error_message=job.error_message,
            scan_metadata=job.scan_metadata,
            created_at=job.created_at,
        )
    except UnauthorizedTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Scan Denied", "code": exc.code, "message": exc.message, "details": exc.details},
        ) from exc
    except SentinelException as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Scan Error", "code": exc.code, "message": exc.message},
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Scan Execution Error", "code": "SCAN_INTERNAL_ERROR", "message": str(exc)},
        ) from exc


@router.post(
    "/{target_id}",
    response_model=ScanJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Execute Assessment by Target/Asset ID",
    include_in_schema=False,
)
@router.post(
    "/{target_id}/execute",
    response_model=ScanJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Execute Assessment by Target/Asset ID (Execute subpath)",
    include_in_schema=False,
)
async def execute_scan_by_target_id(
    target_id: str,
    request: ScanExecuteRequest | None = None,
    db: Session = Depends(get_db),
) -> ScanJobResponse:
    """Allow executing a scan directly via path parameter /scans/{target_id} or /scans/{target_id}/execute."""
    asset_id = request.asset_id if (request and request.asset_id) else target_id
    rule_ids = request.rule_ids if request else None
    try:
        job = await ScannerEngine.execute_scan(db=db, asset_id=asset_id, rule_ids=rule_ids)
        return ScanJobResponse(
            id=job.id,
            target_id=job.target_id,
            scope_grant_id=job.scope_grant_id,
            status=job.status,
            started_at=job.started_at,
            completed_at=job.completed_at,
            total_checks=job.total_checks,
            passed_checks=job.passed_checks,
            failed_checks=job.failed_checks,
            observations_count=len(job.observations) if job.observations else job.failed_checks,
            error_message=job.error_message,
            scan_metadata=job.scan_metadata,
            created_at=job.created_at,
        )
    except UnauthorizedTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Scan Denied", "code": exc.code, "message": exc.message, "details": exc.details},
        ) from exc
    except SentinelException as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Scan Error", "code": exc.code, "message": exc.message},
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Scan Execution Error", "code": "SCAN_INTERNAL_ERROR", "message": str(exc)},
        ) from exc


@router.get(
    "",
    response_model=list[ScanJobResponse],
    summary="List Scan Jobs",
)
def list_scans(
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[ScanJobResponse]:
    """Retrieve history of assessment jobs."""
    stmt = (
        select(ScanJob)
        .options(selectinload(ScanJob.observations))
        .order_by(ScanJob.started_at.desc(), ScanJob.created_at.desc())
        .limit(limit)
    )
    jobs = list(db.scalars(stmt).all())
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
            observations_count=len(j.observations),
            error_message=j.error_message,
            scan_metadata=j.scan_metadata,
            created_at=j.created_at,
        )
        for j in jobs
    ]


@router.get(
    "/{scan_id}",
    response_model=ScanJobResponse,
    summary="Get Scan Job Status",
)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
) -> ScanJobResponse:
    """Retrieve details and metrics of a specific scan job."""
    stmt = select(ScanJob).options(selectinload(ScanJob.observations)).where(ScanJob.id == scan_id)
    job = db.scalars(stmt).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not Found", "message": f"Scan job '{scan_id}' not found."},
        )
    return ScanJobResponse(
        id=job.id,
        target_id=job.target_id,
        scope_grant_id=job.scope_grant_id,
        status=job.status,
        started_at=job.started_at,
        completed_at=job.completed_at,
        total_checks=job.total_checks,
        passed_checks=job.passed_checks,
        failed_checks=job.failed_checks,
        observations_count=len(job.observations),
        error_message=job.error_message,
        scan_metadata=job.scan_metadata,
        created_at=job.created_at,
    )


@router.get(
    "/{scan_id}/observations",
    response_model=list[TechnicalObservationResponse],
    summary="List Technical Observations & Evidence for Scan",
    include_in_schema=False,
)
@router.get(
    "/{scan_id}/findings",
    response_model=list[TechnicalObservationResponse],
    summary="List Technical Observations & Evidence for Scan",
)
def get_scan_findings(
    scan_id: str,
    db: Session = Depends(get_db),
) -> list[TechnicalObservationResponse]:
    """Retrieve detailed vulnerability observations and evidence for a specific scan."""
    stmt = select(TechnicalObservation).where(TechnicalObservation.scan_id == scan_id)
    findings = list(db.scalars(stmt).all())
    return [
        TechnicalObservationResponse(
            id=f.id,
            scan_id=f.scan_id,
            target_id=f.target_id,
            rule_id=f.rule_id,
            title=f.title,
            technical_issue_type=f.technical_issue_type,
            severity=f.severity,
            confidence=f.confidence,
            evidence=f.evidence,
            remediation=f.remediation,
            references=f.references,
            created_at=f.created_at,
        )
        for f in findings
    ]


@router.get(
    "/{scan_id}/terminal",
    summary="Get Practical Terminal Execution Stream for Scan",
)
def get_scan_terminal(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve full practical terminal execution logs, reconnaissance metadata, and metrics."""
    stmt = select(ScanJob).where(ScanJob.id == scan_id)
    job = db.scalars(stmt).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not Found", "message": f"Scan job '{scan_id}' not found."},
        )
    meta = job.scan_metadata or {}
    return {
        "scan_id": job.id,
        "target_id": job.target_id,
        "status": job.status,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "terminal_logs": meta.get("terminal_logs", []),
        "recon_details": meta.get("recon_details", {}),
        "deep_scan_metrics": meta.get("deep_scan_metrics", {}),
    }
