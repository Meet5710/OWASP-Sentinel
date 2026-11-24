"""OWASP Sentinel - Patch Verification & Historical Posture Endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.db.asset import AuthorizedAsset
from app.models.db.history import FindingHistoryRecord, PatchVerification
from app.models.schemas.history import (
    FindingHistoryRecordResponse,
    PatchVerificationResponse,
    TargetPostureTimelineResponse,
)

router = APIRouter()


@router.get(
    "/verifications",
    response_model=list[PatchVerificationResponse],
    summary="List Patch Verifications & Remediation Tracking",
)
def list_verifications(
    target_id: str | None = None,
    verification_status: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[PatchVerificationResponse]:
    """Retrieve audit history of verified remediations (REMEDIATED, STILL_VULNERABLE, REGRESSED)."""
    stmt = select(PatchVerification).order_by(PatchVerification.verified_at.desc()).limit(limit)
    if target_id:
        stmt = stmt.where(PatchVerification.target_id == target_id)
    if verification_status:
        stmt = stmt.where(PatchVerification.verification_status == verification_status.upper())

    verifications = list(db.scalars(stmt).all())
    return [
        PatchVerificationResponse(
            id=v.id,
            finding_id=v.finding_id,
            scan_id=v.scan_id,
            target_id=v.target_id,
            verification_status=v.verification_status,
            verified_at=v.verified_at,
            notes=v.notes,
            evidence=v.evidence,
        )
        for v in verifications
    ]


@router.get(
    "/timeline/{target_id}",
    response_model=TargetPostureTimelineResponse,
    summary="Get Target Security Posture Timeline for Dashboard Visualizers",
)
def get_target_timeline(
    target_id: str,
    db: Session = Depends(get_db),
) -> TargetPostureTimelineResponse:
    """Retrieve historical vulnerability counts and remediation verification timeline for charting."""
    stmt_asset = select(AuthorizedAsset).where(AuthorizedAsset.id == target_id)
    asset = db.scalars(stmt_asset).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not Found", "message": f"Asset '{target_id}' not found."},
        )

    # Fetch History Records ordered by time
    stmt_hist = (
        select(FindingHistoryRecord)
        .where(FindingHistoryRecord.target_id == target_id)
        .order_by(FindingHistoryRecord.recorded_at.asc())
    )
    records = list(db.scalars(stmt_hist).all())

    # Fetch Recent Verifications
    stmt_ver = (
        select(PatchVerification)
        .where(PatchVerification.target_id == target_id)
        .order_by(PatchVerification.verified_at.desc())
        .limit(20)
    )
    verifications = list(db.scalars(stmt_ver).all())

    return TargetPostureTimelineResponse(
        target_id=asset.id,
        canonical_url=asset.canonical_url,
        total_historical_assessments=len(records),
        history_records=[
            FindingHistoryRecordResponse(
                id=r.id,
                target_id=r.target_id,
                scan_id=r.scan_id,
                total_findings=r.total_findings,
                critical_count=r.critical_count,
                high_count=r.high_count,
                medium_count=r.medium_count,
                low_count=r.low_count,
                info_count=r.info_count,
                new_findings_count=r.new_findings_count,
                resolved_findings_count=r.resolved_findings_count,
                recurrent_findings_count=r.recurrent_findings_count,
                recorded_at=r.recorded_at,
            )
            for r in records
        ],
        recent_verifications=[
            PatchVerificationResponse(
                id=v.id,
                finding_id=v.finding_id,
                scan_id=v.scan_id,
                target_id=v.target_id,
                verification_status=v.verification_status,
                verified_at=v.verified_at,
                notes=v.notes,
                evidence=v.evidence,
            )
            for v in verifications
        ],
    )
