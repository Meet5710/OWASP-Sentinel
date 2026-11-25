"""OWASP Sentinel - Finding Management & OWASP Mapping Endpoints."""

from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import SentinelException
from app.db.session import get_db
from app.models.db.finding import FindingCategoryMapping
from app.models.schemas.common import ErrorResponse
from app.models.schemas.finding import (
    FindingCategoryMappingResponse,
    FindingResponse,
    FindingStatusUpdateRequest,
    OWASPCategoryCount,
    OWASPFindingsSummaryResponse,
)
from app.services import finding_service

router = APIRouter()


@router.get(
    "",
    response_model=list[FindingResponse],
    summary="List Findings with Multi-Dimensional Filters",
)
def list_findings(
    target_id: str | None = None,
    scan_id: str | None = None,
    severity: str | None = None,
    owasp_edition: str | None = None,
    owasp_category: str | None = None,
    confidence: str | None = None,
    validation_status: str | None = None,
    active_only: bool = False,
    limit: int = 500,
    db: Session = Depends(get_db),
) -> list[FindingResponse]:
    """Retrieve findings filtered by target, scan_id, severity, OWASP edition, category, confidence, or status."""
    findings = finding_service.list_findings(
        db=db,
        target_id=target_id,
        scan_id=scan_id,
        severity=severity,
        owasp_edition=owasp_edition,
        owasp_category_code=owasp_category,
        confidence=confidence,
        validation_status=validation_status,
        active_only=active_only,
        limit=limit,
    )
    return [
        FindingResponse(
            id=f.id,
            target_id=f.target_id,
            scan_id=f.scan_id,
            detection_rule_id=f.detection_rule_id,
            technical_issue_type=f.technical_issue_type,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            validation_status=f.validation_status,
            first_seen_at=f.first_seen_at,
            last_seen_at=f.last_seen_at,
            evidence=f.evidence,
            remediation_recommendations=f.remediation_recommendations,
            references=f.references,
            status_history=f.status_history,
            category_mappings=[
                FindingCategoryMappingResponse(
                    id=m.id,
                    edition_identifier=m.edition_identifier,
                    category_identifier=m.category_identifier,
                    owasp_edition=m.edition_identifier,
                    owasp_category_code=m.category_identifier,
                    owasp_category_title=m.owasp_category_title or m.category_identifier,
                    justification=m.justification,
                )
                for m in f.category_mappings
            ],
        )
        for f in findings
    ]


@router.post(
    "/seed-baseline",
    summary="Seed Baseline Findings Dataset",
    description="Loads official baseline findings, category mappings, and technical observations.",
)
def seed_baseline(
    force: bool = False,
    db: Session = Depends(get_db),
):
    """Seed baseline dataset on demand."""
    from app.services.seed_service import BaselineSeedService
    from app.models.db.finding import Finding
    seeded = BaselineSeedService.seed_baseline_findings(db, force=force)
    total = db.query(Finding).count()
    return {"status": "ok", "seeded": seeded, "total_findings": total}


@router.get(
    "/stats/owasp-summary",
    response_model=OWASPFindingsSummaryResponse,
    summary="Get Findings Breakdown Grouped by OWASP Category",
)
def get_owasp_summary(
    edition: str = "2025",
    db: Session = Depends(get_db),
) -> OWASPFindingsSummaryResponse:
    """Aggregate finding counts and severity distributions mapped to an OWASP Top 10 edition."""
    stmt = (
        select(FindingCategoryMapping)
        .options(selectinload(FindingCategoryMapping.finding))
        .where(FindingCategoryMapping.edition_identifier == edition)
    )
    mappings = list(db.scalars(stmt).all())

    cat_counts: dict[str, dict] = defaultdict(lambda: {"title": "", "count": 0, "severities": defaultdict(int)})

    for m in mappings:
        code = m.category_identifier
        cat_counts[code]["title"] = m.owasp_category_title or m.category_identifier
        cat_counts[code]["count"] += 1
        if m.finding:
            cat_counts[code]["severities"][m.finding.severity] += 1

    summaries = [
        OWASPCategoryCount(
            category_code=code,
            category_title=data["title"],
            finding_count=data["count"],
            severity_breakdown=dict(data["severities"]),
        )
        for code, data in sorted(cat_counts.items())
    ]

    return OWASPFindingsSummaryResponse(
        edition=edition,
        total_findings=sum(s.finding_count for s in summaries),
        category_summaries=summaries,
    )


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Get Finding Details by ID",
)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
) -> FindingResponse:
    """Retrieve full details of a finding including concrete evidence and OWASP mappings."""
    f = finding_service.get_finding_by_id(db, finding_id)
    if not f:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not Found", "message": f"Finding '{finding_id}' not found."},
        )
    return FindingResponse(
        id=f.id,
        target_id=f.target_id,
        scan_id=f.scan_id,
        detection_rule_id=f.detection_rule_id,
        technical_issue_type=f.technical_issue_type,
        title=f.title,
        severity=f.severity,
        confidence=f.confidence,
        validation_status=f.validation_status,
        first_seen_at=f.first_seen_at,
        last_seen_at=f.last_seen_at,
        evidence=f.evidence,
        remediation_recommendations=f.remediation_recommendations,
        references=f.references,
        status_history=f.status_history,
        category_mappings=[
            FindingCategoryMappingResponse(
                id=m.id,
                owasp_edition=m.owasp_edition,
                owasp_category_code=m.owasp_category_code,
                owasp_category_title=m.owasp_category_title,
                justification=m.justification,
            )
            for m in f.category_mappings
        ],
    )


@router.patch(
    "/{finding_id}/status",
    response_model=FindingResponse,
    summary="Update Finding Validation Status",
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
        status.HTTP_404_NOT_FOUND: {"model": ErrorResponse},
    },
)
def update_status(
    finding_id: str,
    request: FindingStatusUpdateRequest,
    db: Session = Depends(get_db),
) -> FindingResponse:
    """Transition a finding's validation status (e.g. to FALSE_POSITIVE or MITIGATED)."""
    try:
        f = finding_service.update_finding_status(
            db=db,
            finding_id=finding_id,
            new_status=request.validation_status,
            actor=request.actor,
            note=request.note,
        )
        return FindingResponse(
            id=f.id,
            target_id=f.target_id,
            scan_id=f.scan_id,
            detection_rule_id=f.detection_rule_id,
            technical_issue_type=f.technical_issue_type,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            validation_status=f.validation_status,
            first_seen_at=f.first_seen_at,
            last_seen_at=f.last_seen_at,
            evidence=f.evidence,
            remediation_recommendations=f.remediation_recommendations,
            references=f.references,
            status_history=f.status_history,
            category_mappings=[
                FindingCategoryMappingResponse(
                    id=m.id,
                    edition_identifier=m.edition_identifier,
                    category_identifier=m.category_identifier,
                    owasp_edition=m.edition_identifier,
                    owasp_category_code=m.category_identifier,
                    owasp_category_title=m.owasp_category_title or m.category_identifier,
                    justification=m.justification,
                )
                for m in f.category_mappings
            ],
        )
    except SentinelException as exc:
        code = status.HTTP_404_NOT_FOUND if exc.code == "FINDING_NOT_FOUND" else status.HTTP_400_BAD_REQUEST
        raise HTTPException(
            status_code=code,
            detail={"error": "Finding Error", "code": exc.code, "message": exc.message},
        ) from exc
