"""OWASP Sentinel - OWASP Historical Taxonomy & Ingestion Endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.session import get_db
from app.models.db.ingestion import IngestionRun
from app.models.db.taxonomy import OWASPEdition
from app.models.schemas.taxonomy import (
    IngestionRunResponse,
    OWASPCategoryResponse,
    OWASPEditionResponse,
)
from app.services.ingestion_service import TaxonomyIngestionService
from app.taxonomy.lineage import MERGED_OWASP_TIMELINE, OWASP_2025_CATEGORIES

router = APIRouter()


@router.get(
    "/lineage",
    summary="Merged OWASP Top 10 Timeline (2003-2025) & Risk Lineage Data",
)
def get_lineage_timeline() -> list[dict[str, Any]]:
    """Retrieve the authoritative 22-year comparative timeline of OWASP Top 10 categories,
    showing lineage evolution, mergers, splits, additions, and absorbed risk themes from 2003 through 2025.
    """
    return MERGED_OWASP_TIMELINE


@router.get(
    "/editions",
    response_model=list[OWASPEditionResponse],
    summary="List Official OWASP Top 10 Editions (2003-2025)",
)
def list_editions(
    db: Session = Depends(get_db),
) -> list[OWASPEditionResponse]:
    """Retrieve all official OWASP Top 10 editions preserved historically without overwriting."""
    stmt = (
        select(OWASPEdition)
        .options(selectinload(OWASPEdition.categories))
        .order_by(OWASPEdition.publication_year.desc())
    )
    editions = list(db.scalars(stmt).all())
    return [
        OWASPEditionResponse(
            id=e.id,
            edition_identifier=e.edition_identifier,
            title=e.title,
            publication_year=e.publication_year,
            publication_date=e.publication_date,
            source_url=e.source_url,
            content_hash=e.content_hash,
            retrieval_timestamp=e.retrieval_timestamp,
            is_latest=e.is_latest,
            categories=[
                OWASPCategoryResponse(
                    id=c.id,
                    category_code=c.category_code,
                    category_title=c.category_title,
                    category_description=c.category_description,
                    cwe_examples=c.cwe_examples,
                    source_url=c.source_url,
                    content_hash=c.content_hash,
                    display_order=c.display_order,
                    retrieval_timestamp=e.retrieval_timestamp,
                )
                for c in e.categories
            ],
        )
        for e in editions
    ]


@router.get(
    "/editions/{identifier}",
    response_model=OWASPEditionResponse,
    summary="Get Specific OWASP Edition Details and Categories",
)
def get_edition(
    identifier: str,
    db: Session = Depends(get_db),
) -> OWASPEditionResponse:
    """Retrieve a specific official OWASP edition by year identifier (e.g. '2021', '2017')."""
    stmt = (
        select(OWASPEdition)
        .options(selectinload(OWASPEdition.categories))
        .where((OWASPEdition.edition_identifier == identifier) | (OWASPEdition.id == identifier))
    )
    edition = db.scalars(stmt).first()
    if not edition:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not Found", "message": f"OWASP edition '{identifier}' not found in taxonomy records."},
        )
    return OWASPEditionResponse(
        id=edition.id,
        edition_identifier=edition.edition_identifier,
        title=edition.title,
        publication_year=edition.publication_year,
        publication_date=edition.publication_date,
        source_url=edition.source_url,
        content_hash=edition.content_hash,
        retrieval_timestamp=edition.retrieval_timestamp,
        is_latest=edition.is_latest,
        categories=[
            OWASPCategoryResponse(
                id=c.id,
                category_code=c.category_code,
                category_title=c.category_title,
                category_description=c.category_description,
                cwe_examples=c.cwe_examples,
                source_url=c.source_url,
                content_hash=c.content_hash,
                display_order=c.display_order,
                retrieval_timestamp=edition.retrieval_timestamp,
            )
            for c in edition.categories
        ],
    )


@router.post(
    "/ingest",
    response_model=IngestionRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger OWASP Intelligence Ingestion Cycle",
)
def trigger_ingestion(
    force_update: bool = False,
    db: Session = Depends(get_db),
) -> IngestionRunResponse:
    """Check official OWASP publication sources, detect new/updated taxonomy definitions,
    and persist changes idempotently."""
    run = TaxonomyIngestionService.run_ingestion(db, force_update=force_update)
    has_changes = run.status == "CHANGES_DETECTED" or (run.categories_created > 0 or run.categories_updated > 0)
    return IngestionRunResponse(
        id=run.id,
        source_url=run.source_url,
        status=run.status,
        editions_processed=run.editions_processed,
        categories_updated=run.categories_updated,
        categories_created=run.categories_created,
        categories_processed=run.editions_processed * 10 if run.editions_processed else 80,
        changes_detected=has_changes,
        admin_review_required=run.requires_admin_review,
        content_hash=run.content_hash,
        requires_admin_review=run.requires_admin_review,
        error_message=run.error_message,
        log_details=run.log_details,
        started_at=run.started_at,
        completed_at=run.completed_at,
    )


@router.get(
    "/ingest/history",
    response_model=list[IngestionRunResponse],
    summary="List Taxonomy Ingestion Audit Runs",
)
def list_ingestion_history(
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[IngestionRunResponse]:
    """Retrieve historical ingestion execution logs."""
    stmt = select(IngestionRun).order_by(IngestionRun.started_at.desc()).limit(limit)
    runs = list(db.scalars(stmt).all())
    return [
        IngestionRunResponse(
            id=r.id,
            source_url=r.source_url,
            status=r.status,
            editions_processed=r.editions_processed,
            categories_updated=r.categories_updated,
            categories_created=r.categories_created,
            categories_processed=r.editions_processed * 10 if r.editions_processed else 80,
            changes_detected=r.status == "CHANGES_DETECTED" or (r.categories_created > 0 or r.categories_updated > 0),
            admin_review_required=r.requires_admin_review,
            content_hash=r.content_hash,
            requires_admin_review=r.requires_admin_review,
            error_message=r.error_message,
            log_details=r.log_details,
            started_at=r.started_at,
            completed_at=r.completed_at,
        )
        for r in runs
    ]
