"""OWASP Sentinel - Health Endpoint

Provides service availability and readiness checks.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.schemas.common import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="Service Health Check")
async def get_health() -> HealthResponse:
    """Return current operational status, version, and environment of OWASP Sentinel."""
    return HealthResponse(
        status="healthy",
        app_name=settings.PROJECT_NAME,
        version=settings.VERSION,
        environment=settings.APP_ENV,
    )


@router.get("/seed-status", summary="Check Baseline Seeding Diagnostics")
def get_seed_status(db: Session = Depends(get_db)):
    """Return current seeding status, errors, and entity counts."""
    from app.services.seed_service import BaselineSeedService
    from app.models.db.finding import Finding, FindingCategoryMapping
    from app.models.db.asset import AuthorizedAsset
    from app.models.db.scan import ScanJob

    return {
        "status": "healthy",
        "last_status": BaselineSeedService.last_status,
        "findings_count": db.query(Finding).count(),
        "mappings_count": db.query(FindingCategoryMapping).count(),
        "assets_count": db.query(AuthorizedAsset).count(),
        "scans_count": db.query(ScanJob).count(),
    }


@router.post("/reseed", summary="Force Reseed Baseline Data")
def trigger_reseed(db: Session = Depends(get_db)):
    """Explicitly re-run baseline finding seeding."""
    from app.services.seed_service import BaselineSeedService
    from app.models.db.finding import Finding

    success = BaselineSeedService.seed_baseline_findings(db, force=True)
    return {
        "success": success,
        "last_status": BaselineSeedService.last_status,
        "findings_count": db.query(Finding).count(),
    }
