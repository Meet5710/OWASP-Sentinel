"""OWASP Sentinel - Health Endpoint

Provides service availability and readiness checks.
"""

from fastapi import APIRouter

from app.core.config import settings
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
