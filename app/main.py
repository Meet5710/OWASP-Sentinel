"""OWASP Sentinel - Main Application Entrypoint

FastAPI application factory, middleware configuration, and exception handlers.
"""

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

# Ensure project root is in sys.path when executed directly
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1.api import api_router
from app.api.v1.endpoints import path_finder
from app.core.config import settings
from app.core.exceptions import SentinelException
from app.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and shutdown routines."""
    # Startup: Initialize SQLite/database schema
    init_db()

    # Seed official OWASP historical taxonomy idempotently
    from app.db.session import SessionLocal
    from app.services.ingestion_service import TaxonomyIngestionService
    from app.models.db.path_finder import PathFinderScan
    from app.models.schemas.path_finder import PathFinderStatus
    from sqlalchemy import select
    from datetime import datetime, timezone

    with SessionLocal() as db:
        TaxonomyIngestionService.run_ingestion(db)

        # Reconcile orphaned Path Finder scans from prior server sessions
        stale_scans = db.scalars(
            select(PathFinderScan).where(
                PathFinderScan.status.in_([PathFinderStatus.RUNNING.value, PathFinderStatus.PENDING.value])
            )
        ).all()
        for s in stale_scans:
            s.status = PathFinderStatus.CANCELLED.value
            s.completed_at = datetime.now(timezone.utc)
            s.config_json = {
                **(s.config_json or {}),
                "interrupted": True,
                "note": "Scan marked cancelled due to server restart.",
            }
        if stale_scans:
            db.commit()

    yield
    # Shutdown: Clean up connections, flush background tasks


def create_app() -> FastAPI:
    """Create and configure the OWASP Sentinel FastAPI application instance."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description=(
            "OWASP Sentinel is a standalone cybersecurity platform focusing exclusively on "
            "OWASP web application security assessments, OWASP Top 10 intelligence, "
            "and continuous posture tracking."
        ),
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Cross-Origin Resource Sharing (CORS) Configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_origin_regex=r"^https?://.*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security Headers Middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline' https: http:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: http:; "
            "style-src 'self' 'unsafe-inline' https: http:; "
            "img-src 'self' data: https: http:; "
            "font-src 'self' data: https: http:; "
            "connect-src 'self' https: http: ws: wss:;"
        )
        return response

    # Global Exception Handlers
    @app.exception_handler(SentinelException)
    async def handle_sentinel_exception(request: Request, exc: SentinelException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "Sentinel Exception",
                "code": exc.code,
                "message": exc.message,
                "details": exc.details,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Validation Error",
                "code": "REQUEST_VALIDATION_FAILED",
                "message": "The submitted payload did not match the expected schema.",
                "details": {"errors": jsonable_encoder(exc.errors())},
            },
        )

    # Register API Routers
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)
    app.include_router(path_finder.router, prefix="/api/pathfinder", tags=["Path Finder"])
    app.include_router(path_finder.router, prefix="/api/path-finder", tags=["Path Finder"])

    # OWASP Top 10 Security Scan Execution Endpoints
    from pydantic import BaseModel, Field
    from scanner_main import scan as run_owasp_scan

    class ScanRequest(BaseModel):
        target_url: str = Field(..., description="Target URL to be assessed")
        selected_checks: list[str] = Field(..., description="List of OWASP category IDs to execute")

    @app.get("/api/status", tags=["Scan"])
    def get_scan_status():
        return {"status": "online"}

    @app.post("/api/scan", tags=["Scan"])
    def execute_scan(request: ScanRequest):
        return run_owasp_scan(target_url=request.target_url, selected_ids=request.selected_checks, auth={})

    # Static Assets & Frontend Web Application
    frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
    frontend_assets = frontend_dist / "assets"
    if frontend_assets.exists():
        app.mount("/assets", StaticFiles(directory=str(frontend_assets)), name="static_assets")

    @app.get("/app", tags=["Frontend"])
    @app.get("/app/{full_path:path}", tags=["Frontend"])
    async def serve_frontend_app(full_path: str = ""):
        dist_index = frontend_dist / "index.html"
        if dist_index.exists():
            return FileResponse(dist_index)
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"message": "Frontend build not found. Run 'npm run build' in the frontend directory."},
        )

    # Root informational route (serves Web UI to browsers, JSON to API clients)
    @app.get("/", tags=["Root"])
    async def root_info(request: Request):
        accept = request.headers.get("accept", "")
        dist_index = frontend_dist / "index.html"
        if accept.startswith("text/html") and dist_index.exists():
            return FileResponse(dist_index)
        return {
            "name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "status": "online",
            "documentation": "/docs",
            "health_check": f"{settings.API_V1_PREFIX}/health",
            "web_dashboard": "/app",
            "phase": "Phase 1 to Phase 8 Complete (Standalone Assessment & Intelligence Platform)",
        }

    return app


app = create_app()

if __name__ == "__main__":
    import os
    import uvicorn

    # Ensure current working directory is project root so uvicorn reloader finds app.main:app
    if Path.cwd().resolve() != _project_root:
        os.chdir(str(_project_root))

    print(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}...")
    print(f"Environment: {settings.APP_ENV}")
    print(f"Web Dashboard: http://{settings.HOST}:{settings.PORT}/app")
    print(f"API Docs available at: http://{settings.HOST}:{settings.PORT}/docs")
    print(f"Health check at: http://{settings.HOST}:{settings.PORT}{settings.API_V1_PREFIX}/health")

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
