"""OWASP Sentinel - Path Finder Celery Task Definitions

Provides Celery worker tasks for running asynchronous endpoint discovery scans
and dedicated async route verification tasks.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from app.core.celery_app import celery_app
from app.services.path_finder_service import run_path_finder_scan_task
from app.services.route_checker import AsyncRouteVerificationService

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.path_finder_tasks.execute_path_finder_scan_celery_task", bind=True, max_retries=2)
def execute_path_finder_scan_celery_task(
    self: Any,
    scan_id: str,
    base_url: str,
    mode: str,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute Path Finder scan in Celery worker process."""
    logger.info("[Celery Worker] Starting Path Finder scan '%s' against '%s' (mode: %s)", scan_id, base_url, mode)
    try:
        asyncio.run(run_path_finder_scan_task(scan_id=scan_id, base_url=base_url, mode=mode, config=config))
        return {"scan_id": scan_id, "status": "COMPLETED"}
    except Exception as exc:
        logger.error("[Celery Worker] Scan '%s' failed: %s", scan_id, exc)
        raise self.retry(exc=exc, countdown=10)


@celery_app.task(name="app.tasks.path_finder_tasks.verify_routes_celery_task", bind=True, max_retries=2)
def verify_routes_celery_task(
    self: Any,
    scan_id: str,
    base_url: str,
    target_id: Optional[str] = None,
    candidate_routes: Optional[List[str]] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute Async Route Verification Service directly inside Celery worker."""
    cfg = config or {}
    logger.info("[Celery Worker] Starting Route Verification for scan '%s' against '%s'", scan_id, base_url)
    try:
        checker = AsyncRouteVerificationService(
            concurrency=int(cfg.get("threads") or cfg.get("concurrency") or 10),
            timeout=float(cfg.get("timeout") or 5.0),
            rps_limit=float(cfg.get("rps") or 30.0),
            custom_headers=cfg.get("headers"),
        )
        result = asyncio.run(
            checker.execute_verification(
                scan_id=scan_id,
                base_url=base_url,
                target_id=target_id,
                candidate_routes=candidate_routes,
                config=cfg,
            )
        )
        return result
    except Exception as exc:
        logger.error("[Celery Worker] Route verification for scan '%s' failed: %s", scan_id, exc)
        raise self.retry(exc=exc, countdown=10)
