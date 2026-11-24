"""OWASP Sentinel - Asynchronous Background Tasks

Celery task definitions for asynchronous scan execution, automated recurring
schedule dispatch, and taxonomy ingestion.
"""

import asyncio
import logging
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.scanner.engine import ScannerEngine
from app.services.ingestion_service import TaxonomyIngestionService
from app.services.scheduler_service import (
    evaluate_patch_verification_and_history,
    trigger_due_schedules,
)

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.scan_tasks.execute_async_scan", bind=True, max_retries=3)
def execute_async_scan(self: Any, asset_id: str, rule_ids: list[str] | None = None) -> dict[str, str]:
    """Execute non-destructive security scan in asynchronous worker pool."""
    logger.info(f"[Celery] Starting asynchronous assessment for asset {asset_id}...")
    try:
        with SessionLocal() as db:
            scan_job = asyncio.run(ScannerEngine.execute_scan(db=db, asset_id=asset_id, rule_ids=rule_ids))

            # Record patch verification & posture metrics
            evaluate_patch_verification_and_history(db=db, target_id=asset_id, current_scan_id=scan_job.id)

            obs_count = len(scan_job.observations) if scan_job.observations else scan_job.failed_checks
            logger.info(f"[Celery] Scan {scan_job.id} completed. Observations: {obs_count}")
            return {"scan_id": scan_job.id, "status": scan_job.status}
    except Exception as exc:
        logger.error(f"[Celery] Scan execution failed for asset {asset_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="app.tasks.scan_tasks.trigger_due_schedules_task")
def trigger_due_schedules_task() -> int:
    """Periodic worker task checking and firing due recurring scans."""
    logger.info("[Celery Beat] Checking for due assessment schedules...")
    try:
        with SessionLocal() as db:
            executed_jobs = asyncio.run(trigger_due_schedules(db))
            logger.info(f"[Celery Beat] Dispatched {len(executed_jobs)} due scan jobs.")
            return len(executed_jobs)
    except Exception as exc:
        logger.error(f"[Celery Beat] Error triggering due schedules: {exc}")
        return 0


@celery_app.task(name="app.tasks.scan_tasks.ingest_taxonomy_task")
def ingest_taxonomy_task() -> dict[str, Any]:
    """Periodic task checking official OWASP publication sources for changes."""
    logger.info("[Celery Beat] Running daily OWASP taxonomy verification check...")
    try:
        with SessionLocal() as db:
            run = TaxonomyIngestionService.run_ingestion(db)
            has_changes = run.status == "CHANGES_DETECTED" or run.categories_updated > 0 or run.categories_created > 0
            logger.info(
                f"[Celery Beat] Taxonomy check completed. Editions: {run.editions_processed}, Changes: {has_changes}"
            )
            return {
                "run_id": run.id,
                "status": run.status,
                "changes_detected": has_changes,
                "admin_review_required": run.requires_admin_review,
            }
    except Exception as exc:
        logger.error(f"[Celery Beat] Taxonomy check failed: {exc}")
        return {"error": str(exc)}
