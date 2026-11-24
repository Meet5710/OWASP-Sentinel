"""OWASP Sentinel - Path Finder Background Job Queue Manager

Orchestrates asynchronous scan enqueueing across Celery/Redis worker queues
and high-speed non-blocking background task workers.
"""

import asyncio
import logging
from typing import Any, Dict, Optional

from fastapi import BackgroundTasks

from app.services.path_finder_broadcaster import broadcaster
from app.services.path_finder_service import run_path_finder_scan_task
from app.services.path_finder_state import state_store

logger = logging.getLogger(__name__)


def enqueue_path_finder_scan(
    scan_id: str,
    base_url: str,
    mode: str,
    config: Optional[Dict[str, Any]] = None,
    background_tasks: Optional[BackgroundTasks] = None,
) -> str:
    """Enqueue a Path Finder scan job to the background worker pool without blocking the main web server.

    1. Initializes live control flag to RUNNING in Redis/FastStateStore.
    2. Initializes real-time progress metrics.
    3. Attempts to dispatch to Celery worker queue if Redis broker is online.
    4. If Celery/Redis is offline, gracefully dispatches to asynchronous worker without blocking.

    Returns:
        Queue engine type used ("celery" or "async_worker").
    """
    cfg = config or {}

    # 1. Initialize control flag and metrics in fast state store
    state_store.set_control_flag(scan_id, "RUNNING")
    state_store.set_metrics(
        scan_id,
        {
            "progress_percent": 0.0,
            "requests_per_second": 0.0,
            "total_discovered": 0,
            "processed_paths": 0,
            "status": "PENDING",
        },
    )

    # Broadcast initial queued status
    broadcaster.publish(
        scan_id,
        "status_change",
        {"status": "PENDING", "message": "Scan job successfully queued for execution."},
    )

    # 2. Check Celery / Redis availability
    if state_store.is_redis_available():
        try:
            from app.tasks.path_finder_tasks import execute_path_finder_scan_celery_task

            execute_path_finder_scan_celery_task.delay(
                scan_id=scan_id,
                base_url=base_url,
                mode=mode,
                config=cfg,
            )
            logger.info("Enqueued Path Finder scan '%s' to Celery/Redis worker queue.", scan_id)
            return "celery"
        except Exception as exc:
            logger.warning(
                "Celery dispatch failed for scan '%s' (%s). Falling back to asynchronous worker.",
                scan_id,
                exc,
            )

    # 3. Fallback to non-blocking async task worker
    if background_tasks is not None:
        background_tasks.add_task(
            run_path_finder_scan_task,
            scan_id,
            base_url,
            mode,
            cfg,
        )
    else:
        # If called outside request context (e.g. tests/scripts), schedule in event loop
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(run_path_finder_scan_task(scan_id, base_url, mode, cfg))
        except RuntimeError:
            asyncio.run(run_path_finder_scan_task(scan_id, base_url, mode, cfg))

    logger.info("Dispatched Path Finder scan '%s' via non-blocking asynchronous worker.", scan_id)
    return "async_worker"

