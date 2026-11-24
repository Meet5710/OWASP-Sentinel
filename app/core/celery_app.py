"""OWASP Sentinel - Celery Application & Beat Configuration

Configures asynchronous task execution and periodic Celery Beat scheduling
for recurring assessments and taxonomy ingestion checks.
"""

import os

from celery import Celery
from celery.schedules import crontab

# Broker & backend URLs (configurable via environment variables)
REDIS_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "owasp_sentinel",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.path_finder_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # Beat Periodic Schedule
    beat_schedule={
        # Check and execute due recurring security scans every minute
        "trigger-due-scans-every-minute": {
            "task": "app.tasks.scan_tasks.trigger_due_schedules_task",
            "schedule": 60.0,
        },
        # Check official OWASP sources for taxonomy updates once daily at 03:00 UTC
        "check-owasp-taxonomy-daily": {
            "task": "app.tasks.scan_tasks.ingest_taxonomy_task",
            "schedule": crontab(hour=3, minute=0),
        },
    },
)
