"""OWASP Sentinel - Scan Scheduling & Patch Verification Engine

Coordinates recurring assessments, calculates next execution intervals (Daily, Weekly, Cron),
triggers automated diffing, and generates patch verification records.
"""

import logging
from datetime import datetime, timedelta, timezone

from croniter import croniter
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import SentinelException
from app.models.db.asset import AuthorizedAsset
from app.models.db.finding import Finding, TechnicalObservation
from app.models.db.history import FindingHistoryRecord, PatchVerification
from app.models.db.scan import ScanJob
from app.models.db.schedule import ScheduledScan
from app.scanner.engine import ScannerEngine
from app.services.asset_service import check_target_authorization
from app.services.audit_service import record_audit_event

logger = logging.getLogger(__name__)


def calculate_next_run(
    frequency: str,
    cron_expr: str | None = None,
    base_time: datetime | None = None,
) -> datetime:
    """Calculate the next execution timestamp based on frequency policy or cron expression."""
    now = base_time or datetime.now(timezone.utc)
    freq_upper = frequency.upper()

    if freq_upper == "DAILY":
        return now + timedelta(days=1)
    elif freq_upper == "WEEKLY":
        return now + timedelta(days=7)
    elif freq_upper == "MONTHLY":
        return now + timedelta(days=30)
    elif freq_upper == "CRON" and cron_expr:
        try:
            itr = croniter(cron_expr, now)
            next_ts = itr.get_next(datetime)
            return next_ts.replace(tzinfo=timezone.utc) if not next_ts.tzinfo else next_ts
        except Exception as e:
            raise SentinelException(f"Invalid cron expression '{cron_expr}': {e}", code="INVALID_CRON") from e
    else:
        # Default to 7 days
        return now + timedelta(days=7)


def create_schedule(
    db: Session,
    target_id: str,
    frequency: str = "WEEKLY",
    cron_expression: str | None = None,
    rule_ids: list[str] | None = None,
) -> ScheduledScan:
    """Register a new recurring assessment schedule."""
    stmt = select(AuthorizedAsset).where(AuthorizedAsset.id == target_id)
    asset = db.scalars(stmt).first()
    if not asset:
        raise SentinelException(f"Asset ID '{target_id}' not found.", code="ASSET_NOT_FOUND")

    # Verify asset is approved
    if asset.approval_status != "APPROVED":
        raise SentinelException(
            f"Cannot schedule assessment: Asset status is '{asset.approval_status}'. Must be APPROVED.",
            code="ASSET_NOT_APPROVED",
        )

    next_run = calculate_next_run(frequency=frequency, cron_expr=cron_expression)

    schedule = ScheduledScan(
        target_id=asset.id,
        scope_grant_id=asset.scope_grant_id,
        frequency=frequency.upper(),
        cron_expression=cron_expression,
        is_active=True,
        next_run_at=next_run,
        rule_ids=rule_ids or [],
        schedule_metadata={"frequency": frequency.upper(), "configured_by": asset.scope_grant.authorized_by},
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    record_audit_event(
        db=db,
        event_type="SCAN_SCHEDULED",
        actor=asset.scope_grant.authorized_by,
        target_id=asset.id,
        scope_id=asset.scope_grant_id,
        description=f"Scheduled assessment ({frequency.upper()}) created for asset '{asset.canonical_url}'. Next run at {next_run.isoformat()}.",
    )

    return schedule


def evaluate_patch_verification_and_history(
    db: Session,
    target_id: str,
    current_scan_id: str,
) -> FindingHistoryRecord:
    """Compare findings against previous scan runs, create patch verifications, and record posture trend."""
    now = datetime.now(timezone.utc)

    # 1. Fetch current scan observations
    stmt_obs = select(TechnicalObservation).where(TechnicalObservation.scan_id == current_scan_id)
    current_obs = list(db.scalars(stmt_obs).all())
    current_issue_types = {o.technical_issue_type for o in current_obs}

    # 2. Fetch all known findings for this target
    stmt_findings = select(Finding).where(Finding.target_id == target_id)
    target_findings = list(db.scalars(stmt_findings).all())

    new_count = 0
    resolved_count = 0
    recurrent_count = 0

    for f in target_findings:
        is_observed_now = f.technical_issue_type in current_issue_types

        if is_observed_now:
            if f.first_seen_at == f.last_seen_at:
                # Newly identified in current scan
                new_count += 1
            elif f.validation_status == "CONFIRMED":
                # Persistently vulnerable
                recurrent_count += 1
                pv = PatchVerification(
                    finding_id=f.id,
                    scan_id=current_scan_id,
                    target_id=target_id,
                    verification_status="STILL_VULNERABLE",
                    notes=f"Weakness '{f.title}' remains present after re-assessment.",
                    evidence=f.evidence,
                )
                db.add(pv)
        else:
            # Not observed in current scan -> Potential remediation
            is_just_mitigated = (
                f.validation_status == "MITIGATED"
                and bool(f.status_history)
                and current_scan_id in str(f.status_history[-1].get("note", ""))
            )
            if f.validation_status in ("CONFIRMED", "POTENTIAL") or is_just_mitigated:
                resolved_count += 1
                old_status = f.validation_status if not is_just_mitigated else "CONFIRMED"
                f.validation_status = "MITIGATED"
                if not is_just_mitigated:
                    f.status_history = [
                        *f.status_history,
                        {
                            "from_status": old_status,
                            "to_status": "MITIGATED",
                            "timestamp": now.isoformat(),
                            "actor": "System/AutomatedVerification",
                            "note": f"Weakness is no longer observed in scan {current_scan_id}. Automatically verified as remediated.",
                        },
                    ]
                pv = PatchVerification(
                    finding_id=f.id,
                    scan_id=current_scan_id,
                    target_id=target_id,
                    verification_status="REMEDIATED",
                    notes=f"Weakness '{f.title}' was not detected in scan {current_scan_id}. Remediated successfully.",
                    evidence={"last_verified_scan": current_scan_id},
                )
                db.add(pv)

    # 3. Calculate Severity Metric Totals
    active_findings = [f for f in target_findings if f.validation_status == "CONFIRMED"]
    crit_count = sum(1 for f in active_findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in active_findings if f.severity == "HIGH")
    med_count = sum(1 for f in active_findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in active_findings if f.severity == "LOW")
    info_count = sum(1 for f in active_findings if f.severity == "INFO")

    history_record = FindingHistoryRecord(
        target_id=target_id,
        scan_id=current_scan_id,
        total_findings=len(active_findings),
        critical_count=crit_count,
        high_count=high_count,
        medium_count=med_count,
        low_count=low_count,
        info_count=info_count,
        new_findings_count=new_count,
        resolved_findings_count=resolved_count,
        recurrent_findings_count=recurrent_count,
        recorded_at=now,
    )
    db.add(history_record)
    db.commit()
    db.refresh(history_record)

    return history_record


async def trigger_due_schedules(db: Session) -> list[ScanJob]:
    """Execute all active recurring assessment schedules whose next_run_at has arrived."""
    now = datetime.now(timezone.utc)
    stmt = select(ScheduledScan).where(ScheduledScan.is_active.is_(True)).where(ScheduledScan.next_run_at <= now)
    due_schedules = list(db.scalars(stmt).all())
    executed_jobs: list[ScanJob] = []

    for schedule in due_schedules:
        try:
            # Check pre-scan clearance
            clearance = check_target_authorization(db, target=schedule.asset.canonical_url)
            if not clearance.is_authorized:
                logger.warning(f"Scheduled scan skipped for {schedule.asset.canonical_url}: {clearance.reason}")
                continue

            # Execute scan
            job = await ScannerEngine.execute_scan(
                db=db,
                asset_id=schedule.target_id,
                rule_ids=schedule.rule_ids if schedule.rule_ids else None,
            )

            # Evaluate patch verification and history metrics
            evaluate_patch_verification_and_history(
                db=db,
                target_id=schedule.target_id,
                current_scan_id=job.id,
            )

            # Advance next_run_at
            schedule.last_run_at = now
            schedule.last_scan_id = job.id
            schedule.next_run_at = calculate_next_run(
                frequency=schedule.frequency,
                cron_expr=schedule.cron_expression,
                base_time=now,
            )
            db.commit()
            executed_jobs.append(job)

        except Exception as e:
            logger.error(f"Error executing scheduled scan for {schedule.id}: {e}")
            db.rollback()

    return executed_jobs
