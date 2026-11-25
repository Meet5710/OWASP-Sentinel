"""OWASP Sentinel - Baseline Data Seeding Service.

Seeds the comprehensive OWASP Top 10 findings, category mappings,
technical observations, and scans from the baseline fixture on application startup
when running on fresh environments (such as Render or Docker).
"""

from datetime import datetime
import gzip
import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.models.db.asset import AuthorizedAsset
from app.models.db.finding import Finding, FindingCategoryMapping, TechnicalObservation
from app.models.db.organization import Organization
from app.models.db.scan import ScanJob
from app.models.db.scope import ScopeGrant

logger = logging.getLogger("sentinel.seed")


def parse_dt(val: Any) -> datetime | None:
    """Safely convert strings or datetimes to Python datetime objects."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        # Handles '2026-10-29 13:52:42.788830' and standard ISO formats
        clean_val = str(val).strip().replace(" ", "T")
        return datetime.fromisoformat(clean_val)
    except Exception:
        return None


def parse_json(val: Any, default: Any) -> Any:
    """Ensure JSON columns are Python dict/list structures rather than unparsed strings."""
    if val is None:
        return default
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return default
    return default


class BaselineSeedService:
    """Service to load and seed baseline security findings into the database."""

    @classmethod
    def seed_baseline_findings(cls, db: Session, force: bool = False) -> bool:
        """Seed baseline findings, scans, observations, and categories if database is empty or forced."""
        try:
            existing_findings = db.query(Finding).count()
            if existing_findings > 0 and not force:
                logger.info("Database already contains %d findings; skipping baseline seeding.", existing_findings)
                return False

            fixture_path = Path(__file__).resolve().parent.parent / "db" / "fixtures" / "baseline_data.json.gz"
            if not fixture_path.exists():
                logger.warning("Baseline findings fixture not found at %s", fixture_path)
                return False

            logger.info("Seeding baseline findings dataset from %s...", fixture_path)
            with gzip.open(fixture_path, "rt", encoding="utf-8") as f:
                data = json.load(f)

            # 1. Organizations
            for row in data.get("organizations", []):
                if not db.query(Organization).filter(Organization.id == row["id"]).first():
                    org = Organization(
                        id=row["id"],
                        name=row["name"],
                        contact_email=row["contact_email"],
                        description=row.get("description"),
                        created_at=parse_dt(row.get("created_at")),
                        updated_at=parse_dt(row.get("updated_at")),
                    )
                    db.add(org)
            db.flush()

            # 2. Scope Grants
            for row in data.get("scope_grants", []):
                if not db.query(ScopeGrant).filter(ScopeGrant.id == row["id"]).first():
                    scope = ScopeGrant(
                        id=row["id"],
                        organization_id=row["organization_id"],
                        scope_code=row["scope_code"],
                        title=row["title"],
                        authorized_by=row["authorized_by"],
                        authorization_document_ref=row.get("authorization_document_ref"),
                        valid_from=parse_dt(row.get("valid_from")),
                        valid_until=parse_dt(row.get("valid_until")),
                        max_requests_per_minute=row.get("max_requests_per_minute", 60),
                        request_budget=row.get("request_budget", 1000),
                        allowed_protocols=parse_json(row.get("allowed_protocols"), ["http", "https"]),
                        allowed_ports=parse_json(row.get("allowed_ports"), [80, 443]),
                        allow_subdomains=bool(row.get("allow_subdomains", False)),
                        allow_private_ips=bool(row.get("allow_private_ips", False)),
                        is_active=bool(row.get("is_active", True)),
                        created_at=parse_dt(row.get("created_at")),
                        updated_at=parse_dt(row.get("updated_at")),
                    )
                    db.add(scope)
            db.flush()

            # 3. Authorized Assets (Seed with approval_status="BASELINE" to keep user Target Inventory clean)
            for row in data.get("authorized_assets", []):
                if not db.query(AuthorizedAsset).filter(AuthorizedAsset.id == row["id"]).first():
                    asset = AuthorizedAsset(
                        id=row["id"],
                        organization_id=row["organization_id"],
                        scope_grant_id=row["scope_grant_id"],
                        target_input=row["target_input"],
                        canonical_url=row["canonical_url"],
                        host=row["host"],
                        scheme=row["scheme"],
                        port=row["port"],
                        path=row.get("path", "/"),
                        asset_type=row.get("asset_type", "URL"),
                        is_ip_address=bool(row.get("is_ip_address", False)),
                        is_private_ip=bool(row.get("is_private_ip", False)),
                        resolved_ips=parse_json(row.get("resolved_ips"), []),
                        approval_status="BASELINE",  # Tag as BASELINE so user's Target Inventory stays clean
                        approved_by=row.get("approved_by"),
                        approved_at=parse_dt(row.get("approved_at")),
                        created_at=parse_dt(row.get("created_at")),
                        updated_at=parse_dt(row.get("updated_at")),
                    )
                    db.add(asset)
            db.flush()

            # 4. Scan Jobs
            for row in data.get("scan_jobs", []):
                if not db.query(ScanJob).filter(ScanJob.id == row["id"]).first():
                    scan = ScanJob(
                        id=row["id"],
                        target_id=row["target_id"],
                        scope_grant_id=row["scope_grant_id"],
                        status=row.get("status", "COMPLETED"),
                        started_at=parse_dt(row.get("started_at")),
                        completed_at=parse_dt(row.get("completed_at")),
                        total_checks=row.get("total_checks", 0),
                        passed_checks=row.get("passed_checks", 0),
                        failed_checks=row.get("failed_checks", 0),
                        error_message=row.get("error_message"),
                        scan_metadata=parse_json(row.get("scan_metadata"), {}),
                        created_at=parse_dt(row.get("created_at")),
                        updated_at=parse_dt(row.get("updated_at")),
                    )
                    db.add(scan)
            db.flush()

            # 5. Technical Observations
            for row in data.get("technical_observations", []):
                if not db.query(TechnicalObservation).filter(TechnicalObservation.id == row["id"]).first():
                    obs = TechnicalObservation(
                        id=row["id"],
                        scan_id=row["scan_id"],
                        target_id=row["target_id"],
                        rule_id=row["rule_id"],
                        technical_issue_type=row["technical_issue_type"],
                        title=row["title"],
                        severity=row["severity"],
                        confidence=row.get("confidence", "CERTAIN"),
                        evidence=parse_json(row.get("evidence"), {}),
                        remediation=row.get("remediation", ""),
                        references=parse_json(row.get("references"), []),
                        created_at=parse_dt(row.get("created_at")),
                        updated_at=parse_dt(row.get("updated_at")),
                    )
                    db.add(obs)
            db.flush()

            # 6. Findings
            for row in data.get("findings", []):
                if not db.query(Finding).filter(Finding.id == row["id"]).first():
                    fnd = Finding(
                        id=row["id"],
                        target_id=row["target_id"],
                        scan_id=row["scan_id"],
                        observation_id=row.get("observation_id"),
                        detection_rule_id=row["detection_rule_id"],
                        technical_issue_type=row["technical_issue_type"],
                        title=row["title"],
                        severity=row["severity"],
                        confidence=row.get("confidence", "CERTAIN"),
                        validation_status=row.get("validation_status", "CONFIRMED"),
                        first_seen_at=parse_dt(row.get("first_seen_at")),
                        last_seen_at=parse_dt(row.get("last_seen_at")),
                        evidence=parse_json(row.get("evidence"), {}),
                        remediation_recommendations=row.get("remediation_recommendations", ""),
                        references=parse_json(row.get("references"), []),
                        status_history=parse_json(row.get("status_history"), []),
                        created_at=parse_dt(row.get("created_at")),
                        updated_at=parse_dt(row.get("updated_at")),
                    )
                    db.add(fnd)
            db.flush()

            # 7. Finding Category Mappings
            for row in data.get("finding_category_mappings", []):
                if not db.query(FindingCategoryMapping).filter(FindingCategoryMapping.id == row["id"]).first():
                    mapping = FindingCategoryMapping(
                        id=row["id"],
                        finding_id=row["finding_id"],
                        owasp_edition=row["owasp_edition"],
                        owasp_category_code=row["owasp_category_code"],
                        owasp_category_title=row.get("owasp_category_title", ""),
                        justification=row.get("justification", ""),
                        created_at=parse_dt(row.get("created_at")),
                    )
                    db.add(mapping)

            db.commit()
            logger.info(
                "Successfully seeded baseline data: %d findings, %d category mappings, %d observations, %d scan jobs.",
                len(data.get("findings", [])),
                len(data.get("finding_category_mappings", [])),
                len(data.get("technical_observations", [])),
                len(data.get("scan_jobs", [])),
            )
            return True

        except Exception as e:
            db.rollback()
            logger.error("Failed to seed baseline findings dataset: %s", e, exc_info=True)
            return False

