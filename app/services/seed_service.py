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

    last_status: str = ""

    @classmethod
    def seed_baseline_findings(cls, db: Session, force: bool = False) -> bool:
        """Seed baseline findings, scans, observations, and categories if database is empty or forced."""
        try:
            existing_findings = db.query(Finding).count()
            if existing_findings > 0 and not force:
                cls.last_status = f"Skipped: Database already contains {existing_findings} findings."
                logger.info("Database already contains %d findings; skipping baseline seeding.", existing_findings)
                return False

            candidates = [
                Path(__file__).resolve().parent.parent / "db" / "fixtures" / "baseline_data.json.gz",
                Path(__file__).resolve().parent.parent.parent / "app" / "db" / "fixtures" / "baseline_data.json.gz",
                Path.cwd() / "app" / "db" / "fixtures" / "baseline_data.json.gz",
                Path.cwd() / "db" / "fixtures" / "baseline_data.json.gz",
            ]
            fixture_path = None
            for p in candidates:
                if p.exists():
                    fixture_path = p
                    break

            if not fixture_path:
                cls.last_status = f"Error: Baseline fixture not found in {[str(c) for c in candidates]}."
                logger.warning(cls.last_status)
                return False

            logger.info("Seeding baseline findings dataset from %s...", fixture_path)
            with gzip.open(fixture_path, "rt", encoding="utf-8") as f:
                data = json.load(f)

            # Track ID remappings if org or scope exists with a different ID
            org_id_map = {}
            scope_id_map = {}

            # 1. Organizations
            for row in data.get("organizations", []):
                existing_org = db.query(Organization).filter(
                    (Organization.id == row["id"]) | (Organization.name == row["name"])
                ).first()
                if existing_org:
                    org_id_map[row["id"]] = existing_org.id
                else:
                    org = Organization(
                        id=row["id"],
                        name=row["name"],
                        contact_email=row.get("contact_email", "admin@sentinel.local"),
                        description=row.get("description"),
                        created_at=parse_dt(row.get("created_at")),
                        updated_at=parse_dt(row.get("updated_at")),
                    )
                    db.add(org)
                    org_id_map[row["id"]] = org.id
            db.flush()

            fallback_org_id = next(iter(org_id_map.values()), None)
            if not fallback_org_id:
                any_org = db.query(Organization).first()
                fallback_org_id = any_org.id if any_org else None

            # 2. Scope Grants
            for row in data.get("scope_grants", []):
                existing_scope = db.query(ScopeGrant).filter(
                    (ScopeGrant.id == row["id"]) | (ScopeGrant.scope_code == row["scope_code"])
                ).first()
                if existing_scope:
                    scope_id_map[row["id"]] = existing_scope.id
                else:
                    target_org_id = org_id_map.get(row["organization_id"], fallback_org_id)
                    scope = ScopeGrant(
                        id=row["id"],
                        organization_id=target_org_id,
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
                    scope_id_map[row["id"]] = scope.id
            db.flush()

            fallback_scope_id = next(iter(scope_id_map.values()), None)
            if not fallback_scope_id:
                any_scope = db.query(ScopeGrant).first()
                fallback_scope_id = any_scope.id if any_scope else None

            # 3. Authorized Assets (Seed with approval_status="BASELINE" to keep user Target Inventory clean)
            asset_id_map = {}
            for row in data.get("authorized_assets", []):
                existing_asset = db.query(AuthorizedAsset).filter(
                    (AuthorizedAsset.id == row["id"]) |
                    (AuthorizedAsset.canonical_url == row["canonical_url"]) |
                    (AuthorizedAsset.host == row["host"])
                ).first()
                if existing_asset:
                    asset_id_map[row["id"]] = existing_asset.id
                else:
                    target_org_id = org_id_map.get(row["organization_id"], fallback_org_id)
                    target_scope_id = scope_id_map.get(row["scope_grant_id"], fallback_scope_id)
                    asset = AuthorizedAsset(
                        id=row["id"],
                        organization_id=target_org_id,
                        scope_grant_id=target_scope_id,
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
                    asset_id_map[row["id"]] = asset.id
            db.flush()

            # 4. Scan Jobs
            scan_id_map = {}
            for row in data.get("scan_jobs", []):
                mapped_target_id = asset_id_map.get(row["target_id"], row["target_id"])
                if not db.query(AuthorizedAsset).filter(AuthorizedAsset.id == mapped_target_id).first():
                    continue

                existing_scan = db.query(ScanJob).filter(ScanJob.id == row["id"]).first()
                if existing_scan:
                    scan_id_map[row["id"]] = existing_scan.id
                else:
                    target_scope_id = scope_id_map.get(row["scope_grant_id"], fallback_scope_id)
                    scan = ScanJob(
                        id=row["id"],
                        target_id=mapped_target_id,
                        scope_grant_id=target_scope_id,
                        status=row.get("status", "COMPLETED"),
                        started_at=parse_dt(row.get("started_at")),
                        completed_at=parse_dt(row.get("completed_at")),
                        total_checks=row.get("total_checks", 0),
                        passed_checks=row.get("passed_checks", 0),
                        failed_checks=row.get("failed_checks", 0),
                        error_message=(row.get("error_message") or "")[:1000] if row.get("error_message") else None,
                        scan_metadata=parse_json(row.get("scan_metadata"), {}),
                        created_at=parse_dt(row.get("created_at")),
                        updated_at=parse_dt(row.get("updated_at")),
                    )
                    db.add(scan)
                    scan_id_map[row["id"]] = scan.id
            db.flush()

            # 5. Technical Observations
            obs_id_map = {}
            for row in data.get("technical_observations", []):
                mapped_target_id = asset_id_map.get(row["target_id"], row["target_id"])
                mapped_scan_id = scan_id_map.get(row["scan_id"], row["scan_id"])
                if not db.query(ScanJob).filter(ScanJob.id == mapped_scan_id).first():
                    continue
                if not db.query(AuthorizedAsset).filter(AuthorizedAsset.id == mapped_target_id).first():
                    continue

                existing_obs = db.query(TechnicalObservation).filter(TechnicalObservation.id == row["id"]).first()
                if existing_obs:
                    obs_id_map[row["id"]] = existing_obs.id
                else:
                    obs = TechnicalObservation(
                        id=row["id"],
                        scan_id=mapped_scan_id,
                        target_id=mapped_target_id,
                        rule_id=str(row["rule_id"])[:100],
                        technical_issue_type=str(row["technical_issue_type"])[:100],
                        title=str(row["title"])[:255],
                        severity=str(row["severity"])[:50],
                        confidence=str(row.get("confidence", "CERTAIN"))[:50],
                        evidence=parse_json(row.get("evidence"), {}),
                        remediation=str(row.get("remediation", ""))[:2000],
                        references=parse_json(row.get("references"), []),
                        created_at=parse_dt(row.get("created_at")),
                        updated_at=parse_dt(row.get("updated_at")),
                    )
                    db.add(obs)
                    obs_id_map[row["id"]] = obs.id
            db.flush()

            # 6. Findings
            finding_id_map = {}
            for row in data.get("findings", []):
                mapped_target_id = asset_id_map.get(row["target_id"], row["target_id"])
                mapped_scan_id = scan_id_map.get(row["scan_id"], row["scan_id"])
                mapped_obs_id = obs_id_map.get(row.get("observation_id"))

                if not db.query(AuthorizedAsset).filter(AuthorizedAsset.id == mapped_target_id).first():
                    continue
                if not db.query(ScanJob).filter(ScanJob.id == mapped_scan_id).first():
                    continue

                existing_fnd = db.query(Finding).filter(Finding.id == row["id"]).first()
                if existing_fnd:
                    finding_id_map[row["id"]] = existing_fnd.id
                else:
                    fnd = Finding(
                        id=row["id"],
                        target_id=mapped_target_id,
                        scan_id=mapped_scan_id,
                        observation_id=mapped_obs_id,
                        detection_rule_id=str(row["detection_rule_id"])[:100],
                        technical_issue_type=str(row["technical_issue_type"])[:100],
                        title=str(row["title"])[:255],
                        severity=str(row["severity"])[:50],
                        confidence=str(row.get("confidence", "CERTAIN"))[:50],
                        validation_status=str(row.get("validation_status", "CONFIRMED"))[:50],
                        first_seen_at=parse_dt(row.get("first_seen_at")),
                        last_seen_at=parse_dt(row.get("last_seen_at")),
                        evidence=parse_json(row.get("evidence"), {}),
                        remediation_recommendations=str(row.get("remediation_recommendations", "")),
                        references=parse_json(row.get("references"), []),
                        status_history=parse_json(row.get("status_history"), []),
                        created_at=parse_dt(row.get("created_at")),
                        updated_at=parse_dt(row.get("updated_at")),
                    )
                    db.add(fnd)
                    finding_id_map[row["id"]] = fnd.id
            db.flush()

            # 7. Finding Category Mappings
            for row in data.get("finding_category_mappings", []):
                mapped_fnd_id = finding_id_map.get(row["finding_id"], row["finding_id"])
                if not db.query(Finding).filter(Finding.id == mapped_fnd_id).first():
                    continue

                if not db.query(FindingCategoryMapping).filter(FindingCategoryMapping.id == row["id"]).first():
                    raw_code = str(row.get("owasp_category_code", "")).strip()
                    raw_title = str(row.get("owasp_category_title", "")).strip()
                    if "-" in raw_code:
                        clean_code = raw_code.split("-")[0].strip()
                        clean_title = raw_title or raw_code.split("-", 1)[1].strip()
                    elif " " in raw_code:
                        clean_code = raw_code.split(" ", 1)[0].strip()
                        clean_title = raw_title or raw_code.split(" ", 1)[1].strip()
                    else:
                        clean_code = raw_code
                        clean_title = raw_title or raw_code

                    mapping = FindingCategoryMapping(
                        id=row["id"],
                        finding_id=mapped_fnd_id,
                        owasp_edition=str(row["owasp_edition"])[:50],
                        owasp_category_code=clean_code[:50],
                        owasp_category_title=clean_title[:255],
                        justification=str(row.get("justification", "")),
                        created_at=parse_dt(row.get("created_at")),
                    )
                    db.add(mapping)

            db.commit()
            msg = (
                f"Successfully seeded baseline data: {len(data.get('findings', []))} findings, "
                f"{len(data.get('finding_category_mappings', []))} category mappings, "
                f"{len(data.get('technical_observations', []))} observations, "
                f"{len(data.get('scan_jobs', []))} scan jobs."
            )
            cls.last_status = msg
            logger.info(msg)
            return True

        except Exception as e:
            db.rollback()
            cls.last_status = f"Database Exception during seeding: {type(e).__name__}: {e}"
            logger.error("Failed to seed baseline findings dataset: %s", e, exc_info=True)
            return False

