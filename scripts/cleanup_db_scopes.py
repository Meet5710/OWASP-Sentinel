"""OWASP Sentinel - Database Cleanup Script

Removes obsolete test-generated scope grants, deduplicates inventory targets,
re-links all findings and scan history cleanly, and establishes standard production scopes.
"""

from datetime import datetime, timezone
import sys
from pathlib import Path

# Ensure project root is in sys.path
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from app.db.session import SessionLocal
from app.models.db.asset import AuthorizedAsset
from app.models.db.audit import AuditEvent
from app.models.db.finding import Finding, TechnicalObservation
from app.models.db.organization import Organization
from app.models.db.scan import ScanJob
from app.models.db.schedule import ScheduledScan
from app.models.db.scope import ScopeGrant


def cleanup():
    db = SessionLocal()
    try:
        # 1. Clean primary organizations
        acme = db.query(Organization).filter(Organization.name == "Acme Cyber Corp").first()
        if not acme:
            acme = Organization(name="Acme Cyber Corp", contact_email="sec-admin@acme.com")
            db.add(acme)
            db.flush()

        defense = db.query(Organization).filter(Organization.name == "Global Defense Ltd").first()
        if not defense:
            defense = Organization(name="Global Defense Ltd", contact_email="ciso@globaldefense.com")
            db.add(defense)
            db.flush()

        smart_org = db.query(Organization).filter(Organization.name == "Smart Trichy Corp").first()
        if not smart_org:
            smart_org = Organization(name="Smart Trichy Corp", contact_email="admin@smarttrichy.in")
            db.add(smart_org)
            db.flush()

        # 2. Define clean production scopes
        valid_from = datetime(2026, 1, 1, tzinfo=timezone.utc)
        valid_until = datetime(2027, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

        clean_scopes_defs = [
            {
                "scope_code": "SCOPE-CORP-PROD",
                "title": "Enterprise Production Web Apps",
                "organization_id": acme.id,
                "authorized_by": "sec-admin@acme.com",
                "authorization_document_ref": "DOC-AUTH-2026-CORP",
                "valid_from": valid_from,
                "valid_until": valid_until,
                "max_requests_per_minute": 120,
                "request_budget": 10000,
                "allowed_protocols": ["http", "https"],
                "allowed_ports": [80, 443, 8080, 8443],
                "allow_subdomains": True,
                "allow_private_ips": False,
                "is_active": True,
            },
            {
                "scope_code": "SCOPE-WEB-AUDIT",
                "title": "External Web Security Audit",
                "organization_id": defense.id,
                "authorized_by": "ciso@globaldefense.com",
                "authorization_document_ref": "DOC-AUTH-2026-AUDIT",
                "valid_from": valid_from,
                "valid_until": valid_until,
                "max_requests_per_minute": 60,
                "request_budget": 5000,
                "allowed_protocols": ["http", "https"],
                "allowed_ports": [80, 443],
                "allow_subdomains": True,
                "allow_private_ips": False,
                "is_active": True,
            },
            {
                "scope_code": "SCOPE-API-SERVICES",
                "title": "API & Microservices Security Scope",
                "organization_id": smart_org.id,
                "authorized_by": "api-lead@smarttrichy.in",
                "authorization_document_ref": "DOC-AUTH-2026-API",
                "valid_from": valid_from,
                "valid_until": valid_until,
                "max_requests_per_minute": 100,
                "request_budget": 8000,
                "allowed_protocols": ["http", "https"],
                "allowed_ports": [80, 443],
                "allow_subdomains": True,
                "allow_private_ips": False,
                "is_active": True,
            },
        ]

        clean_scopes = {}
        for s_def in clean_scopes_defs:
            existing = db.query(ScopeGrant).filter(ScopeGrant.scope_code == s_def["scope_code"]).first()
            if not existing:
                existing = ScopeGrant(**s_def)
                db.add(existing)
                db.flush()
            clean_scopes[s_def["scope_code"]] = existing

        primary_scope = clean_scopes["SCOPE-CORP-PROD"]
        audit_scope = clean_scopes["SCOPE-WEB-AUDIT"]
        api_scope = clean_scopes["SCOPE-API-SERVICES"]

        # 3. Deduplicate Authorized Assets and preserve all findings & scans
        all_assets = db.query(AuthorizedAsset).all()
        by_url: dict[str, list[AuthorizedAsset]] = {}
        for a in all_assets:
            by_url.setdefault(a.canonical_url, []).append(a)

        survivors: dict[str, AuthorizedAsset] = {}
        for url, asset_list in by_url.items():
            best = None
            best_f_count = -1
            for a in asset_list:
                f_count = db.query(Finding).filter(Finding.target_id == a.id).count()
                if f_count > best_f_count:
                    best_f_count = f_count
                    best = a
            assert best is not None
            survivors[url] = best

            if "smarttrichy" in url:
                best.scope_grant_id = primary_scope.id
                best.organization_id = smart_org.id
                best.approval_status = "APPROVED"
            elif "suraksha" in url:
                best.scope_grant_id = audit_scope.id
                best.organization_id = defense.id
                best.approval_status = "APPROVED"
            elif "api" in url:
                best.scope_grant_id = api_scope.id
                best.organization_id = acme.id
                best.approval_status = "APPROVED"
            else:
                best.scope_grant_id = primary_scope.id
                best.organization_id = acme.id
                best.approval_status = "APPROVED"

            for a in asset_list:
                if a.id != best.id:
                    db.query(Finding).filter(Finding.target_id == a.id).update({"target_id": best.id})
                    db.query(TechnicalObservation).filter(TechnicalObservation.target_id == a.id).update(
                        {"target_id": best.id}
                    )
                    db.query(ScanJob).filter(ScanJob.target_id == a.id).update(
                        {"target_id": best.id, "scope_grant_id": best.scope_grant_id}
                    )
                    db.query(ScheduledScan).filter(ScheduledScan.target_id == a.id).update(
                        {"target_id": best.id, "scope_grant_id": best.scope_grant_id}
                    )
                    db.delete(a)

        db.flush()

        # Update remaining ScanJobs, ScheduledScans, AuditEvents
        clean_scope_ids = [s.id for s in clean_scopes.values()]
        for sj in db.query(ScanJob).all():
            if sj.scope_grant_id not in clean_scope_ids:
                asset = db.query(AuthorizedAsset).filter(AuthorizedAsset.id == sj.target_id).first()
                sj.scope_grant_id = asset.scope_grant_id if asset else primary_scope.id

        for sc in db.query(ScheduledScan).all():
            if sc.scope_grant_id not in clean_scope_ids:
                asset = db.query(AuthorizedAsset).filter(AuthorizedAsset.id == sc.target_id).first()
                sc.scope_grant_id = asset.scope_grant_id if asset else primary_scope.id

        for ae in db.query(AuditEvent).all():
            if ae.scope_id and ae.scope_id not in clean_scope_ids:
                ae.scope_id = primary_scope.id

        db.flush()

        # 4. Delete all old test scope grants
        old_scopes = db.query(ScopeGrant).filter(~ScopeGrant.id.in_(clean_scope_ids)).all()
        print(f"Deleting {len(old_scopes)} old test scope grants...")
        for os in old_scopes:
            db.delete(os)

        db.commit()
        print("Cleanup completed successfully!")

        # Print summary
        print("\n=== Remaining Scope Grants ===")
        for s in db.query(ScopeGrant).all():
            print(f"  - [{s.scope_code}] {s.title} ({s.organization.name})")

        print("\n=== Remaining Clean Authorized Assets ===")
        for a in db.query(AuthorizedAsset).all():
            print(f"  - {a.canonical_url} (Scope: {a.scope_grant.scope_code}, Status: {a.approval_status})")

        print(f"\nTotal Findings Preserved: {db.query(Finding).count()}")
        print(f"Total Scan Jobs Preserved: {db.query(ScanJob).count()}")

    except Exception as e:
        db.rollback()
        print("Error during cleanup:", e)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    cleanup()
