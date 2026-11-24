"""OWASP Sentinel - Scope Grant Management Service."""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import SentinelException
from app.models.db.organization import Organization
from app.models.db.scope import ScopeGrant
from app.models.schemas.scope import ScopeGrantCreate
from app.services.audit_service import record_audit_event


def get_or_create_organization(db: Session, name: str, contact_email: str) -> Organization:
    """Find existing organization by name or create a new one."""
    stmt = select(Organization).where(Organization.name == name)
    org = db.scalars(stmt).first()
    if not org:
        org = Organization(name=name, contact_email=contact_email)
        db.add(org)
        db.commit()
        db.refresh(org)
    return org


def create_scope_grant(db: Session, data: ScopeGrantCreate) -> ScopeGrant:
    """Register and persist a new authorized scope grant."""
    # Check if scope_code already exists
    existing = get_scope_by_code(db, data.scope_code)
    if existing:
        raise SentinelException(
            message=f"Scope code '{data.scope_code}' already exists.",
            code="SCOPE_ALREADY_EXISTS",
        )

    org = get_or_create_organization(
        db, name=data.organization_name, contact_email=f"security@{data.organization_name.lower().replace(' ', '')}.com"
    )

    scope = ScopeGrant(
        organization_id=org.id,
        scope_code=data.scope_code.strip().upper(),
        title=data.title.strip(),
        authorized_by=data.authorized_by.strip(),
        authorization_document_ref=data.authorization_document_ref,
        valid_from=data.valid_from,
        valid_until=data.valid_until,
        max_requests_per_minute=data.max_requests_per_minute,
        request_budget=data.request_budget,
        allowed_protocols=data.allowed_protocols,
        allowed_ports=data.allowed_ports,
        allow_subdomains=data.allow_subdomains,
        allow_private_ips=data.allow_private_ips,
        is_active=True,
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)

    record_audit_event(
        db=db,
        event_type="SCOPE_CREATED",
        actor=data.authorized_by,
        scope_id=scope.id,
        description=f"Scope grant '{scope.scope_code}' created for {org.name}.",
        metadata={
            "scope_code": scope.scope_code,
            "valid_from": scope.valid_from.isoformat(),
            "valid_until": scope.valid_until.isoformat(),
            "allowed_ports": scope.allowed_ports,
        },
    )

    return scope


def get_scope_by_code(db: Session, scope_code: str) -> ScopeGrant | None:
    """Retrieve scope grant by its unique scope code."""
    stmt = select(ScopeGrant).where(ScopeGrant.scope_code == scope_code.strip().upper())
    return db.scalars(stmt).first()


def list_scope_grants(db: Session, active_only: bool = False) -> list[ScopeGrant]:
    """Return all configured scope grants."""
    stmt = select(ScopeGrant)
    if active_only:
        stmt = stmt.where(ScopeGrant.is_active.is_(True))
    return list(db.scalars(stmt).all())


def is_scope_valid(scope: ScopeGrant) -> tuple[bool, str]:
    """Validate whether scope grant is currently active and within valid time bounds."""
    if not scope.is_active:
        return False, "Scope grant is deactivated."

    now = datetime.now(timezone.utc)
    valid_from = scope.valid_from if scope.valid_from.tzinfo else scope.valid_from.replace(tzinfo=timezone.utc)
    valid_until = scope.valid_until if scope.valid_until.tzinfo else scope.valid_until.replace(tzinfo=timezone.utc)

    if now < valid_from:
        return False, f"Scope grant authorization window has not started yet (starts at {valid_from.isoformat()})."
    if now > valid_until:
        return False, f"Scope grant has expired as of {valid_until.isoformat()}."

    return True, "Scope is valid and active."
