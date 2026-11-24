"""OWASP Sentinel - Audit Log API Endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.db.audit import AuditEvent
from app.models.schemas.audit import AuditEventResponse

router = APIRouter()


@router.get(
    "",
    response_model=list[AuditEventResponse],
    summary="List Security Audit Trail Events",
)
def list_audit_events(
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[AuditEventResponse]:
    """Retrieve immutable audit event trail."""
    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    events = list(db.scalars(stmt).all())
    return [
        AuditEventResponse(
            id=e.id,
            event_type=e.event_type,
            actor=e.actor,
            target_id=e.target_id,
            scope_id=e.scope_id,
            description=e.description,
            ip_address=e.ip_address,
            metadata_json=e.metadata_json,
            created_at=e.created_at,
        )
        for e in events
    ]
