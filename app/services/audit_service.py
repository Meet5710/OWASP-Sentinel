"""OWASP Sentinel - Audit Logging Service."""

from typing import Any

from sqlalchemy.orm import Session

from app.models.db.audit import AuditEvent


def record_audit_event(
    db: Session,
    event_type: str,
    actor: str,
    description: str,
    target_id: str | None = None,
    scope_id: str | None = None,
    ip_address: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    """Record an immutable security audit event."""
    event = AuditEvent(
        event_type=event_type,
        actor=actor,
        target_id=target_id,
        scope_id=scope_id,
        description=description,
        ip_address=ip_address,
        metadata_json=metadata or {},
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event
