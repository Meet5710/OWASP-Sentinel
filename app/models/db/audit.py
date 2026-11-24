"""OWASP Sentinel - Audit Event ORM Model."""

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, generate_uuid


class AuditEvent(Base):
    """Immutable audit trail for authorization, scope modifications, and scan requests."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    event_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)  # User email or system process
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    scope_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
