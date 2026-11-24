"""OWASP Sentinel - Audit Schemas."""

from datetime import datetime

from pydantic import BaseModel, Field


class AuditEventResponse(BaseModel):
    """Immutable audit record representation."""

    id: str
    event_type: str
    actor: str
    target_id: str | None = None
    scope_id: str | None = None
    description: str
    ip_address: str | None = None
    metadata_json: dict = Field(default_factory=dict)
    created_at: datetime
