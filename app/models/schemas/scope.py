"""OWASP Sentinel - Scope Grant Schemas."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator


class ScopeGrantCreate(BaseModel):
    """Payload to register an authorized testing scope grant."""

    organization_name: str = Field(
        ..., description="Organization or client name owning the target assets", min_length=2, max_length=150
    )
    scope_code: str = Field(
        ..., description="Unique alphanumeric identifier (e.g. 'SCOPE-2026-WEB')", min_length=3, max_length=100
    )
    title: str = Field(..., description="Scope title or engagement name", min_length=3, max_length=255)
    authorized_by: str = Field(
        ..., description="Name/email of approving authority or security officer", min_length=2, max_length=255
    )
    authorization_document_ref: str | None = Field(
        default=None, description="Contract, JIRA ticket, or approval doc reference", max_length=255
    )

    valid_from: datetime = Field(..., description="Start timestamp of authorized window")
    valid_until: datetime = Field(..., description="Expiration timestamp of authorized window")

    max_requests_per_minute: int = Field(default=60, ge=1, le=1000, description="Rate limit ceiling per minute")
    request_budget: int = Field(
        default=5000, ge=10, le=1000000, description="Total maximum requests allowed in this scope"
    )

    allowed_protocols: list[str] = Field(default=["http", "https"], description="Protocols permitted in this scope")
    allowed_ports: list[int] = Field(default=[80, 443, 8080, 8443], description="Permitted TCP ports")

    allow_subdomains: bool = Field(default=False, description="Whether subdomains are automatically in scope")
    allow_private_ips: bool = Field(default=False, description="Whether private lab / RFC1918 IPs are authorized")

    @field_validator("valid_until")
    @classmethod
    def validate_window(cls, v: datetime, info) -> datetime:
        valid_from = info.data.get("valid_from")
        if valid_from and v <= valid_from:
            raise ValueError("valid_until must be strictly after valid_from.")
        return v


class ScopeGrantResponse(BaseModel):
    """Public representation of an authorized testing scope grant."""

    id: str
    organization_id: str
    scope_code: str
    title: str
    authorized_by: str
    authorization_document_ref: str | None
    valid_from: datetime
    valid_until: datetime
    max_requests_per_minute: int
    request_budget: int
    allowed_protocols: list[str]
    allowed_ports: list[int]
    allow_subdomains: bool
    allow_private_ips: bool
    is_active: bool
    is_expired: bool
    created_at: datetime

    @classmethod
    def from_orm_model(cls, model) -> "ScopeGrantResponse":
        now = datetime.now(timezone.utc)
        # If model.valid_until is naive, make it UTC-aware for comparison
        until = model.valid_until if model.valid_until.tzinfo else model.valid_until.replace(tzinfo=timezone.utc)
        is_expired = now > until
        return cls(
            id=model.id,
            organization_id=model.organization_id,
            scope_code=model.scope_code,
            title=model.title,
            authorized_by=model.authorized_by,
            authorization_document_ref=model.authorization_document_ref,
            valid_from=model.valid_from,
            valid_until=model.valid_until,
            max_requests_per_minute=model.max_requests_per_minute,
            request_budget=model.request_budget,
            allowed_protocols=model.allowed_protocols,
            allowed_ports=model.allowed_ports,
            allow_subdomains=model.allow_subdomains,
            allow_private_ips=model.allow_private_ips,
            is_active=model.is_active,
            is_expired=is_expired,
            created_at=model.created_at,
        )
