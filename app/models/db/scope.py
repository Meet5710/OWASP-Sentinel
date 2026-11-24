"""OWASP Sentinel - Scope Grant ORM Model."""
"""OWASP Sentinel - Scope Grant ORM Model."""
"""OWASP Sentinel - Scope Grant ORM Model."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, generate_uuid

if TYPE_CHECKING:
    from app.models.db.asset import AuthorizedAsset
    from app.models.db.organization import Organization


class ScopeGrant(Base, TimestampMixin):
    """Defines explicit administrative authorization and boundaries for security testing."""

    __tablename__ = "scope_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scope_code: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    authorized_by: Mapped[str] = mapped_column(String(255), nullable=False)
    authorization_document_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Validity Period
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Operational & Safety Controls
    max_requests_per_minute: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    request_budget: Mapped[int] = mapped_column(Integer, default=5000, nullable=False)
    allowed_protocols: Mapped[list[str]] = mapped_column(JSON, default=lambda: ["http", "https"], nullable=False)
    allowed_ports: Mapped[list[int]] = mapped_column(JSON, default=lambda: [80, 443, 8080, 8443], nullable=False)

    # Subdomain & Private Network Boundaries
    allow_subdomains: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allow_private_ips: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="scope_grants")
    assets: Mapped[list["AuthorizedAsset"]] = relationship(
        "AuthorizedAsset", back_populates="scope_grant", cascade="all, delete-orphan"
    )
