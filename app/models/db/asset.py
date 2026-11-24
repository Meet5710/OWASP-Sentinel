"""OWASP Sentinel - Authorized Asset ORM Model."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, generate_uuid

if TYPE_CHECKING:
    from app.models.db.organization import Organization
    from app.models.db.scope import ScopeGrant


class AuthorizedAsset(Base, TimestampMixin):
    """An approved, scoped web asset eligible for security assessment."""

    __tablename__ = "authorized_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scope_grant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scope_grants.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Asset Identity & Normalization
    target_input: Mapped[str] = mapped_column(String(2048), nullable=False)
    canonical_url: Mapped[str] = mapped_column(String(2048), index=True, nullable=False)
    host: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    scheme: Mapped[str] = mapped_column(String(10), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    path: Mapped[str] = mapped_column(String(2048), default="/", nullable=False)

    # Classification & Network Characteristics
    asset_type: Mapped[str] = mapped_column(String(50), default="URL", nullable=False)  # DOMAIN, SUBDOMAIN, IP, URL
    is_ip_address: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_private_ip: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved_ips: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    # Authorization & Governance Lifecycle
    approval_status: Mapped[str] = mapped_column(
        String(50), default="APPROVED", nullable=False
    )  # PENDING, APPROVED, REVOKED, EXPIRED
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="assets")
    scope_grant: Mapped["ScopeGrant"] = relationship("ScopeGrant", back_populates="assets")
