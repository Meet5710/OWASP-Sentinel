"""OWASP Sentinel - Scan Job ORM Model."""
"""OWASP Sentinel - Scan Job ORM Model."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, generate_uuid

if TYPE_CHECKING:
    from app.models.db.asset import AuthorizedAsset
    from app.models.db.finding import TechnicalObservation
    from app.models.db.scope import ScopeGrant


class ScanJob(Base, TimestampMixin):
    """Tracks an assessment execution against an authorized target asset."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("authorized_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scope_grant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scope_grants.id", ondelete="CASCADE"), nullable=False, index=True
    )

    status: Mapped[str] = mapped_column(
        String(50), default="PENDING", nullable=False, index=True
    )  # PENDING, RUNNING, COMPLETED, FAILED, CANCELLED

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Metrics
    total_checks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    passed_checks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_checks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    scan_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Relationships
    asset: Mapped["AuthorizedAsset"] = relationship("AuthorizedAsset")
    scope_grant: Mapped["ScopeGrant"] = relationship("ScopeGrant")
    observations: Mapped[list["TechnicalObservation"]] = relationship(
        "TechnicalObservation", back_populates="scan_job", cascade="all, delete-orphan"
    )
