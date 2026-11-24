"""OWASP Sentinel - Scheduled Scan ORM Model."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, generate_uuid

if TYPE_CHECKING:
    from app.models.db.asset import AuthorizedAsset
    from app.models.db.scope import ScopeGrant


class ScheduledScan(Base):
    """Recurring assessment schedule definition for an authorized target asset."""

    __tablename__ = "scheduled_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("authorized_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scope_grant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scope_grants.id", ondelete="CASCADE"), nullable=False, index=True
    )

    frequency: Mapped[str] = mapped_column(String(50), nullable=False)  # DAILY, WEEKLY, MONTHLY, CRON
    cron_expression: Mapped[str | None] = mapped_column(String(100), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    schedule_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Relationships
    asset: Mapped["AuthorizedAsset"] = relationship("AuthorizedAsset")
    scope_grant: Mapped["ScopeGrant"] = relationship("ScopeGrant")
