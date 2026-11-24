"""OWASP Sentinel - Finding History and Patch Verification ORM Models."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, generate_uuid

if TYPE_CHECKING:
    from app.models.db.asset import AuthorizedAsset
    from app.models.db.finding import Finding
    from app.models.db.scan import ScanJob


class PatchVerification(Base):
    """Tracks automated diffing of findings across consecutive scans to verify remediation."""

    __tablename__ = "patch_verifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("authorized_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    verification_status: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # STILL_VULNERABLE, REMEDIATED, REGRESSED
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Relationships
    finding: Mapped["Finding"] = relationship("Finding")
    scan_job: Mapped["ScanJob"] = relationship("ScanJob")
    asset: Mapped["AuthorizedAsset"] = relationship("AuthorizedAsset")


class FindingHistoryRecord(Base):
    """Snapshot of security posture metrics for a target asset at a point in time."""

    __tablename__ = "finding_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("authorized_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )

    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    info_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    new_findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    resolved_findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    recurrent_findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    asset: Mapped["AuthorizedAsset"] = relationship("AuthorizedAsset")
    scan_job: Mapped["ScanJob"] = relationship("ScanJob")
