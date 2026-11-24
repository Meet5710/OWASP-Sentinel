"""OWASP Sentinel - Finding and Observation ORM Models."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from app.db.base import Base, TimestampMixin, generate_uuid

if TYPE_CHECKING:
    from app.models.db.asset import AuthorizedAsset
    from app.models.db.scan import ScanJob


class TechnicalObservation(Base, TimestampMixin):
    """Raw, immutable technical observation produced by an automated scanner rule."""

    __tablename__ = "technical_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("authorized_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    rule_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    technical_issue_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)

    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: Mapped[str] = mapped_column(String(50), default="CERTAIN", nullable=False)  # CERTAIN, FIRM, TENTATIVE

    evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    remediation: Mapped[str] = mapped_column(String(2000), nullable=False)
    references: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    # Relationships
    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="observations")
    asset: Mapped["AuthorizedAsset"] = relationship("AuthorizedAsset")

    @property
    def description(self) -> str:
        return self.title


class Finding(Base, TimestampMixin):
    """A managed security finding with status history and multi-category OWASP linkages."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("authorized_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    observation_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("technical_observations.id", ondelete="SET NULL"), nullable=True, index=True
    )

    detection_rule_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    technical_issue_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)

    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: Mapped[str] = mapped_column(String(50), default="CERTAIN", nullable=False)  # CERTAIN, FIRM, TENTATIVE
    validation_status: Mapped[str] = mapped_column(
        String(50), default="CONFIRMED", nullable=False, index=True
    )  # POTENTIAL, CONFIRMED, FALSE_POSITIVE, MITIGATED

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    remediation_recommendations: Mapped[str] = mapped_column(Text, nullable=False)
    references: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    status_history: Mapped[list[dict]] = mapped_column(JSON, default=list, nullable=False)

    # Relationships
    asset: Mapped["AuthorizedAsset"] = relationship("AuthorizedAsset")
    scan_job: Mapped["ScanJob"] = relationship("ScanJob")
    category_mappings: Mapped[list["FindingCategoryMapping"]] = relationship(
        "FindingCategoryMapping", back_populates="finding", cascade="all, delete-orphan"
    )


class FindingCategoryMapping(Base):
    """Explicit mapping linking a technical finding to an OWASP Top 10 category with documented rationale."""

    __tablename__ = "finding_category_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    owasp_edition: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    owasp_category_code: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    owasp_category_title: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    finding: Mapped["Finding"] = relationship("Finding", back_populates="category_mappings")

    # Synonyms for edition_identifier, category_identifier, assigned_at
    edition_identifier = synonym("owasp_edition")
    category_identifier = synonym("owasp_category_code")
    assigned_at = synonym("created_at")
