"""OWASP Sentinel - Path Finder (Authorized Endpoint Discovery) ORM Models.

Defines persistence for scans and discovered paths/endpoints under authorized target assets.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, generate_uuid, utc_now

if TYPE_CHECKING:
    from app.models.db.asset import AuthorizedAsset
    from app.models.db.user import User


class PathFinderScan(Base, TimestampMixin):
    """Tracks an authorized endpoint discovery / path finding scan execution against an authorized target."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("authorized_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Execution Mode: QUICK, AGGRESSIVE, PASSIVE, EXHAUSTIVE, RECURSIVE
    mode: Mapped[str] = mapped_column(String(50), default="QUICK", nullable=False)

    # Dynamic Scan Configuration (wordlist, extensions, headers, rate limits, status filters)
    config_json: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Status: PENDING, RUNNING, PAUSED, COMPLETED, CANCELLED, FAILED
    status: Mapped[str] = mapped_column(
        String(50), default="PENDING", nullable=False, index=True
    )
    progress_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    target: Mapped["AuthorizedAsset"] = relationship("AuthorizedAsset", backref="path_finder_scans")
    user: Mapped[Optional["User"]] = relationship("User")
    discovered_paths: Mapped[List["DiscoveredPath"]] = relationship(
        "DiscoveredPath",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="DiscoveredPath.discovered_at.desc()",
    )


# Alias Scan to PathFinderScan for direct compatibility with naming preference
Scan = PathFinderScan


class DiscoveredPath(Base):
    """Represents a discovered HTTP endpoint or URI path under an authorized target."""

    __tablename__ = "discovered_paths"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    full_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    content_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    redirect_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    response_time_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )

    # Composite Index for high-performance filtering by scan and HTTP status code
    __table_args__ = (
        Index("ix_discovered_paths_scan_status", "scan_id", "status_code"),
    )

    # Relationships
    scan: Mapped["PathFinderScan"] = relationship("PathFinderScan", back_populates="discovered_paths")

