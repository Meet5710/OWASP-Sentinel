"""OWASP Sentinel - Ingestion Run ORM Model."""

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, generate_uuid


class IngestionRun(Base):
    """Audit log tracking executions of the OWASP taxonomy ingestion service."""

    __tablename__ = "ingestion_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    source_url: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # SUCCESS, FAILED, NO_CHANGE, CHANGES_DETECTED
    editions_processed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    categories_updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    categories_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    requires_admin_review: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    log_details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
