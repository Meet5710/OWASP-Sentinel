"""OWASP Sentinel - OWASP Historical Taxonomy ORM Models."""

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, generate_uuid


class OWASPEdition(Base, TimestampMixin):
    """Represents an official publication edition of the OWASP Top 10."""

    __tablename__ = "owasp_editions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    edition_identifier: Mapped[str] = mapped_column(
        String(20), unique=True, index=True, nullable=False
    )  # e.g. "2021", "2017"
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    publication_year: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    publication_date: Mapped[str | None] = mapped_column(String(50), nullable=True)
    source_url: Mapped[str] = mapped_column(String(500), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    retrieval_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    is_latest: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    edition_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Relationships
    categories: Mapped[list["OWASPCategory"]] = relationship(
        "OWASPCategory", back_populates="edition", cascade="all, delete-orphan", order_by="OWASPCategory.display_order"
    )


class OWASPCategory(Base, TimestampMixin):
    """An official category definition within an OWASP Top 10 edition."""

    __tablename__ = "owasp_categories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    edition_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("owasp_editions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    category_code: Mapped[str] = mapped_column(String(50), index=True, nullable=False)  # e.g. "A01:2021", "A1:2017"
    category_title: Mapped[str] = mapped_column(String(255), nullable=False)
    category_description: Mapped[str] = mapped_column(Text, nullable=False)
    cwe_examples: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    source_url: Mapped[str] = mapped_column(String(500), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    display_order: Mapped[int] = mapped_column(Integer, nullable=False)  # 1 to 10

    # Relationships
    edition: Mapped["OWASPEdition"] = relationship("OWASPEdition", back_populates="categories")
