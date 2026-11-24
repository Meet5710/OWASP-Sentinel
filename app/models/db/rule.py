"""OWASP Sentinel - Detection Rule ORM Model."""

from sqlalchemy import JSON, Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, generate_uuid


class DetectionRuleEntity(Base, TimestampMixin):
    """Database representation of registered security detection rules."""

    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    rule_id: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    severity_default: Mapped[str] = mapped_column(String(50), default="MEDIUM", nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    rule_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
