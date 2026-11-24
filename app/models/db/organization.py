"""OWASP Sentinel - Organization ORM Model."""

from typing import TYPE_CHECKING

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, generate_uuid

if TYPE_CHECKING:
    from app.models.db.asset import AuthorizedAsset
    from app.models.db.scope import ScopeGrant
    from app.models.db.user import User


class Organization(Base, TimestampMixin):
    """Represents a tenant or organization managing target assessments."""

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(150), unique=True, index=True, nullable=False)
    contact_email: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Relationships
    users: Mapped[list["User"]] = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    scope_grants: Mapped[list["ScopeGrant"]] = relationship(
        "ScopeGrant", back_populates="organization", cascade="all, delete-orphan"
    )
    assets: Mapped[list["AuthorizedAsset"]] = relationship(
        "AuthorizedAsset", back_populates="organization", cascade="all, delete-orphan"
    )
