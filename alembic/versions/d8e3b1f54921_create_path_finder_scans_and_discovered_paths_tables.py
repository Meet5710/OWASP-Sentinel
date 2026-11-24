"""create_path_finder_scans_and_discovered_paths_tables

Revision ID: d8e3b1f54921
Revises: bce15aa903ad
Create Date: 2026-11-20 12:50:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d8e3b1f54921"
down_revision: Union[str, Sequence[str], None] = "bce15aa903ad"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to add Path Finder scans and discovered_paths tables."""
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing_tables = insp.get_table_names()

    # 1. Create scans table if not already created
    if "scans" not in existing_tables:
        op.create_table(
            "scans",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("target_id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=True),
            sa.Column("mode", sa.String(length=50), server_default="QUICK", nullable=False),
            sa.Column("config_json", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(length=50), server_default="PENDING", nullable=False),
            sa.Column("progress_percent", sa.Float(), server_default="0.0", nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["target_id"], ["authorized_assets.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_scans_target_id"), "scans", ["target_id"], unique=False)
        op.create_index(op.f("ix_scans_user_id"), "scans", ["user_id"], unique=False)
        op.create_index(op.f("ix_scans_status"), "scans", ["status"], unique=False)
        op.create_index(op.f("ix_scans_created_at"), "scans", ["created_at"], unique=False)
    else:
        # Ensure existing indexes
        existing_indexes = [idx["name"] for idx in insp.get_indexes("scans")]
        if "ix_scans_target_id" not in existing_indexes:
            op.create_index(op.f("ix_scans_target_id"), "scans", ["target_id"], unique=False)
        if "ix_scans_user_id" not in existing_indexes:
            op.create_index(op.f("ix_scans_user_id"), "scans", ["user_id"], unique=False)
        if "ix_scans_status" not in existing_indexes:
            op.create_index(op.f("ix_scans_status"), "scans", ["status"], unique=False)
        if "ix_scans_created_at" not in existing_indexes:
            op.create_index(op.f("ix_scans_created_at"), "scans", ["created_at"], unique=False)

    # 2. Create discovered_paths table if not already created
    if "discovered_paths" not in existing_tables:
        op.create_table(
            "discovered_paths",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("scan_id", sa.String(length=36), nullable=False),
            sa.Column("path", sa.String(length=2048), nullable=False),
            sa.Column("full_url", sa.String(length=2048), nullable=False),
            sa.Column("status_code", sa.Integer(), nullable=False),
            sa.Column("content_length", sa.Integer(), nullable=True),
            sa.Column("content_type", sa.String(length=255), nullable=True),
            sa.Column("redirect_url", sa.String(length=2048), nullable=True),
            sa.Column("response_time_ms", sa.Float(), nullable=True),
            sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_discovered_paths_scan_id"), "discovered_paths", ["scan_id"], unique=False)
        op.create_index(op.f("ix_discovered_paths_status_code"), "discovered_paths", ["status_code"], unique=False)
        op.create_index(
            "ix_discovered_paths_scan_status", "discovered_paths", ["scan_id", "status_code"], unique=False
        )
        op.create_index(op.f("ix_discovered_paths_discovered_at"), "discovered_paths", ["discovered_at"], unique=False)
    else:
        existing_indexes = [idx["name"] for idx in insp.get_indexes("discovered_paths")]
        if "ix_discovered_paths_scan_id" not in existing_indexes:
            op.create_index(op.f("ix_discovered_paths_scan_id"), "discovered_paths", ["scan_id"], unique=False)
        if "ix_discovered_paths_status_code" not in existing_indexes:
            op.create_index(op.f("ix_discovered_paths_status_code"), "discovered_paths", ["status_code"], unique=False)
        if "ix_discovered_paths_scan_status" not in existing_indexes:
            op.create_index(
                "ix_discovered_paths_scan_status", "discovered_paths", ["scan_id", "status_code"], unique=False
            )
        if "ix_discovered_paths_discovered_at" not in existing_indexes:
            op.create_index(op.f("ix_discovered_paths_discovered_at"), "discovered_paths", ["discovered_at"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing_tables = insp.get_table_names()

    if "discovered_paths" in existing_tables:
        op.drop_table("discovered_paths")

    if "scans" in existing_tables:
        op.drop_table("scans")
