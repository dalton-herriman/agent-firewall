from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260310_0002"
down_revision = "20260310_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "policy_rules",
        sa.Column("resource_tool_names", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.execute("UPDATE policy_rules SET resource_tool_names = json_build_array(tool)")


def downgrade() -> None:
    op.drop_column("policy_rules", "resource_tool_names")
