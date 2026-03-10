from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260310_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policy_rules",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("agent_id", sa.String(length=200), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("action", sa.String(length=10), nullable=False),
        sa.Column("tool", sa.String(length=200), nullable=False),
        sa.Column("conditions", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policy_rules_agent_id", "policy_rules", ["agent_id"])
    op.create_index("ix_policy_rules_tool", "policy_rules", ["tool"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("agent_id", sa.String(length=200), nullable=False),
        sa.Column("tool_name", sa.String(length=200), nullable=False),
        sa.Column("decision", sa.String(length=10), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("request_payload", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_agent_id", "audit_logs", ["agent_id"])
    op.create_index("ix_audit_logs_tool_name", "audit_logs", ["tool_name"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    op.create_table(
        "adapter_configs",
        sa.Column("tool_name", sa.String(length=200), nullable=False),
        sa.Column("target_uri", sa.Text(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("schema", sa.JSON(), nullable=False, server_default="[]"),
        sa.PrimaryKeyConstraint("tool_name"),
    )

    op.create_table(
        "runtime_configs",
        sa.Column("key", sa.String(length=200), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False, server_default="{}"),
        sa.PrimaryKeyConstraint("key"),
    )


def downgrade() -> None:
    op.drop_table("runtime_configs")
    op.drop_table("adapter_configs")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_tool_name", table_name="audit_logs")
    op.drop_index("ix_audit_logs_agent_id", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_policy_rules_tool", table_name="policy_rules")
    op.drop_index("ix_policy_rules_agent_id", table_name="policy_rules")
    op.drop_table("policy_rules")

