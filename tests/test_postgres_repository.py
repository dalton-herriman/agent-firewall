from __future__ import annotations

import pytest

from agent_firewall.models.policy import PolicyCondition, PolicyRule
from agent_firewall.repositories.postgres import PolicyRuleRow, PostgresPolicyRepository


class _ScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


class _Session:
    def __init__(self, rows):
        self._rows = rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def scalars(self, statement):
        return _ScalarResult(self._rows)


@pytest.mark.asyncio
async def test_postgres_policy_repository_preserves_resource_lists_and_wildcard_subjects() -> None:
    rows = [
        PolicyRuleRow(
            id="91b5b8cf-6f5d-450f-9cac-89d2a7fe4b61",
            agent_id="*",
            tenant_id="tenant-a",
            name="wildcard policy",
            description=None,
            effect="allow",
            tool="filesystem.read",
            resource_tool_names=["filesystem.read", "filesystem.write"],
            subject_agent_ids=[],
            invocation_action="invoke",
            conditions=[{"field": "tool_args.path", "operator": "eq", "value": "/tmp/file.txt"}],
            priority=1,
            version=1,
            status="published",
            enabled=True,
        )
    ]
    repository = PostgresPolicyRepository(lambda: _Session(rows))

    policies = await repository.list_rules_for_agent("tenant-a", "agent-123")

    assert len(policies) == 1
    assert policies[0].subject.agent_ids == []
    assert policies[0].resource.tool_names == ["filesystem.read", "filesystem.write"]
    assert policies[0].conditions == [PolicyCondition(field="tool_args.path", operator="eq", value="/tmp/file.txt")]
    assert isinstance(policies[0], PolicyRule)
