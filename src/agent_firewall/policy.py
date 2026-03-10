from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from agent_firewall.models.policy import PolicyCondition, PolicyRule
from agent_firewall.models.tooling import ToolInvocationRequest


def _value_for_field(request: ToolInvocationRequest, field: str) -> Any:
    if field.startswith("tool_args."):
        return request.tool_args.get(field.removeprefix("tool_args."))
    if field.startswith("metadata."):
        return request.metadata.get(field.removeprefix("metadata."))
    return getattr(request, field, None)


def _matches_condition(request: ToolInvocationRequest, condition: PolicyCondition) -> bool:
    candidate = _value_for_field(request, condition.field)
    value = condition.value
    match condition.operator:
        case "eq":
            return candidate == value
        case "neq":
            return candidate != value
        case "in":
            return candidate in value if isinstance(value, list) else False
        case "not_in":
            return candidate not in value if isinstance(value, list) else True
        case "contains":
            return value in candidate if isinstance(candidate, (list, str)) else False
        case "regex":
            return isinstance(candidate, str) and re.search(str(value), candidate) is not None
    return False


def evaluate_policy(request: ToolInvocationRequest, rules: Sequence[PolicyRule], default_mode: str) -> tuple[bool, PolicyRule | None, str]:
    matching_rules = sorted(
        [
            rule
            for rule in rules
            if rule.operation == request.action
            and rule.subject.matches(request.agent_id)
            and rule.resource.matches(request.tool_name)
            and all(_matches_condition(request, c) for c in rule.conditions)
        ],
        key=lambda rule: rule.priority,
    )
    if matching_rules:
        matched = matching_rules[0]
        return matched.effect == "allow", matched, f"matched policy {matched.name}"
    if default_mode == "allow":
        return True, None, "default allow"
    return False, None, "default deny"
