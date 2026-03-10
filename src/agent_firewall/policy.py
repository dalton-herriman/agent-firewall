from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from fnmatch import fnmatch

from agent_firewall.models.policy import PolicyCondition, PolicyRule, PolicyValidationResult
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
            return candidate not in value if isinstance(value, list) else False
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
        key=lambda rule: (rule.priority, 0 if rule.effect == "deny" else 1, rule.name),
    )
    if matching_rules:
        matched = matching_rules[0]
        return matched.effect == "allow", matched, f"matched policy {matched.name}"
    if default_mode == "allow":
        return True, None, "default allow"
    return False, None, "default deny"


def validate_policy_candidate(candidate: PolicyRule, existing_rules: Sequence[PolicyRule]) -> PolicyValidationResult:
    errors: list[str] = []
    for existing in existing_rules:
        if str(existing.id) == str(candidate.id):
            continue
        same_priority = existing.priority == candidate.priority
        same_operation = existing.operation == candidate.operation
        overlapping_subjects = not existing.subject.agent_ids or not candidate.subject.agent_ids or bool(
            set(existing.subject.agent_ids) & set(candidate.subject.agent_ids)
        )
        overlapping_resources = _resources_overlap(existing.resource.tool_names, candidate.resource.tool_names)
        same_conditions = existing.conditions == candidate.conditions
        conflicting_effect = existing.effect != candidate.effect
        if same_priority and same_operation and overlapping_subjects and overlapping_resources and same_conditions and conflicting_effect:
            errors.append(
                f"policy '{candidate.name}' conflicts with '{existing.name}' at priority {candidate.priority}"
            )
    return PolicyValidationResult(valid=not errors, errors=errors)


def _resources_overlap(left: list[str], right: list[str]) -> bool:
    if not left or not right:
        return True
    return any(fnmatch(a, b) or fnmatch(b, a) for a in left for b in right)
