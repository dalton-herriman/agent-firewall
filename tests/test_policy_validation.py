import pytest
from pydantic import ValidationError

from agent_firewall.models.policy import PolicyCondition


def test_not_in_conditions_require_list_values() -> None:
    with pytest.raises(ValidationError):
        PolicyCondition(field="tool_args.role", operator="not_in", value="admin")


def test_regex_conditions_require_string_patterns() -> None:
    with pytest.raises(ValidationError):
        PolicyCondition(field="tool_args.city", operator="regex", value=123)
