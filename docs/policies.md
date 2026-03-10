# Policy Semantics

## Rule shape

Each policy contains:

- `action`: `allow` or `deny`
- `operation`: currently `invoke`
- `subject.agent_ids`: scoped agent identities
- `resource.tool_names`: shell-style tool patterns
- `conditions`: predicates over tool args and metadata
- `priority`: lower values win
- `version`: monotonically increasing rule revision

## Precedence

1. Lower `priority` wins
2. At equal priority, `deny` beats `allow`
3. If nothing matches, the configured default mode is used

## Ambiguity checks

The management layer rejects new rules that conflict with an existing rule at the same priority, operation, subject overlap, resource overlap, and condition set but with the opposite effect.
