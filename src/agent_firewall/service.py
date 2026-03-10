from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from agent_firewall.cache import RateLimiter
from agent_firewall.config import Settings
from agent_firewall.executor import ToolExecutor
from agent_firewall.models.audit import AuditLogEntry
from agent_firewall.models.config import AdapterConfig, ToolArgumentSpec
from agent_firewall.models.tooling import ToolExecutionResult, ToolInvocationDecision, ToolInvocationRequest
from agent_firewall.observability import get_observability
from agent_firewall.policy import evaluate_policy
from agent_firewall.repositories.base import AdapterRepository, AuditLogRepository, PolicyRepository


class FirewallService:
    def __init__(
        self,
        settings: Settings,
        policy_repository: PolicyRepository,
        audit_log_repository: AuditLogRepository,
        adapter_repository: AdapterRepository,
        rate_limiter: RateLimiter,
        tool_executor: ToolExecutor | None = None,
    ) -> None:
        self._settings = settings
        self._policy_repository = policy_repository
        self._audit_log_repository = audit_log_repository
        self._adapter_repository = adapter_repository
        self._rate_limiter = rate_limiter
        self._tool_executor = tool_executor
        self._observability = get_observability()

    async def evaluate(self, request: ToolInvocationRequest) -> ToolInvocationDecision:
        with self._observability.tracer.start_as_current_span("agent_firewall.evaluate") as span:
            span.set_attribute("agent_firewall.tenant_id", request.tenant_id)
            span.set_attribute("agent_firewall.tool_name", request.tool_name)
            adapter = await self._adapter_repository.get_by_tool_name(request.tenant_id, request.tool_name)
            if adapter is None:
                decision = ToolInvocationDecision(allowed=False, reason="unknown tool")
                await self._audit(request, decision)
                self._observability.record_evaluation(
                    tenant_id=request.tenant_id,
                    tool_name=request.tool_name,
                    allowed=False,
                    reason=decision.reason,
                )
                return decision

            try:
                ToolInvocationRequest.model_validate(request)
            except ValidationError as exc:
                decision = ToolInvocationDecision(allowed=False, reason=f"invalid request: {exc.errors()[0]['msg']}")
                await self._audit(request, decision)
                self._observability.record_evaluation(
                    tenant_id=request.tenant_id,
                    tool_name=request.tool_name,
                    allowed=False,
                    reason=decision.reason,
                )
                return decision

            tool_arg_error = self._validate_tool_args(adapter, request.tool_args)
            if tool_arg_error:
                decision = ToolInvocationDecision(allowed=False, reason=tool_arg_error, action=request.action)
                await self._audit(request, decision)
                self._observability.record_evaluation(
                    tenant_id=request.tenant_id,
                    tool_name=request.tool_name,
                    allowed=False,
                    reason=decision.reason,
                )
                return decision

            allowed_by_rate_limit, remaining = await self._rate_limiter.check(
                key=f"ratelimit:{request.tenant_id}:{request.agent_id}:{request.tool_name}",
                limit=self._settings.rate_limit_max_requests,
                window_seconds=self._settings.rate_limit_window_seconds,
            )
            if not allowed_by_rate_limit:
                decision = ToolInvocationDecision(allowed=False, reason="rate limit exceeded", rate_limit_remaining=remaining)
                await self._audit(request, decision)
                self._observability.record_rate_limit(tenant_id=request.tenant_id, tool_name=request.tool_name)
                self._observability.record_evaluation(
                    tenant_id=request.tenant_id,
                    tool_name=request.tool_name,
                    allowed=False,
                    reason=decision.reason,
                )
                return decision

            rules = await self._policy_repository.list_rules_for_agent(request.tenant_id, request.agent_id)
            allowed, matched_rule, reason = evaluate_policy(request, rules, self._settings.default_policy_mode)
            decision = ToolInvocationDecision(
                allowed=allowed,
                reason=reason,
                action=request.action,
                matched_policy_id=str(matched_rule.id) if matched_rule else None,
                rate_limit_remaining=remaining,
            )
            await self._audit(request, decision)
            self._observability.record_evaluation(
                tenant_id=request.tenant_id,
                tool_name=request.tool_name,
                allowed=decision.allowed,
                reason=decision.reason,
            )
            return decision

    async def execute(self, request: ToolInvocationRequest) -> ToolExecutionResult:
        with self._observability.tracer.start_as_current_span("agent_firewall.execute") as span:
            span.set_attribute("agent_firewall.tenant_id", request.tenant_id)
            span.set_attribute("agent_firewall.tool_name", request.tool_name)
            adapter = await self._adapter_repository.get_by_tool_name(request.tenant_id, request.tool_name)
            if adapter is None:
                raise LookupError("unknown tool")
            decision = await self.evaluate(request)
            if not decision.allowed:
                raise PermissionError(decision.reason)
            if not self._settings.server_broker_enabled:
                raise RuntimeError("tool broker execution disabled")
            if self._tool_executor is None:
                raise RuntimeError("tool executor is not configured")
            result = await self._tool_executor.execute(adapter=adapter, request=request, decision=decision)
            self._observability.record_execution(
                tenant_id=request.tenant_id,
                tool_name=request.tool_name,
                status=result.status,
            )
            return result

    def _validate_tool_args(self, adapter: AdapterConfig, tool_args: dict[str, Any]) -> str | None:
        schema = {spec.name: spec for spec in adapter.input_schema}
        for spec in schema.values():
            if spec.required and spec.name not in tool_args:
                return f"missing required tool arg: {spec.name}"
        for name, value in tool_args.items():
            spec = schema.get(name)
            if spec is None:
                continue
            if not self._matches_type(spec, value):
                return f"invalid tool arg type for {name}"
            if spec.allowed_values and value not in spec.allowed_values:
                return f"invalid tool arg value for {name}"
        return None

    def _matches_type(self, spec: ToolArgumentSpec, value: Any) -> bool:
        match spec.value_type:
            case "string":
                return isinstance(value, str)
            case "integer":
                return isinstance(value, int) and not isinstance(value, bool)
            case "number":
                return isinstance(value, (int, float)) and not isinstance(value, bool)
            case "boolean":
                return isinstance(value, bool)
            case "object":
                return isinstance(value, dict)
            case "array":
                return isinstance(value, list)
        return False

    async def _audit(self, request: ToolInvocationRequest, decision: ToolInvocationDecision) -> None:
        await self._audit_log_repository.record(
            AuditLogEntry(
                tenant_id=request.tenant_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                decision="allow" if decision.allowed else "deny",
                reason=decision.reason,
                matched_policy_id=decision.matched_policy_id,
                request_payload=request.model_dump(mode="json"),
            )
        )
