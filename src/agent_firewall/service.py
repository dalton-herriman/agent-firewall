from __future__ import annotations

from pydantic import ValidationError

from agent_firewall.cache import RateLimiter
from agent_firewall.config import Settings
from agent_firewall.models.audit import AuditLogEntry
from agent_firewall.models.tooling import ToolInvocationDecision, ToolInvocationRequest
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
    ) -> None:
        self._settings = settings
        self._policy_repository = policy_repository
        self._audit_log_repository = audit_log_repository
        self._adapter_repository = adapter_repository
        self._rate_limiter = rate_limiter

    async def evaluate(self, request: ToolInvocationRequest) -> ToolInvocationDecision:
        adapter = await self._adapter_repository.get_by_tool_name(request.tool_name)
        if adapter is None:
            decision = ToolInvocationDecision(allowed=False, reason="unknown tool")
            await self._audit(request, decision)
            return decision

        try:
            ToolInvocationRequest.model_validate(request)
        except ValidationError as exc:
            decision = ToolInvocationDecision(allowed=False, reason=f"invalid request: {exc.errors()[0]['msg']}")
            await self._audit(request, decision)
            return decision

        allowed_by_rate_limit, remaining = await self._rate_limiter.check(
            key=f"ratelimit:{request.agent_id}:{request.tool_name}",
            limit=self._settings.rate_limit_max_requests,
            window_seconds=self._settings.rate_limit_window_seconds,
        )
        if not allowed_by_rate_limit:
            decision = ToolInvocationDecision(allowed=False, reason="rate limit exceeded", rate_limit_remaining=remaining)
            await self._audit(request, decision)
            return decision

        rules = await self._policy_repository.list_rules_for_agent(request.agent_id)
        allowed, matched_rule, reason = evaluate_policy(request, rules, self._settings.default_policy_mode)
        decision = ToolInvocationDecision(
            allowed=allowed,
            reason=reason,
            matched_policy_id=str(matched_rule.id) if matched_rule else None,
            rate_limit_remaining=remaining,
        )
        await self._audit(request, decision)
        return decision

    async def _audit(self, request: ToolInvocationRequest, decision: ToolInvocationDecision) -> None:
        await self._audit_log_repository.record(
            AuditLogEntry(
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                decision="allow" if decision.allowed else "deny",
                reason=decision.reason,
                request_payload=request.model_dump(mode="json"),
            )
        )

