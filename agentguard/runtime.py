"""AgentGuard runtime: intercept tool calls, enforce policy, audit everything.

Wrap any tool-executing function; AgentGuard authorizes it against the policy,
routes high-risk actions through an approval callback, and writes a signed audit
entry for every decision.
"""

from __future__ import annotations

from collections.abc import Callable

from agentguard.audit import AuditLog
from agentguard.policy import Decision, Policy, ToolCall


class ToolBlockedError(Exception):
    pass


class AgentGuard:
    def __init__(
        self,
        policy: Policy,
        approval_callback: Callable[[ToolCall, str], bool] | None = None,
        audit: AuditLog | None = None,
    ):
        self.policy = policy
        self.audit = audit or AuditLog()
        # Default approval callback denies (safe default; wire a real UI/CLI in prod).
        self._approve = approval_callback or (lambda call, reason: False)

    def guard(self, call: ToolCall, execute: Callable[[ToolCall], object]) -> object:
        decision, reason = self.policy.evaluate(call)

        if decision is Decision.APPROVE:
            approved = self._approve(call, reason)
            decision = Decision.ALLOW if approved else Decision.DENY
            reason = f"human {'approved' if approved else 'denied'}: {reason}"

        self.audit.record(call.tool, decision.value, reason)

        if decision is Decision.ALLOW:
            return execute(call)
        raise ToolBlockedError(f"blocked '{call.tool}': {reason}")
