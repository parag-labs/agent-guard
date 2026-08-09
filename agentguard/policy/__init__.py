"""AgentGuard policy engine: deny-by-default, least-privilege tool authorization.

Every agent tool call is evaluated against a policy before execution. Decisions
are ALLOW, DENY, or APPROVE (human-in-the-loop for high-risk actions).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVE = "approve"  # requires human approval


@dataclass
class ToolCall:
    tool: str
    args: dict[str, object] = field(default_factory=dict)


@dataclass
class ToolPolicy:
    tool: str
    allow: bool = False
    # Optional constraints
    path_allow: list[str] = field(default_factory=list)   # glob patterns
    path_deny: list[str] = field(default_factory=list)
    domain_allow: list[str] = field(default_factory=list)
    require_approval: bool = False


@dataclass
class Policy:
    """Deny-by-default: only explicitly allowed tools/constraints pass."""

    tools: dict[str, ToolPolicy] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, spec: dict) -> Policy:
        tools = {}
        for t in spec.get("tools", []):
            tp = ToolPolicy(
                tool=t["tool"],
                allow=t.get("allow", False),
                path_allow=t.get("path_allow", []),
                path_deny=t.get("path_deny", []),
                domain_allow=t.get("domain_allow", []),
                require_approval=t.get("require_approval", False),
            )
            tools[tp.tool] = tp
        return cls(tools=tools)

    def evaluate(self, call: ToolCall) -> tuple[Decision, str]:
        tp = self.tools.get(call.tool)
        if tp is None or not tp.allow:
            return Decision.DENY, f"tool '{call.tool}' not in allow-list (deny-by-default)"

        path = str(call.args.get("path", "")) if call.args.get("path") is not None else ""
        # Deny-by-default extends to constrained arguments: if a tool is restricted
        # to certain paths but the call provides none, we can't prove it's in bounds,
        # so we refuse rather than fall through to allow.
        if tp.path_allow and not path:
            return Decision.DENY, f"tool '{call.tool}' requires a path within its allowed set"
        if path:
            for pattern in tp.path_deny:
                if fnmatch.fnmatch(path, pattern):
                    return Decision.DENY, f"path '{path}' matches deny pattern '{pattern}'"
            if tp.path_allow and not any(fnmatch.fnmatch(path, p) for p in tp.path_allow):
                return Decision.DENY, f"path '{path}' not in allowed paths"

        domain = str(call.args.get("domain", "")) if call.args.get("domain") is not None else ""
        if tp.domain_allow and not domain:
            return Decision.DENY, f"tool '{call.tool}' requires a domain within its allowed set"
        if domain and tp.domain_allow and domain not in tp.domain_allow:
            return Decision.DENY, f"domain '{domain}' not in allow-list"

        if tp.require_approval:
            return Decision.APPROVE, f"tool '{call.tool}' requires human approval"

        return Decision.ALLOW, "ok"
