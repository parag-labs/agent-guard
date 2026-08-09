"""AgentGuard tests: least-privilege enforcement, approval gating, signed audit."""

import pytest

from agentguard.policy import Decision, Policy, ToolCall
from agentguard.runtime import AgentGuard, ToolBlockedError

POLICY_SPEC = {
    "tools": [
        {"tool": "read_file", "allow": True, "path_allow": ["/data/*"], "path_deny": ["/data/secrets/*", "*.env"]},
        {"tool": "http_get", "allow": True, "domain_allow": ["api.company.com"]},
        {"tool": "run_shell", "allow": True, "require_approval": True},
    ]
}


def _guard(approve=False):
    return AgentGuard(Policy.from_dict(POLICY_SPEC), approval_callback=lambda c, r: approve)


def test_unlisted_tool_denied_by_default():
    g = _guard()
    with pytest.raises(ToolBlockedError):
        g.guard(ToolCall("write_file", {"path": "/data/x"}), lambda c: "wrote")


def test_allowed_path_executes():
    g = _guard()
    out = g.guard(ToolCall("read_file", {"path": "/data/report.txt"}), lambda c: "content")
    assert out == "content"


def test_denied_path_blocks_secret_exfil():
    g = _guard()
    with pytest.raises(ToolBlockedError):
        g.guard(ToolCall("read_file", {"path": "/data/secrets/key.env"}), lambda c: "leak")


def test_domain_allow_list():
    g = _guard()
    with pytest.raises(ToolBlockedError):
        g.guard(ToolCall("http_get", {"domain": "evil.com"}), lambda c: "resp")


def test_high_risk_requires_approval():
    denied = _guard(approve=False)
    with pytest.raises(ToolBlockedError):
        denied.guard(ToolCall("run_shell", {"cmd": "rm -rf /"}), lambda c: "ran")

    approved = _guard(approve=True)
    assert approved.guard(ToolCall("run_shell", {"cmd": "ls"}), lambda c: "listed") == "listed"


def test_audit_log_is_signed_and_chained():
    g = _guard()
    try:
        g.guard(ToolCall("write_file", {"path": "/x"}), lambda c: "x")
    except ToolBlockedError:
        pass
    g.guard(ToolCall("read_file", {"path": "/data/a"}), lambda c: "a")
    assert len(g.audit.entries()) == 2
    assert g.audit.verify_chain() is True


def test_policy_evaluate_decisions():
    p = Policy.from_dict(POLICY_SPEC)
    assert p.evaluate(ToolCall("read_file", {"path": "/data/a"}))[0] is Decision.ALLOW
    assert p.evaluate(ToolCall("run_shell", {}))[0] is Decision.APPROVE
    assert p.evaluate(ToolCall("nope", {}))[0] is Decision.DENY
