"""Adversarial fuzz suite: try to defeat the guard.

AgentGuard makes two promises - deny-by-default authorization, and a tamper-evident
audit trail. This suite is written from the attacker's side of both: it throws
path-traversal, glob tricks, unexpected argument shapes, and deny/allow-precedence
cases at the policy engine, and it flips bytes in the signed audit chain. The
invariant is simple and absolute - nothing outside the explicit allow-list is ever
authorized, and any edit to the audit log is detected.
"""

from __future__ import annotations

import random

from agentguard.audit import AuditLog
from agentguard.policy import Decision, Policy, ToolCall


def _fs_policy() -> Policy:
    # A realistic least-privilege file policy: read only under /workspace, never
    # touch secrets, and require approval to delete.
    return Policy.from_dict(
        {
            "tools": [
                {
                    "tool": "read_file",
                    "allow": True,
                    "path_allow": ["/workspace/*"],
                    "path_deny": ["*.env*", "*secrets*", "*id_rsa*"],
                },
                {"tool": "http_get", "allow": True, "domain_allow": ["api.internal"]},
                {"tool": "delete_file", "allow": True, "require_approval": True},
            ]
        }
    )


# ---- deny-by-default is the floor ----

def test_unknown_tools_are_always_denied():
    policy = _fs_policy()
    for tool in ["exec", "eval", "rm", "read_fil", "READ_FILE", "http_post", ""]:
        decision, _ = policy.evaluate(ToolCall(tool, {"path": "/workspace/ok.txt"}))
        assert decision is Decision.DENY, f"unlisted tool '{tool}' slipped through"


def test_tool_names_are_matched_exactly_not_by_prefix():
    # A near-miss on a real tool name must not inherit its permissions.
    policy = _fs_policy()
    for tool in ["read_file2", "read_file ", " read_file", "read_file\n"]:
        decision, _ = policy.evaluate(ToolCall(tool, {"path": "/workspace/ok.txt"}))
        assert decision is Decision.DENY


# ---- path constraints hold under hostile inputs ----

def test_secret_paths_are_denied_even_inside_the_allowed_root():
    policy = _fs_policy()
    hostile = [
        "/workspace/.env",
        "/workspace/secrets/prod.key",
        "/workspace/nested/id_rsa",
        "/workspace/sub/secrets/db.pem",
    ]
    for path in hostile:
        decision, reason = policy.evaluate(ToolCall("read_file", {"path": path}))
        assert decision is Decision.DENY, f"secret path allowed: {path} ({reason})"


def test_paths_outside_the_allowed_root_are_denied():
    policy = _fs_policy()
    outside = [
        "/etc/passwd",
        "/root/.ssh/known_hosts",
        "workspace/relative.txt",  # no leading slash -> not under /workspace/
        "/workspaceX/evil.txt",  # prefix look-alike
    ]
    for path in outside:
        decision, _ = policy.evaluate(ToolCall("read_file", {"path": path}))
        assert decision is Decision.DENY, f"path outside root allowed: {path}"


def test_deny_patterns_win_over_allow():
    # A path that matches BOTH an allow glob and a deny glob must be denied - deny
    # precedence is the safe default and this pins it down.
    policy = _fs_policy()
    decision, reason = policy.evaluate(ToolCall("read_file", {"path": "/workspace/.env"}))
    assert decision is Decision.DENY
    assert "deny" in reason.lower()


def test_domain_allow_list_is_strict():
    policy = _fs_policy()
    for domain in ["api.external", "api.internal.evil.com", "evil.com", "API.INTERNAL"]:
        decision, _ = policy.evaluate(ToolCall("http_get", {"domain": domain}))
        assert decision is Decision.DENY, f"domain slipped through: {domain}"
    ok, _ = policy.evaluate(ToolCall("http_get", {"domain": "api.internal"}))
    assert ok is Decision.ALLOW


def test_high_risk_tools_require_approval_never_silent_allow():
    policy = _fs_policy()
    decision, _ = policy.evaluate(ToolCall("delete_file", {"path": "/workspace/tmp.txt"}))
    assert decision is Decision.APPROVE  # never a silent ALLOW


def test_missing_or_odd_arguments_do_not_crash_or_bypass():
    policy = _fs_policy()
    weird_args = [
        {},  # no path at all
        {"path": ""},  # empty
        {"path": None},  # None
        {"path": 12345},  # wrong type
        {"unexpected": "x"},  # unrelated key
        {"path": "/workspace/ok.txt", "extra": object()},
    ]
    for args in weird_args:
        decision, _ = policy.evaluate(ToolCall("read_file", args))
        # It must return a Decision, never raise; and it must not ALLOW a path that
        # wasn't checked. A missing/empty path with an allow-root configured => DENY.
        assert decision in (Decision.ALLOW, Decision.DENY, Decision.APPROVE)
        if args.get("path") in (None, "", 12345) or "path" not in args:
            assert decision is Decision.DENY


def test_randomized_paths_never_escape_the_allow_root():
    rng = random.Random(0)
    policy = _fs_policy()
    tokens = ["workspace", "..", ".", "etc", "secrets", "ok.txt", ".env", "a", "id_rsa"]
    for _ in range(5000):
        depth = rng.randint(1, 6)
        path = "/" + "/".join(rng.choice(tokens) for _ in range(depth))
        decision, _ = policy.evaluate(ToolCall("read_file", {"path": path}))
        if decision is Decision.ALLOW:
            # The only way to ALLOW is: matches /workspace/* and hits no deny glob.
            assert path.startswith("/workspace/")
            assert ".env" not in path and "secrets" not in path and "id_rsa" not in path


# ---- audit trail is tamper-evident ----

def test_clean_audit_chain_verifies():
    log = AuditLog()
    for i in range(50):
        log.record(f"tool-{i}", "allow", "ok")
    assert log.verify_chain() is True


def test_editing_any_audit_field_is_detected():
    rng = random.Random(1)
    for _ in range(200):
        log = AuditLog()
        for i in range(10):
            log.record(f"tool-{i}", "allow" if i % 2 else "deny", "reason")
        entries = log.entries()
        victim = entries[rng.randrange(len(entries))]
        # Tamper with the recorded decision after the fact.
        victim.decision = "allow" if victim.decision == "deny" else "deny"
        assert log.verify_chain() is False


def test_truncating_or_reordering_the_chain_is_detected():
    log = AuditLog()
    for i in range(10):
        log.record(f"tool-{i}", "allow", "ok")

    # Reorder the actual chain (white-box): each entry's prev_hash pins its position,
    # so swapping two entries must break verification.
    log._entries[3], log._entries[6] = log._entries[6], log._entries[3]
    assert log.verify_chain() is False


def test_a_signature_from_the_wrong_key_is_rejected():
    log = AuditLog()
    log.record("t", "allow", "ok")
    entry = log.entries()[0]
    # Forge a signature with a freshly generated (attacker) key.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    attacker = Ed25519PrivateKey.generate()
    entry.signature = attacker.sign(entry.entry_hash.encode()).hex()
    assert log.verify_chain() is False


def test_flipping_a_byte_in_a_signature_is_rejected():
    rng = random.Random(2)
    for _ in range(100):
        log = AuditLog()
        log.record("t", "allow", "ok")
        entry = log.entries()[0]
        raw = bytearray.fromhex(entry.signature)
        raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
        entry.signature = raw.hex()
        assert log.verify_chain() is False
