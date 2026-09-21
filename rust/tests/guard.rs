//! AgentGuard tests: least-privilege enforcement, approval gating, signed audit.

use agent_guard::{AgentGuard, ArgValue, Decision, Policy, ToolCall, ToolPolicy};
use std::collections::HashMap;

fn guard_policy() -> Policy {
    Policy::new(vec![
        ToolPolicy {
            tool: "read_file".into(),
            allow: true,
            path_allow: vec!["/data/*".into()],
            path_deny: vec!["/data/secrets/*".into(), "*.env".into()],
            ..Default::default()
        },
        ToolPolicy {
            tool: "http_get".into(),
            allow: true,
            domain_allow: vec!["api.company.com".into()],
            ..Default::default()
        },
        ToolPolicy {
            tool: "run_shell".into(),
            allow: true,
            require_approval: true,
            ..Default::default()
        },
    ])
}

fn guard(approve: bool) -> AgentGuard {
    AgentGuard::new(guard_policy()).with_approval(move |_, _| approve)
}

fn call(tool: &str, key: &str, val: ArgValue) -> ToolCall {
    let mut args = HashMap::new();
    args.insert(key.to_string(), val);
    ToolCall::with_args(tool, args)
}

#[test]
fn unlisted_tool_denied_by_default() {
    let mut g = guard(false);
    let r = g.guard(&call("write_file", "path", "/data/x".into()), |_| "wrote");
    assert!(r.is_err());
}

#[test]
fn allowed_path_executes() {
    let mut g = guard(false);
    let out = g
        .guard(
            &call("read_file", "path", "/data/report.txt".into()),
            |_| "content",
        )
        .unwrap();
    assert_eq!(out, "content");
}

#[test]
fn denied_path_blocks_secret_exfil() {
    let mut g = guard(false);
    let r = g.guard(
        &call("read_file", "path", "/data/secrets/key.env".into()),
        |_| "leak",
    );
    assert!(r.is_err());
}

#[test]
fn domain_allow_list() {
    let mut g = guard(false);
    let r = g.guard(&call("http_get", "domain", "evil.com".into()), |_| "resp");
    assert!(r.is_err());
}

#[test]
fn high_risk_requires_approval() {
    let mut denied = guard(false);
    assert!(denied
        .guard(&call("run_shell", "cmd", "rm -rf /".into()), |_| "ran")
        .is_err());

    let mut approved = guard(true);
    assert_eq!(
        approved
            .guard(&call("run_shell", "cmd", "ls".into()), |_| "listed")
            .unwrap(),
        "listed"
    );
}

#[test]
fn audit_log_is_signed_and_chained() {
    let mut g = guard(false);
    let _ = g.guard(&call("write_file", "path", "/x".into()), |_| "x");
    let _ = g.guard(&call("read_file", "path", "/data/a".into()), |_| "a");
    assert_eq!(g.audit.entries().len(), 2);
    assert!(g.audit.verify_chain());
}

#[test]
fn policy_evaluate_decisions() {
    let p = guard_policy();
    assert_eq!(
        p.evaluate(&call("read_file", "path", "/data/a".into())).0,
        Decision::Allow
    );
    assert_eq!(p.evaluate(&ToolCall::new("run_shell")).0, Decision::Approve);
    assert_eq!(p.evaluate(&ToolCall::new("nope")).0, Decision::Deny);
}
