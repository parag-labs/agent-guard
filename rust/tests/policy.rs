//! Extra focused tests for the policy primitives and runtime plumbing.

use agent_guard::{
    AgentGuard, ArgValue, AuditLog, Decision, Policy, ToolBlockedError, ToolCall, ToolPolicy,
};
use std::collections::HashMap;

fn read_only() -> Policy {
    Policy::new(vec![ToolPolicy {
        tool: "read_file".into(),
        allow: true,
        path_allow: vec!["/data/*".into()],
        path_deny: vec!["*.secret".into()],
        ..Default::default()
    }])
}

fn read(path: &str) -> ToolCall {
    let mut args = HashMap::new();
    args.insert("path".to_string(), ArgValue::from(path));
    ToolCall::with_args("read_file", args)
}

#[test]
fn decision_value_strings() {
    assert_eq!(Decision::Allow.value(), "allow");
    assert_eq!(Decision::Deny.value(), "deny");
    assert_eq!(Decision::Approve.value(), "approve");
}

#[test]
fn allow_false_is_denied_even_when_listed() {
    let policy = Policy::new(vec![ToolPolicy {
        tool: "read_file".into(),
        allow: false,
        ..Default::default()
    }]);
    assert_eq!(policy.evaluate(&read("/data/x")).0, Decision::Deny);
}

#[test]
fn glob_question_mark_matches_single_char() {
    let policy = Policy::new(vec![ToolPolicy {
        tool: "read_file".into(),
        allow: true,
        path_allow: vec!["/data/?.txt".into()],
        ..Default::default()
    }]);
    assert_eq!(policy.evaluate(&read("/data/a.txt")).0, Decision::Allow);
    assert_eq!(policy.evaluate(&read("/data/ab.txt")).0, Decision::Deny);
}

#[test]
fn glob_char_class_and_negation() {
    let policy = Policy::new(vec![ToolPolicy {
        tool: "read_file".into(),
        allow: true,
        path_allow: vec!["/data/[a-c].txt".into()],
        path_deny: vec!["/data/[!a-c].txt".into()],
        ..Default::default()
    }]);
    assert_eq!(policy.evaluate(&read("/data/b.txt")).0, Decision::Allow);
    // 'z' is not in the allow class, so it fails the allow-list.
    assert_eq!(policy.evaluate(&read("/data/z.txt")).0, Decision::Deny);
}

#[test]
fn star_matches_across_slashes() {
    // Python fnmatch '*' spans '/', which is why deny globs catch nested secrets.
    let policy = read_only();
    let (decision, reason) = policy.evaluate(&read("/data/deep/nested/creds.secret"));
    assert_eq!(decision, Decision::Deny);
    assert!(reason.contains("deny pattern"));
}

#[test]
fn arg_value_int_stringifies() {
    let mut args = HashMap::new();
    args.insert("path".to_string(), ArgValue::Int(42));
    let call = ToolCall::with_args("read_file", args);
    // 42 -> "42": non-empty, not under /data/*, so denied as not-in-allowed-paths.
    let (decision, reason) = read_only().evaluate(&call);
    assert_eq!(decision, Decision::Deny);
    assert!(reason.contains("not in allowed paths"));
}

#[test]
fn blocked_error_message_and_display() {
    let mut g = AgentGuard::new(read_only());
    let err = g.guard(&read("/etc/passwd"), |_| "x").unwrap_err();
    let expected = ToolBlockedError {
        message: "blocked 'read_file': path '/etc/passwd' not in allowed paths".to_string(),
    };
    assert_eq!(err, expected);
    assert_eq!(format!("{err}"), expected.message);
}

#[test]
fn with_audit_uses_supplied_log_and_records_decision() {
    let log = AuditLog::new();
    let mut g = AgentGuard::new(read_only()).with_audit(log);
    let _ = g.guard(&read("/data/ok.txt"), |_| "content");
    let entries = g.audit.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].decision, "allow");
    assert!(g.audit.verify_chain());
}
