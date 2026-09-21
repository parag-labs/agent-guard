//! Adversarial fuzz suite (port of the Python reference): try to defeat the guard.
//!
//! Two promises are attacked here -- deny-by-default authorization and a
//! tamper-evident audit trail. The invariant is absolute: nothing outside the
//! explicit allow-list is ever authorized, and any edit to the audit log is caught.

use agent_guard::{ArgValue, AuditLog, Decision, Policy, ToolCall, ToolPolicy};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashMap;

fn fs_policy() -> Policy {
    Policy::new(vec![
        ToolPolicy {
            tool: "read_file".into(),
            allow: true,
            path_allow: vec!["/workspace/*".into()],
            path_deny: vec!["*.env*".into(), "*secrets*".into(), "*id_rsa*".into()],
            ..Default::default()
        },
        ToolPolicy {
            tool: "http_get".into(),
            allow: true,
            domain_allow: vec!["api.internal".into()],
            ..Default::default()
        },
        ToolPolicy {
            tool: "delete_file".into(),
            allow: true,
            require_approval: true,
            ..Default::default()
        },
    ])
}

fn read(path: ArgValue) -> ToolCall {
    let mut args = HashMap::new();
    args.insert("path".to_string(), path);
    ToolCall::with_args("read_file", args)
}

fn get(domain: &str) -> ToolCall {
    let mut args = HashMap::new();
    args.insert("domain".to_string(), domain.into());
    ToolCall::with_args("http_get", args)
}

// --- a tiny deterministic RNG (SplitMix64) so the fuzz is reproducible ---
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Rng { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    fn range_incl(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

fn from_hex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16).unwrap();
        let lo = (b[i + 1] as char).to_digit(16).unwrap();
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    out
}

// ---- deny-by-default is the floor ----

#[test]
fn unknown_tools_are_always_denied() {
    let policy = fs_policy();
    for tool in [
        "exec",
        "eval",
        "rm",
        "read_fil",
        "READ_FILE",
        "http_post",
        "",
    ] {
        let mut args = HashMap::new();
        args.insert("path".to_string(), ArgValue::from("/workspace/ok.txt"));
        let (decision, _) = policy.evaluate(&ToolCall::with_args(tool, args));
        assert_eq!(
            decision,
            Decision::Deny,
            "unlisted tool '{tool}' slipped through"
        );
    }
}

#[test]
fn tool_names_are_matched_exactly_not_by_prefix() {
    let policy = fs_policy();
    for tool in ["read_file2", "read_file ", " read_file", "read_file\n"] {
        let mut args = HashMap::new();
        args.insert("path".to_string(), ArgValue::from("/workspace/ok.txt"));
        let (decision, _) = policy.evaluate(&ToolCall::with_args(tool, args));
        assert_eq!(decision, Decision::Deny);
    }
}

// ---- path constraints hold under hostile inputs ----

#[test]
fn secret_paths_are_denied_even_inside_the_allowed_root() {
    let policy = fs_policy();
    let hostile = [
        "/workspace/.env",
        "/workspace/secrets/prod.key",
        "/workspace/nested/id_rsa",
        "/workspace/sub/secrets/db.pem",
    ];
    for path in hostile {
        let (decision, reason) = policy.evaluate(&read(path.into()));
        assert_eq!(
            decision,
            Decision::Deny,
            "secret path allowed: {path} ({reason})"
        );
    }
}

#[test]
fn paths_outside_the_allowed_root_are_denied() {
    let policy = fs_policy();
    let outside = [
        "/etc/passwd",
        "/root/.ssh/known_hosts",
        "workspace/relative.txt",
        "/workspaceX/evil.txt",
    ];
    for path in outside {
        let (decision, _) = policy.evaluate(&read(path.into()));
        assert_eq!(
            decision,
            Decision::Deny,
            "path outside root allowed: {path}"
        );
    }
}

#[test]
fn deny_patterns_win_over_allow() {
    let policy = fs_policy();
    let (decision, reason) = policy.evaluate(&read("/workspace/.env".into()));
    assert_eq!(decision, Decision::Deny);
    assert!(reason.to_lowercase().contains("deny"));
}

#[test]
fn domain_allow_list_is_strict() {
    let policy = fs_policy();
    for domain in [
        "api.external",
        "api.internal.evil.com",
        "evil.com",
        "API.INTERNAL",
    ] {
        let (decision, _) = policy.evaluate(&get(domain));
        assert_eq!(decision, Decision::Deny, "domain slipped through: {domain}");
    }
    let (ok, _) = policy.evaluate(&get("api.internal"));
    assert_eq!(ok, Decision::Allow);
}

#[test]
fn high_risk_tools_require_approval_never_silent_allow() {
    let policy = fs_policy();
    let mut args = HashMap::new();
    args.insert("path".to_string(), ArgValue::from("/workspace/tmp.txt"));
    let (decision, _) = policy.evaluate(&ToolCall::with_args("delete_file", args));
    assert_eq!(decision, Decision::Approve);
}

#[test]
fn missing_or_odd_arguments_do_not_crash_or_bypass() {
    let policy = fs_policy();

    // {} - no path at all
    assert_eq!(
        policy.evaluate(&ToolCall::new("read_file")).0,
        Decision::Deny
    );
    // {"path": ""}
    assert_eq!(policy.evaluate(&read("".into())).0, Decision::Deny);
    // {"path": None}
    assert_eq!(policy.evaluate(&read(ArgValue::Null)).0, Decision::Deny);
    // {"path": 12345}
    assert_eq!(
        policy.evaluate(&read(ArgValue::Int(12345))).0,
        Decision::Deny
    );
    // {"unexpected": "x"}
    let mut odd = HashMap::new();
    odd.insert("unexpected".to_string(), ArgValue::from("x"));
    assert_eq!(
        policy.evaluate(&ToolCall::with_args("read_file", odd)).0,
        Decision::Deny
    );
    // {"path": "/workspace/ok.txt", "extra": object()} -> valid path, allowed
    let mut ok = HashMap::new();
    ok.insert("path".to_string(), ArgValue::from("/workspace/ok.txt"));
    ok.insert("extra".to_string(), ArgValue::Other);
    let (decision, _) = policy.evaluate(&ToolCall::with_args("read_file", ok));
    assert_eq!(decision, Decision::Allow);
}

#[test]
fn randomized_paths_never_escape_the_allow_root() {
    let mut rng = Rng::new(0);
    let policy = fs_policy();
    let tokens = [
        "workspace",
        "..",
        ".",
        "etc",
        "secrets",
        "ok.txt",
        ".env",
        "a",
        "id_rsa",
    ];
    for _ in 0..5000 {
        let depth = rng.range_incl(1, 6);
        let mut parts = Vec::with_capacity(depth);
        for _ in 0..depth {
            parts.push(tokens[rng.below(tokens.len())]);
        }
        let path = format!("/{}", parts.join("/"));
        let (decision, _) = policy.evaluate(&read(path.clone().into()));
        if decision == Decision::Allow {
            assert!(path.starts_with("/workspace/"));
            assert!(
                !path.contains(".env") && !path.contains("secrets") && !path.contains("id_rsa")
            );
        }
    }
}

// ---- audit trail is tamper-evident ----

#[test]
fn clean_audit_chain_verifies() {
    let mut log = AuditLog::new();
    for i in 0..50 {
        log.record(&format!("tool-{i}"), "allow", "ok");
    }
    assert!(log.verify_chain());
}

#[test]
fn editing_any_audit_field_is_detected() {
    let mut rng = Rng::new(1);
    for _ in 0..200 {
        let mut log = AuditLog::new();
        for i in 0..10 {
            let decision = if i % 2 == 1 { "allow" } else { "deny" };
            log.record(&format!("tool-{i}"), decision, "reason");
        }
        let idx = rng.below(log.entries().len());
        let victim = &mut log.entries_mut()[idx];
        victim.decision = if victim.decision == "deny" {
            "allow"
        } else {
            "deny"
        }
        .to_string();
        assert!(!log.verify_chain());
    }
}

#[test]
fn truncating_or_reordering_the_chain_is_detected() {
    let mut log = AuditLog::new();
    for i in 0..10 {
        log.record(&format!("tool-{i}"), "allow", "ok");
    }
    log.entries_mut().swap(3, 6);
    assert!(!log.verify_chain());
}

#[test]
fn a_signature_from_the_wrong_key_is_rejected() {
    let mut log = AuditLog::new();
    log.record("t", "allow", "ok");
    let attacker = SigningKey::from_bytes(&[7u8; 32]);
    let entry_hash = log.entries()[0].entry_hash.clone();
    let forged = attacker.sign(entry_hash.as_bytes());
    log.entries_mut()[0].signature = to_hex(&forged.to_bytes());
    assert!(!log.verify_chain());
}

#[test]
fn flipping_a_byte_in_a_signature_is_rejected() {
    let mut rng = Rng::new(2);
    for _ in 0..100 {
        let mut log = AuditLog::new();
        log.record("t", "allow", "ok");
        let mut raw = from_hex(&log.entries()[0].signature);
        let idx = rng.below(raw.len());
        let bit = rng.below(8);
        raw[idx] ^= 1u8 << bit;
        log.entries_mut()[0].signature = to_hex(&raw);
        assert!(!log.verify_chain());
    }
}
