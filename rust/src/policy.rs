//! AgentGuard policy engine: deny-by-default, least-privilege tool authorization.
//!
//! Every agent tool call is evaluated against a policy before execution. Decisions
//! are ALLOW, DENY, or APPROVE (human-in-the-loop for high-risk actions).

use std::collections::HashMap;

/// The outcome of evaluating a tool call against a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Permit the tool call to execute.
    Allow,
    /// Block the tool call.
    Deny,
    /// Require human approval before the call may execute.
    Approve,
}

impl Decision {
    /// The lowercase wire string stored in the audit log.
    pub fn value(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Approve => "approve",
        }
    }
}

/// A single argument value in a tool call. Mirrors the reference's dynamically
/// typed args: a string, an integer, an explicit null, or some other object.
#[derive(Debug, Clone)]
pub enum ArgValue {
    /// A string argument.
    Str(String),
    /// An integer argument.
    Int(i64),
    /// An explicit null (treated the same as a missing argument).
    Null,
    /// Any other object; stringifies to a non-empty placeholder.
    Other,
}

impl ArgValue {
    fn as_arg_string(&self) -> String {
        match self {
            ArgValue::Str(s) => s.clone(),
            ArgValue::Int(n) => n.to_string(),
            ArgValue::Null => String::new(),
            ArgValue::Other => "<object>".to_string(),
        }
    }
}

impl From<&str> for ArgValue {
    fn from(s: &str) -> Self {
        ArgValue::Str(s.to_string())
    }
}

impl From<String> for ArgValue {
    fn from(s: String) -> Self {
        ArgValue::Str(s)
    }
}

impl From<i64> for ArgValue {
    fn from(n: i64) -> Self {
        ArgValue::Int(n)
    }
}

/// A single request by the agent to invoke a named tool with arguments.
#[derive(Debug, Clone)]
pub struct ToolCall {
    /// The tool name.
    pub tool: String,
    /// The call arguments.
    pub args: HashMap<String, ArgValue>,
}

impl ToolCall {
    /// Build a tool call with no arguments.
    pub fn new(tool: impl Into<String>) -> Self {
        ToolCall {
            tool: tool.into(),
            args: HashMap::new(),
        }
    }

    /// Build a tool call with the given arguments.
    pub fn with_args(tool: impl Into<String>, args: HashMap<String, ArgValue>) -> Self {
        ToolCall {
            tool: tool.into(),
            args,
        }
    }

    /// Mirror the reference's `str(args.get(key))` with `None -> ""`: a missing or
    /// null value becomes the empty string; any other value is stringified.
    fn arg_string(&self, key: &str) -> String {
        self.args
            .get(key)
            .map(ArgValue::as_arg_string)
            .unwrap_or_default()
    }
}

/// The constraints attached to one allowed tool. The default value denies
/// everything: `allow` is false and every constraint list is empty.
#[derive(Debug, Clone, Default)]
pub struct ToolPolicy {
    /// The tool this policy governs.
    pub tool: String,
    /// Whether the tool is allowed at all.
    pub allow: bool,
    /// Glob patterns a `path` argument must match.
    pub path_allow: Vec<String>,
    /// Glob patterns a `path` argument must not match.
    pub path_deny: Vec<String>,
    /// Exact domains a `domain` argument must be one of.
    pub domain_allow: Vec<String>,
    /// Whether the tool requires human approval.
    pub require_approval: bool,
}

/// Deny-by-default: only explicitly allowed tools, within their declared
/// constraints, ever pass.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// The allow-table, keyed by tool name.
    pub tools: HashMap<String, ToolPolicy>,
}

impl Policy {
    /// Build a policy from a list of tool policies, keyed by tool name.
    pub fn new(tools: Vec<ToolPolicy>) -> Self {
        let mut map = HashMap::new();
        for t in tools {
            map.insert(t.tool.clone(), t);
        }
        Policy { tools: map }
    }

    /// Evaluate a tool call and return the decision plus a human-readable reason.
    pub fn evaluate(&self, call: &ToolCall) -> (Decision, String) {
        let tp = match self.tools.get(&call.tool) {
            Some(tp) if tp.allow => tp,
            _ => {
                return (
                    Decision::Deny,
                    format!("tool '{}' not in allow-list (deny-by-default)", call.tool),
                )
            }
        };

        let path = call.arg_string("path");
        // Deny-by-default extends to constrained arguments: if a tool is restricted
        // to certain paths but the call provides none, we can't prove it's in
        // bounds, so we refuse rather than fall through to allow.
        if !tp.path_allow.is_empty() && path.is_empty() {
            return (
                Decision::Deny,
                format!(
                    "tool '{}' requires a path within its allowed set",
                    call.tool
                ),
            );
        }
        if !path.is_empty() {
            for pattern in &tp.path_deny {
                if fnmatch(&path, pattern) {
                    return (
                        Decision::Deny,
                        format!("path '{path}' matches deny pattern '{pattern}'"),
                    );
                }
            }
            if !tp.path_allow.is_empty() && !tp.path_allow.iter().any(|p| fnmatch(&path, p)) {
                return (
                    Decision::Deny,
                    format!("path '{path}' not in allowed paths"),
                );
            }
        }

        let domain = call.arg_string("domain");
        if !tp.domain_allow.is_empty() && domain.is_empty() {
            return (
                Decision::Deny,
                format!(
                    "tool '{}' requires a domain within its allowed set",
                    call.tool
                ),
            );
        }
        if !domain.is_empty() && !tp.domain_allow.is_empty() && !tp.domain_allow.contains(&domain) {
            return (
                Decision::Deny,
                format!("domain '{domain}' not in allow-list"),
            );
        }

        if tp.require_approval {
            return (
                Decision::Approve,
                format!("tool '{}' requires human approval", call.tool),
            );
        }
        (Decision::Allow, "ok".to_string())
    }
}

// --- glob matching with Python fnmatch semantics (case-sensitive, full match) ---

enum Tok {
    Star,
    Any,
    Lit(char),
    Class {
        neg: bool,
        ranges: Vec<(char, char)>,
    },
}

/// Match `name` against a shell glob using Python `fnmatch` semantics: case
/// sensitive, whole-string, `*` matches any run (including `/`), `?` any single
/// char, and `[...]`/`[!...]` character classes.
fn fnmatch(name: &str, pattern: &str) -> bool {
    let toks = compile(&pattern.chars().collect::<Vec<char>>());
    let name: Vec<char> = name.chars().collect();

    let (mut i, mut j) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_i = 0usize;
    while i < name.len() {
        if j < toks.len() && !matches!(toks[j], Tok::Star) && tok_matches(&toks[j], name[i]) {
            i += 1;
            j += 1;
        } else if j < toks.len() && matches!(toks[j], Tok::Star) {
            star = Some(j);
            star_i = i;
            j += 1;
        } else if let Some(sj) = star {
            j = sj + 1;
            star_i += 1;
            i = star_i;
        } else {
            return false;
        }
    }
    while j < toks.len() && matches!(toks[j], Tok::Star) {
        j += 1;
    }
    j == toks.len()
}

fn tok_matches(tok: &Tok, c: char) -> bool {
    match tok {
        Tok::Any => true,
        Tok::Lit(l) => *l == c,
        Tok::Class { neg, ranges } => {
            let inside = ranges.iter().any(|(lo, hi)| *lo <= c && c <= *hi);
            inside != *neg
        }
        Tok::Star => false,
    }
}

fn compile(pattern: &[char]) -> Vec<Tok> {
    let mut toks = Vec::new();
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            '*' => {
                toks.push(Tok::Star);
                i += 1;
            }
            '?' => {
                toks.push(Tok::Any);
                i += 1;
            }
            '[' => {
                let mut j = i + 1;
                if j < pattern.len() && pattern[j] == '!' {
                    j += 1;
                }
                if j < pattern.len() && pattern[j] == ']' {
                    j += 1;
                }
                while j < pattern.len() && pattern[j] != ']' {
                    j += 1;
                }
                if j >= pattern.len() {
                    // No closing bracket: treat '[' as a literal.
                    toks.push(Tok::Lit('['));
                    i += 1;
                } else {
                    toks.push(parse_class(&pattern[i + 1..j]));
                    i = j + 1;
                }
            }
            c => {
                toks.push(Tok::Lit(c));
                i += 1;
            }
        }
    }
    toks
}

fn parse_class(body: &[char]) -> Tok {
    let mut neg = false;
    let mut idx = 0;
    if !body.is_empty() && body[0] == '!' {
        neg = true;
        idx = 1;
    }
    let mut ranges = Vec::new();
    while idx < body.len() {
        if idx + 2 < body.len() && body[idx + 1] == '-' {
            ranges.push((body[idx], body[idx + 2]));
            idx += 3;
        } else {
            ranges.push((body[idx], body[idx]));
            idx += 1;
        }
    }
    Tok::Class { neg, ranges }
}
