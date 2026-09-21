//! AgentGuard runtime: intercept tool calls, enforce policy, audit everything.
//!
//! Wrap any tool-executing closure; [`AgentGuard`] authorizes it against the
//! policy, routes high-risk actions through an approval callback, and writes a
//! signed audit entry for every decision.

use crate::audit::AuditLog;
use crate::policy::{Decision, Policy, ToolCall};

/// A human-approval callback: given the call and the policy reason, decide whether
/// to permit an APPROVE-gated tool.
type ApprovalFn = Box<dyn Fn(&ToolCall, &str) -> bool>;

/// Returned as `Err` when a tool call is denied by policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolBlockedError {
    /// The human-readable block message.
    pub message: String,
}

impl std::fmt::Display for ToolBlockedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ToolBlockedError {}

/// Mediates every tool call: evaluate policy, route high-risk actions through a
/// human-approval callback, audit the decision, then execute or block.
pub struct AgentGuard {
    /// The policy this guard enforces.
    pub policy: Policy,
    /// The signed audit log every decision is written to.
    pub audit: AuditLog,
    approve: ApprovalFn,
}

impl AgentGuard {
    /// Build a guard with a fresh audit log and the default approval callback,
    /// which denies (a safe default; wire a real UI/CLI in prod).
    pub fn new(policy: Policy) -> Self {
        AgentGuard {
            policy,
            audit: AuditLog::new(),
            approve: Box::new(|_, _| false),
        }
    }

    /// Set the human-approval callback for APPROVE-gated tools.
    pub fn with_approval<F>(mut self, callback: F) -> Self
    where
        F: Fn(&ToolCall, &str) -> bool + 'static,
    {
        self.approve = Box::new(callback);
        self
    }

    /// Use a caller-supplied audit log (e.g. one built with a known key).
    pub fn with_audit(mut self, audit: AuditLog) -> Self {
        self.audit = audit;
        self
    }

    /// Authorize a tool call and, if allowed, execute it. Records a signed audit
    /// entry for every decision and returns `Err(ToolBlockedError)` when denied.
    pub fn guard<T, F>(&mut self, call: &ToolCall, execute: F) -> Result<T, ToolBlockedError>
    where
        F: FnOnce(&ToolCall) -> T,
    {
        let (mut decision, mut reason) = self.policy.evaluate(call);

        if decision == Decision::Approve {
            let approved = (self.approve)(call, &reason);
            decision = if approved {
                Decision::Allow
            } else {
                Decision::Deny
            };
            reason = format!(
                "human {}: {}",
                if approved { "approved" } else { "denied" },
                reason
            );
        }

        self.audit.record(&call.tool, decision.value(), &reason);

        if decision == Decision::Allow {
            Ok(execute(call))
        } else {
            Err(ToolBlockedError {
                message: format!("blocked '{}': {}", call.tool, reason),
            })
        }
    }
}
