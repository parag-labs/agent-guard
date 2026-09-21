// AgentGuard runtime: intercept tool calls, enforce policy, audit everything.
//
// Wrap any tool-executing function; AgentGuard authorizes it against the policy,
// routes high-risk actions through an approval callback, and writes a signed audit
// entry for every decision.

package agentguard

import "fmt"

// ToolBlockedError is returned when a tool call is denied by policy.
type ToolBlockedError struct {
	Message string
}

// Error implements the error interface.
func (e *ToolBlockedError) Error() string { return e.Message }

// ApprovalCallback decides whether a human approves an APPROVE-gated call.
type ApprovalCallback func(call ToolCall, reason string) bool

// Executor runs the underlying tool once a call has been authorized.
type Executor func(call ToolCall) any

// AgentGuard mediates every tool call: it evaluates policy, routes high-risk
// actions through an approval callback, audits the decision, and only then
// executes (or blocks) the call.
type AgentGuard struct {
	Policy  Policy
	Audit   *AuditLog
	approve ApprovalCallback
}

// NewAgentGuard builds a guard. If approvalCallback is nil, approval defaults to
// denial (a safe default; wire a real UI/CLI in prod). If audit is nil, a fresh
// signed log is created.
func NewAgentGuard(policy Policy, approvalCallback ApprovalCallback, audit *AuditLog) *AgentGuard {
	if audit == nil {
		audit = NewAuditLog()
	}
	if approvalCallback == nil {
		approvalCallback = func(ToolCall, string) bool { return false }
	}
	return &AgentGuard{Policy: policy, Audit: audit, approve: approvalCallback}
}

// Guard authorizes a tool call and, if allowed, executes it. It records a signed
// audit entry for every decision and returns a *ToolBlockedError when the call is
// denied.
func (g *AgentGuard) Guard(call ToolCall, execute Executor) (any, error) {
	decision, reason := g.Policy.Evaluate(call)

	if decision == Approve {
		if g.approve(call, reason) {
			decision = Allow
			reason = "human approved: " + reason
		} else {
			decision = Deny
			reason = "human denied: " + reason
		}
	}

	g.Audit.Record(call.Tool, string(decision), reason)

	if decision == Allow {
		return execute(call), nil
	}
	return nil, &ToolBlockedError{Message: fmt.Sprintf("blocked '%s': %s", call.Tool, reason)}
}
