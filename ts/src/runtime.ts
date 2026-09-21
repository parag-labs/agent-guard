/**
 * AgentGuard runtime: intercept tool calls, enforce policy, audit everything.
 *
 * Wrap any tool-executing function; {@link AgentGuard} authorizes it against the
 * policy, routes high-risk actions through an approval callback, and writes a
 * signed audit entry for every decision.
 */

import { AuditLog } from "./audit.ts";
import { Decision, Policy, ToolCall } from "./policy.ts";

/** Thrown when a tool call is denied by policy. */
export class ToolBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ToolBlockedError";
  }
}

/** Decides whether an APPROVE-gated tool may run, given the call and reason. */
export type ApprovalCallback = (call: ToolCall, reason: string) => boolean;

/** Executes an authorized tool call and returns its result. */
export type Executor = (call: ToolCall) => unknown;

/**
 * Mediates every tool call: evaluate policy, route high-risk actions through a
 * human-approval callback, audit the decision, then execute or block.
 */
export class AgentGuard {
  readonly policy: Policy;
  readonly audit: AuditLog;
  private readonly approve: ApprovalCallback;

  constructor(
    policy: Policy,
    approvalCallback?: ApprovalCallback,
    audit?: AuditLog,
  ) {
    this.policy = policy;
    this.audit = audit ?? new AuditLog();
    // Default approval callback denies (safe default; wire a real UI/CLI in prod).
    this.approve = approvalCallback ?? (() => false);
  }

  /**
   * Authorize a tool call and, if allowed, execute it. Records a signed audit
   * entry for every decision and throws {@link ToolBlockedError} when denied.
   */
  guard(call: ToolCall, execute: Executor): unknown {
    let [decision, reason] = this.policy.evaluate(call);

    if (decision === Decision.Approve) {
      const approved = this.approve(call, reason);
      decision = approved ? Decision.Allow : Decision.Deny;
      reason = `human ${approved ? "approved" : "denied"}: ${reason}`;
    }

    this.audit.record(call.tool, decision, reason);

    if (decision === Decision.Allow) {
      return execute(call);
    }
    throw new ToolBlockedError(`blocked '${call.tool}': ${reason}`);
  }
}
