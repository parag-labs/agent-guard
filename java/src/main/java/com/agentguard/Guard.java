// AgentGuard runtime: intercept tool calls, enforce policy, audit everything.
//
// Wrap any tool-executing function; AgentGuard authorizes it against the policy,
// routes high-risk actions through an approval callback, and writes a signed audit
// entry for every decision.

package com.agentguard;

import com.agentguard.Policy.Decision;
import com.agentguard.Policy.Result;
import com.agentguard.Policy.ToolCall;
import java.util.function.BiPredicate;
import java.util.function.Function;

public final class Guard {

    public static final class ToolBlockedException extends RuntimeException {
        public ToolBlockedException(String message) { super(message); }
    }

    public final Policy policy;
    public final AuditLog audit;
    private final BiPredicate<ToolCall, String> approve;

    public Guard(Policy policy) {
        this(policy, null, null);
    }

    public Guard(Policy policy, BiPredicate<ToolCall, String> approvalCallback) {
        this(policy, approvalCallback, null);
    }

    public Guard(Policy policy, BiPredicate<ToolCall, String> approvalCallback, AuditLog audit) {
        this.policy = policy;
        this.audit = audit != null ? audit : new AuditLog();
        // Default approval callback denies (safe default; wire a real UI/CLI in prod).
        this.approve = approvalCallback != null ? approvalCallback : (call, reason) -> false;
    }

    public Object execute(ToolCall call, Function<ToolCall, Object> execute) {
        Result result = policy.evaluate(call);
        Decision decision = result.decision();
        String reason = result.reason();

        if (decision == Decision.APPROVE) {
            boolean approved = approve.test(call, reason);
            decision = approved ? Decision.ALLOW : Decision.DENY;
            reason = "human " + (approved ? "approved" : "denied") + ": " + reason;
        }

        audit.record(call.tool(), decision.value, reason);

        if (decision == Decision.ALLOW) return execute.apply(call);
        throw new ToolBlockedException("blocked '" + call.tool() + "': " + reason);
    }
}
