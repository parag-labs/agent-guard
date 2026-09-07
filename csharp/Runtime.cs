// AgentGuard runtime: intercept tool calls, enforce policy, audit everything.
//
// Wrap any tool-executing function; AgentGuard authorizes it against the policy,
// routes high-risk actions through an approval callback, and writes a signed audit
// entry for every decision.

using System;

namespace AgentGuard;

public sealed class ToolBlockedException : Exception
{
    public ToolBlockedException(string message) : base(message) { }
}

public sealed class Guard
{
    public Policy Policy { get; }
    public AuditLog Audit { get; }
    private readonly Func<ToolCall, string, bool> _approve;

    public Guard(
        Policy policy,
        Func<ToolCall, string, bool>? approvalCallback = null,
        AuditLog? audit = null)
    {
        Policy = policy;
        Audit = audit ?? new AuditLog();
        // Default approval callback denies (safe default; wire a real UI/CLI in prod).
        _approve = approvalCallback ?? ((_, _) => false);
    }

    public object? Execute(ToolCall call, Func<ToolCall, object?> execute)
    {
        var (decision, reason) = Policy.Evaluate(call);

        if (decision == Decision.Approve)
        {
            var approved = _approve(call, reason);
            decision = approved ? Decision.Allow : Decision.Deny;
            reason = $"human {(approved ? "approved" : "denied")}: {reason}";
        }

        Audit.Record(call.Tool, DecisionValue(decision), reason);

        if (decision == Decision.Allow) return execute(call);
        throw new ToolBlockedException($"blocked '{call.Tool}': {reason}");
    }

    public static string DecisionValue(Decision d) => d switch
    {
        Decision.Allow => "allow",
        Decision.Deny => "deny",
        Decision.Approve => "approve",
        _ => throw new ArgumentOutOfRangeException(nameof(d)),
    };
}
