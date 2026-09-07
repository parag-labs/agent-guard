// AgentGuard policy engine: deny-by-default, least-privilege tool authorization.
//
// Every agent tool call is evaluated against a policy before execution. Decisions are
// ALLOW, DENY, or APPROVE (human-in-the-loop for high-risk actions).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace AgentGuard;

public enum Decision { Allow, Deny, Approve }

public sealed class ToolCall
{
    public string Tool { get; }
    public Dictionary<string, object?> Args { get; }

    public ToolCall(string tool, Dictionary<string, object?>? args = null)
    {
        Tool = tool;
        Args = args ?? new Dictionary<string, object?>();
    }
}

public sealed class ToolPolicy
{
    public string Tool { get; }
    public bool Allow { get; }
    public List<string> PathAllow { get; }
    public List<string> PathDeny { get; }
    public List<string> DomainAllow { get; }
    public bool RequireApproval { get; }

    public ToolPolicy(
        string tool,
        bool allow = false,
        IEnumerable<string>? pathAllow = null,
        IEnumerable<string>? pathDeny = null,
        IEnumerable<string>? domainAllow = null,
        bool requireApproval = false)
    {
        Tool = tool;
        Allow = allow;
        PathAllow = pathAllow?.ToList() ?? new List<string>();
        PathDeny = pathDeny?.ToList() ?? new List<string>();
        DomainAllow = domainAllow?.ToList() ?? new List<string>();
        RequireApproval = requireApproval;
    }
}

/// <summary>Deny-by-default: only explicitly allowed tools/constraints pass.</summary>
public sealed class Policy
{
    public Dictionary<string, ToolPolicy> Tools { get; }

    public Policy(IEnumerable<ToolPolicy> tools)
        => Tools = tools.ToDictionary(t => t.Tool, t => t);

    public (Decision, string) Evaluate(ToolCall call)
    {
        if (!Tools.TryGetValue(call.Tool, out var tp) || !tp.Allow)
            return (Decision.Deny, $"tool '{call.Tool}' not in allow-list (deny-by-default)");

        var path = ArgString(call, "path");
        // Deny-by-default extends to constrained arguments: if a tool is restricted to
        // certain paths but the call provides none, we can't prove it's in bounds, so we
        // refuse rather than fall through to allow.
        if (tp.PathAllow.Count > 0 && path.Length == 0)
            return (Decision.Deny, $"tool '{call.Tool}' requires a path within its allowed set");
        if (path.Length > 0)
        {
            foreach (var pattern in tp.PathDeny)
                if (FnMatch(path, pattern))
                    return (Decision.Deny, $"path '{path}' matches deny pattern '{pattern}'");
            if (tp.PathAllow.Count > 0 && !tp.PathAllow.Any(p => FnMatch(path, p)))
                return (Decision.Deny, $"path '{path}' not in allowed paths");
        }

        var domain = ArgString(call, "domain");
        if (tp.DomainAllow.Count > 0 && domain.Length == 0)
            return (Decision.Deny, $"tool '{call.Tool}' requires a domain within its allowed set");
        if (domain.Length > 0 && tp.DomainAllow.Count > 0 && !tp.DomainAllow.Contains(domain))
            return (Decision.Deny, $"domain '{domain}' not in allow-list");

        if (tp.RequireApproval)
            return (Decision.Approve, $"tool '{call.Tool}' requires human approval");

        return (Decision.Allow, "ok");
    }

    private static string ArgString(ToolCall call, string key)
        => call.Args.TryGetValue(key, out var v) && v is not null ? v.ToString() ?? "" : "";

    // --- glob matching with Python fnmatch semantics (case-sensitive, full match) ---

    private static readonly Dictionary<string, Regex> Cache = new();

    private static bool FnMatch(string name, string pattern)
    {
        if (!Cache.TryGetValue(pattern, out var rx))
        {
            rx = new Regex("^" + Translate(pattern) + @"\z", RegexOptions.Singleline);
            Cache[pattern] = rx;
        }
        return rx.IsMatch(name);
    }

    private static string Translate(string pat)
    {
        var sb = new StringBuilder();
        var i = 0;
        while (i < pat.Length)
        {
            var c = pat[i++];
            switch (c)
            {
                case '*': sb.Append(".*"); break;
                case '?': sb.Append('.'); break;
                case '[':
                {
                    var j = i;
                    if (j < pat.Length && (pat[j] == '!' || pat[j] == '^')) j++;
                    if (j < pat.Length && pat[j] == ']') j++;
                    while (j < pat.Length && pat[j] != ']') j++;
                    if (j >= pat.Length)
                    {
                        sb.Append(@"\[");
                    }
                    else
                    {
                        var inner = pat.Substring(i, j - i).Replace(@"\", @"\\");
                        i = j + 1;
                        if (inner.StartsWith("!")) inner = "^" + inner.Substring(1);
                        sb.Append('[').Append(inner).Append(']');
                    }
                    break;
                }
                default: sb.Append(Regex.Escape(c.ToString())); break;
            }
        }
        return sb.ToString();
    }
}
