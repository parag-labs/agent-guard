using System.Collections.Generic;
using Xunit;

namespace AgentGuard.Tests;

public class GuardTests
{
    private static Policy MakePolicy() => new(new[]
    {
        new ToolPolicy("read_file", allow: true,
            pathAllow: new[] { "/data/*" }, pathDeny: new[] { "/data/secrets/*", "*.env" }),
        new ToolPolicy("http_get", allow: true, domainAllow: new[] { "api.company.com" }),
        new ToolPolicy("run_shell", allow: true, requireApproval: true),
    });

    private static Guard MakeGuard(bool approve = false)
        => new(MakePolicy(), (_, _) => approve);

    [Fact]
    public void UnlistedToolDeniedByDefault()
    {
        var g = MakeGuard();
        Assert.Throws<ToolBlockedException>(
            () => g.Execute(new ToolCall("write_file", new() { ["path"] = "/data/x" }), _ => "wrote"));
    }

    [Fact]
    public void AllowedPathExecutes()
    {
        var g = MakeGuard();
        var outVal = g.Execute(new ToolCall("read_file", new() { ["path"] = "/data/report.txt" }), _ => "content");
        Assert.Equal("content", outVal);
    }

    [Fact]
    public void DeniedPathBlocksSecretExfil()
    {
        var g = MakeGuard();
        Assert.Throws<ToolBlockedException>(
            () => g.Execute(new ToolCall("read_file", new() { ["path"] = "/data/secrets/key.env" }), _ => "leak"));
    }

    [Fact]
    public void DomainAllowList()
    {
        var g = MakeGuard();
        Assert.Throws<ToolBlockedException>(
            () => g.Execute(new ToolCall("http_get", new() { ["domain"] = "evil.com" }), _ => "resp"));
    }

    [Fact]
    public void HighRiskRequiresApproval()
    {
        var denied = MakeGuard(approve: false);
        Assert.Throws<ToolBlockedException>(
            () => denied.Execute(new ToolCall("run_shell", new() { ["cmd"] = "rm -rf /" }), _ => "ran"));

        var approved = MakeGuard(approve: true);
        Assert.Equal("listed",
            approved.Execute(new ToolCall("run_shell", new() { ["cmd"] = "ls" }), _ => "listed"));
    }

    [Fact]
    public void AuditLogIsSignedAndChained()
    {
        var g = MakeGuard();
        try { g.Execute(new ToolCall("write_file", new() { ["path"] = "/x" }), _ => "x"); }
        catch (ToolBlockedException) { }
        g.Execute(new ToolCall("read_file", new() { ["path"] = "/data/a" }), _ => "a");
        Assert.Equal(2, g.Audit.Entries().Count);
        Assert.True(g.Audit.VerifyChain());
    }

    [Fact]
    public void PolicyEvaluateDecisions()
    {
        var p = MakePolicy();
        Assert.Equal(Decision.Allow, p.Evaluate(new ToolCall("read_file", new() { ["path"] = "/data/a" })).Item1);
        Assert.Equal(Decision.Approve, p.Evaluate(new ToolCall("run_shell", new())).Item1);
        Assert.Equal(Decision.Deny, p.Evaluate(new ToolCall("nope", new())).Item1);
    }
}
