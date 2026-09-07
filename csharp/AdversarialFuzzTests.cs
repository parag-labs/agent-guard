// Adversarial fuzz suite: try to defeat the guard.
//
// AgentGuard makes two promises - deny-by-default authorization, and a tamper-evident
// audit trail. This suite is written from the attacker's side of both.

using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace AgentGuard.Tests;

public class AdversarialFuzzTests
{
    private static Policy FsPolicy() => new(new[]
    {
        new ToolPolicy("read_file", allow: true,
            pathAllow: new[] { "/workspace/*" },
            pathDeny: new[] { "*.env*", "*secrets*", "*id_rsa*" }),
        new ToolPolicy("http_get", allow: true, domainAllow: new[] { "api.internal" }),
        new ToolPolicy("delete_file", allow: true, requireApproval: true),
    });

    [Fact]
    public void UnknownToolsAreAlwaysDenied()
    {
        var policy = FsPolicy();
        foreach (var tool in new[] { "exec", "eval", "rm", "read_fil", "READ_FILE", "http_post", "" })
        {
            var (d, _) = policy.Evaluate(new ToolCall(tool, new() { ["path"] = "/workspace/ok.txt" }));
            Assert.Equal(Decision.Deny, d);
        }
    }

    [Fact]
    public void ToolNamesAreMatchedExactlyNotByPrefix()
    {
        var policy = FsPolicy();
        foreach (var tool in new[] { "read_file2", "read_file ", " read_file", "read_file\n" })
        {
            var (d, _) = policy.Evaluate(new ToolCall(tool, new() { ["path"] = "/workspace/ok.txt" }));
            Assert.Equal(Decision.Deny, d);
        }
    }

    [Fact]
    public void SecretPathsAreDeniedEvenInsideTheAllowedRoot()
    {
        var policy = FsPolicy();
        var hostile = new[]
        {
            "/workspace/.env",
            "/workspace/secrets/prod.key",
            "/workspace/nested/id_rsa",
            "/workspace/sub/secrets/db.pem",
        };
        foreach (var path in hostile)
        {
            var (d, _) = policy.Evaluate(new ToolCall("read_file", new() { ["path"] = path }));
            Assert.Equal(Decision.Deny, d);
        }
    }

    [Fact]
    public void PathsOutsideTheAllowedRootAreDenied()
    {
        var policy = FsPolicy();
        var outside = new[]
        {
            "/etc/passwd",
            "/root/.ssh/known_hosts",
            "workspace/relative.txt",
            "/workspaceX/evil.txt",
        };
        foreach (var path in outside)
        {
            var (d, _) = policy.Evaluate(new ToolCall("read_file", new() { ["path"] = path }));
            Assert.Equal(Decision.Deny, d);
        }
    }

    [Fact]
    public void DenyPatternsWinOverAllow()
    {
        var policy = FsPolicy();
        var (d, reason) = policy.Evaluate(new ToolCall("read_file", new() { ["path"] = "/workspace/.env" }));
        Assert.Equal(Decision.Deny, d);
        Assert.Contains("deny", reason.ToLowerInvariant());
    }

    [Fact]
    public void DomainAllowListIsStrict()
    {
        var policy = FsPolicy();
        foreach (var domain in new[] { "api.external", "api.internal.evil.com", "evil.com", "API.INTERNAL" })
        {
            var (d, _) = policy.Evaluate(new ToolCall("http_get", new() { ["domain"] = domain }));
            Assert.Equal(Decision.Deny, d);
        }
        var (ok, _) = policy.Evaluate(new ToolCall("http_get", new() { ["domain"] = "api.internal" }));
        Assert.Equal(Decision.Allow, ok);
    }

    [Fact]
    public void HighRiskToolsRequireApprovalNeverSilentAllow()
    {
        var policy = FsPolicy();
        var (d, _) = policy.Evaluate(new ToolCall("delete_file", new() { ["path"] = "/workspace/tmp.txt" }));
        Assert.Equal(Decision.Approve, d);
    }

    [Fact]
    public void MissingOrOddArgumentsDoNotCrashOrBypass()
    {
        var policy = FsPolicy();
        var weirdArgs = new List<Dictionary<string, object?>>
        {
            new(),
            new() { ["path"] = "" },
            new() { ["path"] = null },
            new() { ["path"] = 12345 },
            new() { ["unexpected"] = "x" },
            new() { ["path"] = "/workspace/ok.txt", ["extra"] = new object() },
        };
        foreach (var args in weirdArgs)
        {
            var (d, _) = policy.Evaluate(new ToolCall("read_file", args));
            Assert.Contains(d, new[] { Decision.Allow, Decision.Deny, Decision.Approve });
            var hasPath = args.TryGetValue("path", out var pv) && pv is not null;
            var pathVal = hasPath ? pv!.ToString() : null;
            if (pathVal is null or "" or "12345")
                Assert.Equal(Decision.Deny, d);
        }
    }

    [Fact]
    public void RandomizedPathsNeverEscapeTheAllowRoot()
    {
        var rng = new Random(0);
        var policy = FsPolicy();
        var tokens = new[] { "workspace", "..", ".", "etc", "secrets", "ok.txt", ".env", "a", "id_rsa" };
        for (var i = 0; i < 5000; i++)
        {
            var depth = rng.Next(1, 7);
            var path = "/" + string.Join("/", Enumerable.Range(0, depth).Select(_ => tokens[rng.Next(tokens.Length)]));
            var (d, _) = policy.Evaluate(new ToolCall("read_file", new() { ["path"] = path }));
            if (d == Decision.Allow)
            {
                Assert.StartsWith("/workspace/", path);
                Assert.DoesNotContain(".env", path);
                Assert.DoesNotContain("secrets", path);
                Assert.DoesNotContain("id_rsa", path);
            }
        }
    }

    [Fact]
    public void CleanAuditChainVerifies()
    {
        var log = new AuditLog();
        for (var i = 0; i < 50; i++) log.Record($"tool-{i}", "allow", "ok");
        Assert.True(log.VerifyChain());
    }

    [Fact]
    public void EditingAnyAuditFieldIsDetected()
    {
        var rng = new Random(1);
        for (var iter = 0; iter < 200; iter++)
        {
            var log = new AuditLog();
            for (var i = 0; i < 10; i++) log.Record($"tool-{i}", i % 2 == 1 ? "allow" : "deny", "reason");
            var entries = log.Entries();
            var victim = entries[rng.Next(entries.Count)];
            victim.DecisionStr = victim.DecisionStr == "deny" ? "allow" : "deny";
            Assert.False(log.VerifyChain());
        }
    }

    [Fact]
    public void TruncatingOrReorderingTheChainIsDetected()
    {
        var log = new AuditLog();
        for (var i = 0; i < 10; i++) log.Record($"tool-{i}", "allow", "ok");

        // Reorder the actual backing chain (white-box): each entry's PrevHash pins its
        // position, so swapping two entries must break verification.
        var field = typeof(AuditLog).GetField("_entries",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var backing = (List<AuditEntry>)field!.GetValue(log)!;
        (backing[3], backing[6]) = (backing[6], backing[3]);
        Assert.False(log.VerifyChain());
    }

    [Fact]
    public void ASignatureFromTheWrongKeyIsRejected()
    {
        var log = new AuditLog();
        log.Record("t", "allow", "ok");
        var entry = log.Entries()[0];

        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var attacker = (Ed25519PrivateKeyParameters)gen.GenerateKeyPair().Private;
        var msg = System.Text.Encoding.UTF8.GetBytes(entry.EntryHash);
        var signer = new Ed25519Signer();
        signer.Init(true, attacker);
        signer.BlockUpdate(msg, 0, msg.Length);
        entry.Signature = Convert.ToHexString(signer.GenerateSignature()).ToLowerInvariant();

        Assert.False(log.VerifyChain());
    }

    [Fact]
    public void FlippingAByteInASignatureIsRejected()
    {
        var rng = new Random(2);
        for (var iter = 0; iter < 100; iter++)
        {
            var log = new AuditLog();
            log.Record("t", "allow", "ok");
            var entry = log.Entries()[0];
            var raw = Convert.FromHexString(entry.Signature);
            raw[rng.Next(raw.Length)] ^= (byte)(1 << rng.Next(8));
            entry.Signature = Convert.ToHexString(raw).ToLowerInvariant();
            Assert.False(log.VerifyChain());
        }
    }
}
