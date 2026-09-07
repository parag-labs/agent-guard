// Signed, append-only audit log for every tool-call decision.
//
// Each entry is chained (PrevHash) and Ed25519-signed, so the audit trail is
// tamper-evident -- you can prove after the fact exactly what the agent was allowed
// to do and why.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace AgentGuard;

/// <summary>One audit line. Fields are mutable so tests (and tampering) can mutate them
/// after the fact - the whole point is that verification catches any such edit.</summary>
public sealed class AuditEntry
{
    public double Ts { get; set; }
    public string Tool { get; set; }
    public string DecisionStr { get; set; }
    public string Reason { get; set; }
    public string PrevHash { get; set; }
    public string EntryHash { get; set; }
    public string Signature { get; set; }

    public AuditEntry(double ts, string tool, string decision, string reason,
                      string prevHash, string entryHash, string signature)
    {
        Ts = ts;
        Tool = tool;
        DecisionStr = decision;
        Reason = reason;
        PrevHash = prevHash;
        EntryHash = entryHash;
        Signature = signature;
    }
}

public sealed class AuditLog
{
    private readonly Ed25519PrivateKeyParameters _priv;
    private readonly Ed25519PublicKeyParameters _pub;
    private readonly List<AuditEntry> _entries = new();

    public AuditLog(Ed25519PrivateKeyParameters? priv = null)
    {
        if (priv is null)
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var kp = gen.GenerateKeyPair();
            _priv = (Ed25519PrivateKeyParameters)kp.Private;
        }
        else
        {
            _priv = priv;
        }
        _pub = _priv.GeneratePublicKey();
    }

    public Ed25519PublicKeyParameters PublicKey => _pub;

    public AuditEntry Record(string tool, string decision, string reason)
    {
        var prevHash = _entries.Count > 0 ? _entries[^1].EntryHash : "";
        var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
        var entryHash = Sha256Hex(Canonical(ts, tool, decision, reason, prevHash));
        var signature = SignHex(entryHash);
        var entry = new AuditEntry(ts, tool, decision, reason, prevHash, entryHash, signature);
        _entries.Add(entry);
        return entry;
    }

    public List<AuditEntry> Entries() => new(_entries);

    public bool VerifyChain()
    {
        var prev = "";
        foreach (var e in _entries)
        {
            var expected = Sha256Hex(Canonical(e.Ts, e.Tool, e.DecisionStr, e.Reason, prev));
            if (expected != e.EntryHash) return false;
            if (!Verify(e.EntryHash, e.Signature)) return false;
            prev = e.EntryHash;
        }
        return true;
    }

    // Canonical, sorted-key form matching the reference (decision, prev_hash, reason,
    // tool, ts). Only needs to be self-consistent between Record and VerifyChain.
    private static string Canonical(double ts, string tool, string decision, string reason, string prevHash)
    {
        return "{" +
            $"\"decision\": {JsonStr(decision)}, " +
            $"\"prev_hash\": {JsonStr(prevHash)}, " +
            $"\"reason\": {JsonStr(reason)}, " +
            $"\"tool\": {JsonStr(tool)}, " +
            $"\"ts\": {ts.ToString("R", CultureInfo.InvariantCulture)}" +
            "}";
    }

    private static string JsonStr(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.Append('"').ToString();
    }

    private static string Sha256Hex(string s)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    private string SignHex(string message)
    {
        var msg = Encoding.UTF8.GetBytes(message);
        var signer = new Ed25519Signer();
        signer.Init(true, _priv);
        signer.BlockUpdate(msg, 0, msg.Length);
        return Convert.ToHexString(signer.GenerateSignature()).ToLowerInvariant();
    }

    private bool Verify(string message, string signatureHex)
    {
        try
        {
            var msg = Encoding.UTF8.GetBytes(message);
            var sig = Convert.FromHexString(signatureHex);
            var verifier = new Ed25519Signer();
            verifier.Init(false, _pub);
            verifier.BlockUpdate(msg, 0, msg.Length);
            return verifier.VerifySignature(sig);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
