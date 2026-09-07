// Signed, append-only audit log for every tool-call decision.
//
// Each entry is chained (prevHash) and Ed25519-signed, so the audit trail is
// tamper-evident -- you can prove after the fact exactly what the agent was allowed
// to do and why. The JDK's built-in "Ed25519" provider (JDK 15+) matches the
// primitive the Python and C# ports use.

package com.agentguard;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

public final class AuditLog {

    /** One audit line. Fields are mutable so tests (and tampering) can mutate them
     * after the fact - the whole point is that verification catches any such edit. */
    public static final class Entry {
        public double ts;
        public String tool;
        public String decision;
        public String reason;
        public String prevHash;
        public String entryHash;
        public String signature;

        Entry(double ts, String tool, String decision, String reason,
              String prevHash, String entryHash, String signature) {
            this.ts = ts;
            this.tool = tool;
            this.decision = decision;
            this.reason = reason;
            this.prevHash = prevHash;
            this.entryHash = entryHash;
            this.signature = signature;
        }
    }

    private final PrivateKey priv;
    private final PublicKey pub;
    private final List<Entry> entries = new ArrayList<>();

    public AuditLog() {
        try {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            this.priv = kp.getPrivate();
            this.pub = kp.getPublic();
        } catch (Exception e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
    }

    public PublicKey publicKey() {
        return pub;
    }

    public Entry record(String tool, String decision, String reason) {
        String prevHash = entries.isEmpty() ? "" : entries.get(entries.size() - 1).entryHash;
        double ts = System.currentTimeMillis() / 1000.0;
        String entryHash = sha256Hex(canonical(ts, tool, decision, reason, prevHash));
        String signature = signHex(entryHash);
        Entry entry = new Entry(ts, tool, decision, reason, prevHash, entryHash, signature);
        entries.add(entry);
        return entry;
    }

    public List<Entry> entries() {
        return new ArrayList<>(entries);
    }

    /** Package-visible backing list, for the white-box reorder test. */
    List<Entry> backing() {
        return entries;
    }

    public boolean verifyChain() {
        String prev = "";
        for (Entry e : entries) {
            String expected = sha256Hex(canonical(e.ts, e.tool, e.decision, e.reason, prev));
            if (!expected.equals(e.entryHash)) return false;
            if (!verify(e.entryHash, e.signature)) return false;
            prev = e.entryHash;
        }
        return true;
    }

    // Canonical, sorted-key form matching the reference (decision, prev_hash, reason,
    // tool, ts). Only needs to be self-consistent between record and verifyChain.
    private static String canonical(double ts, String tool, String decision, String reason, String prevHash) {
        return "{"
            + "\"decision\": " + jsonStr(decision) + ", "
            + "\"prev_hash\": " + jsonStr(prevHash) + ", "
            + "\"reason\": " + jsonStr(reason) + ", "
            + "\"tool\": " + jsonStr(tool) + ", "
            + "\"ts\": " + ts
            + "}";
    }

    private static String jsonStr(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') sb.append("\\\"");
            else if (c == '\\') sb.append("\\\\");
            else sb.append(c);
        }
        return sb.append('"').toString();
    }

    private static String sha256Hex(String s) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            return toHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String signHex(String message) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(priv);
            s.update(message.getBytes(StandardCharsets.UTF_8));
            return toHex(s.sign());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private boolean verify(String message, String signatureHex) {
        try {
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(pub);
            v.update(message.getBytes(StandardCharsets.UTF_8));
            return v.verify(fromHex(signatureHex));
        } catch (Exception e) {
            return false;
        }
    }

    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static byte[] fromHex(String hex) {
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
