// Adversarial fuzz suite: try to defeat the guard.
//
// AgentGuard makes two promises - deny-by-default authorization, and a tamper-evident
// audit trail. This suite is written from the attacker's side of both.

package com.agentguard;

import static org.junit.jupiter.api.Assertions.*;

import com.agentguard.Policy.Decision;
import com.agentguard.Policy.ToolCall;
import com.agentguard.Policy.ToolPolicy;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

class AdversarialFuzzTest {

    private static Policy fsPolicy() {
        return new Policy(List.of(
            new ToolPolicy("read_file", true, List.of("/workspace/*"),
                List.of("*.env*", "*secrets*", "*id_rsa*"), List.of(), false),
            new ToolPolicy("http_get", true, List.of(), List.of(), List.of("api.internal"), false),
            new ToolPolicy("delete_file", true, List.of(), List.of(), List.of(), true)
        ));
    }

    private static Map<String, Object> args(String k, Object v) {
        Map<String, Object> m = new HashMap<>();
        m.put(k, v);
        return m;
    }

    @Test
    void unknownToolsAreAlwaysDenied() {
        Policy policy = fsPolicy();
        for (String tool : new String[] {"exec", "eval", "rm", "read_fil", "READ_FILE", "http_post", ""}) {
            assertEquals(Decision.DENY,
                policy.evaluate(new ToolCall(tool, args("path", "/workspace/ok.txt"))).decision());
        }
    }

    @Test
    void toolNamesAreMatchedExactlyNotByPrefix() {
        Policy policy = fsPolicy();
        for (String tool : new String[] {"read_file2", "read_file ", " read_file", "read_file\n"}) {
            assertEquals(Decision.DENY,
                policy.evaluate(new ToolCall(tool, args("path", "/workspace/ok.txt"))).decision());
        }
    }

    @Test
    void secretPathsAreDeniedEvenInsideTheAllowedRoot() {
        Policy policy = fsPolicy();
        String[] hostile = {
            "/workspace/.env",
            "/workspace/secrets/prod.key",
            "/workspace/nested/id_rsa",
            "/workspace/sub/secrets/db.pem",
        };
        for (String path : hostile) {
            assertEquals(Decision.DENY, policy.evaluate(new ToolCall("read_file", args("path", path))).decision());
        }
    }

    @Test
    void pathsOutsideTheAllowedRootAreDenied() {
        Policy policy = fsPolicy();
        String[] outside = {
            "/etc/passwd",
            "/root/.ssh/known_hosts",
            "workspace/relative.txt",
            "/workspaceX/evil.txt",
        };
        for (String path : outside) {
            assertEquals(Decision.DENY, policy.evaluate(new ToolCall("read_file", args("path", path))).decision());
        }
    }

    @Test
    void denyPatternsWinOverAllow() {
        Policy policy = fsPolicy();
        Policy.Result r = policy.evaluate(new ToolCall("read_file", args("path", "/workspace/.env")));
        assertEquals(Decision.DENY, r.decision());
        assertTrue(r.reason().toLowerCase().contains("deny"));
    }

    @Test
    void domainAllowListIsStrict() {
        Policy policy = fsPolicy();
        for (String domain : new String[] {"api.external", "api.internal.evil.com", "evil.com", "API.INTERNAL"}) {
            assertEquals(Decision.DENY, policy.evaluate(new ToolCall("http_get", args("domain", domain))).decision());
        }
        assertEquals(Decision.ALLOW,
            policy.evaluate(new ToolCall("http_get", args("domain", "api.internal"))).decision());
    }

    @Test
    void highRiskToolsRequireApprovalNeverSilentAllow() {
        Policy policy = fsPolicy();
        assertEquals(Decision.APPROVE,
            policy.evaluate(new ToolCall("delete_file", args("path", "/workspace/tmp.txt"))).decision());
    }

    @Test
    void missingOrOddArgumentsDoNotCrashOrBypass() {
        Policy policy = fsPolicy();
        List<Map<String, Object>> weird = new ArrayList<>();
        weird.add(new HashMap<>());
        weird.add(args("path", ""));
        weird.add(args("path", null));
        weird.add(args("path", 12345));
        weird.add(args("unexpected", "x"));
        Map<String, Object> withExtra = args("path", "/workspace/ok.txt");
        withExtra.put("extra", new Object());
        weird.add(withExtra);

        for (Map<String, Object> a : weird) {
            Decision d = policy.evaluate(new ToolCall("read_file", a)).decision();
            assertTrue(d == Decision.ALLOW || d == Decision.DENY || d == Decision.APPROVE);
            Object p = a.get("path");
            boolean pathIsBad = p == null || "".equals(p) || Integer.valueOf(12345).equals(p);
            if (pathIsBad || !a.containsKey("path")) {
                assertEquals(Decision.DENY, d);
            }
        }
    }

    @Test
    void randomizedPathsNeverEscapeTheAllowRoot() {
        Random rng = new Random(0);
        Policy policy = fsPolicy();
        String[] tokens = {"workspace", "..", ".", "etc", "secrets", "ok.txt", ".env", "a", "id_rsa"};
        for (int i = 0; i < 5000; i++) {
            int depth = 1 + rng.nextInt(6);
            StringBuilder sb = new StringBuilder("/");
            for (int j = 0; j < depth; j++) {
                if (j > 0) sb.append('/');
                sb.append(tokens[rng.nextInt(tokens.length)]);
            }
            String path = sb.toString();
            if (policy.evaluate(new ToolCall("read_file", args("path", path))).decision() == Decision.ALLOW) {
                assertTrue(path.startsWith("/workspace/"));
                assertFalse(path.contains(".env"));
                assertFalse(path.contains("secrets"));
                assertFalse(path.contains("id_rsa"));
            }
        }
    }

    @Test
    void cleanAuditChainVerifies() {
        AuditLog log = new AuditLog();
        for (int i = 0; i < 50; i++) log.record("tool-" + i, "allow", "ok");
        assertTrue(log.verifyChain());
    }

    @Test
    void editingAnyAuditFieldIsDetected() {
        Random rng = new Random(1);
        for (int iter = 0; iter < 200; iter++) {
            AuditLog log = new AuditLog();
            for (int i = 0; i < 10; i++) log.record("tool-" + i, i % 2 == 1 ? "allow" : "deny", "reason");
            List<AuditLog.Entry> entries = log.entries();
            AuditLog.Entry victim = entries.get(rng.nextInt(entries.size()));
            victim.decision = victim.decision.equals("deny") ? "allow" : "deny";
            assertFalse(log.verifyChain());
        }
    }

    @Test
    void truncatingOrReorderingTheChainIsDetected() {
        AuditLog log = new AuditLog();
        for (int i = 0; i < 10; i++) log.record("tool-" + i, "allow", "ok");

        // Reorder the actual backing chain (white-box): each entry's prevHash pins its
        // position, so swapping two entries must break verification.
        List<AuditLog.Entry> backing = log.backing();
        AuditLog.Entry tmp = backing.get(3);
        backing.set(3, backing.get(6));
        backing.set(6, tmp);
        assertFalse(log.verifyChain());
    }

    @Test
    void aSignatureFromTheWrongKeyIsRejected() throws Exception {
        AuditLog log = new AuditLog();
        log.record("t", "allow", "ok");
        AuditLog.Entry entry = log.entries().get(0);

        KeyPair attacker = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(attacker.getPrivate());
        s.update(entry.entryHash.getBytes(StandardCharsets.UTF_8));
        entry.signature = AuditLog.toHex(s.sign());

        assertFalse(log.verifyChain());
    }

    @Test
    void flippingAByteInASignatureIsRejected() {
        Random rng = new Random(2);
        for (int iter = 0; iter < 100; iter++) {
            AuditLog log = new AuditLog();
            log.record("t", "allow", "ok");
            AuditLog.Entry entry = log.entries().get(0);
            byte[] raw = AuditLog.fromHex(entry.signature);
            raw[rng.nextInt(raw.length)] ^= (byte) (1 << rng.nextInt(8));
            entry.signature = AuditLog.toHex(raw);
            assertFalse(log.verifyChain());
        }
    }
}
