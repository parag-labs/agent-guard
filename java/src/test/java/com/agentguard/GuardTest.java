package com.agentguard;

import static org.junit.jupiter.api.Assertions.*;

import com.agentguard.Policy.Decision;
import com.agentguard.Policy.ToolCall;
import com.agentguard.Policy.ToolPolicy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiPredicate;
import org.junit.jupiter.api.Test;

class GuardTest {

    private static Policy makePolicy() {
        return new Policy(List.of(
            new ToolPolicy("read_file", true, List.of("/data/*"), List.of("/data/secrets/*", "*.env"), List.of(), false),
            new ToolPolicy("http_get", true, List.of(), List.of(), List.of("api.company.com"), false),
            new ToolPolicy("run_shell", true, List.of(), List.of(), List.of(), true)
        ));
    }

    private static Guard makeGuard(boolean approve) {
        BiPredicate<ToolCall, String> cb = (c, r) -> approve;
        return new Guard(makePolicy(), cb);
    }

    private static Map<String, Object> args(String k, Object v) {
        Map<String, Object> m = new HashMap<>();
        m.put(k, v);
        return m;
    }

    @Test
    void unlistedToolDeniedByDefault() {
        Guard g = makeGuard(false);
        assertThrows(Guard.ToolBlockedException.class,
            () -> g.execute(new ToolCall("write_file", args("path", "/data/x")), c -> "wrote"));
    }

    @Test
    void allowedPathExecutes() {
        Guard g = makeGuard(false);
        Object out = g.execute(new ToolCall("read_file", args("path", "/data/report.txt")), c -> "content");
        assertEquals("content", out);
    }

    @Test
    void deniedPathBlocksSecretExfil() {
        Guard g = makeGuard(false);
        assertThrows(Guard.ToolBlockedException.class,
            () -> g.execute(new ToolCall("read_file", args("path", "/data/secrets/key.env")), c -> "leak"));
    }

    @Test
    void domainAllowList() {
        Guard g = makeGuard(false);
        assertThrows(Guard.ToolBlockedException.class,
            () -> g.execute(new ToolCall("http_get", args("domain", "evil.com")), c -> "resp"));
    }

    @Test
    void highRiskRequiresApproval() {
        Guard denied = makeGuard(false);
        assertThrows(Guard.ToolBlockedException.class,
            () -> denied.execute(new ToolCall("run_shell", args("cmd", "rm -rf /")), c -> "ran"));

        Guard approved = makeGuard(true);
        assertEquals("listed",
            approved.execute(new ToolCall("run_shell", args("cmd", "ls")), c -> "listed"));
    }

    @Test
    void auditLogIsSignedAndChained() {
        Guard g = makeGuard(false);
        try {
            g.execute(new ToolCall("write_file", args("path", "/x")), c -> "x");
        } catch (Guard.ToolBlockedException e) {
            // expected
        }
        g.execute(new ToolCall("read_file", args("path", "/data/a")), c -> "a");
        assertEquals(2, g.audit.entries().size());
        assertTrue(g.audit.verifyChain());
    }

    @Test
    void policyEvaluateDecisions() {
        Policy p = makePolicy();
        assertEquals(Decision.ALLOW, p.evaluate(new ToolCall("read_file", args("path", "/data/a"))).decision());
        assertEquals(Decision.APPROVE, p.evaluate(new ToolCall("run_shell", Map.of())).decision());
        assertEquals(Decision.DENY, p.evaluate(new ToolCall("nope", Map.of())).decision());
    }
}
