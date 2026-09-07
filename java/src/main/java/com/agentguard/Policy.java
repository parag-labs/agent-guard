// AgentGuard policy engine: deny-by-default, least-privilege tool authorization.
//
// Every agent tool call is evaluated against a policy before execution. Decisions are
// ALLOW, DENY, or APPROVE (human-in-the-loop for high-risk actions).

package com.agentguard;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public final class Policy {

    public enum Decision {
        ALLOW("allow"), DENY("deny"), APPROVE("approve");

        public final String value;
        Decision(String value) { this.value = value; }
    }

    public record ToolCall(String tool, Map<String, Object> args) {
        public ToolCall(String tool) { this(tool, Map.of()); }
    }

    public static final class ToolPolicy {
        public final String tool;
        public final boolean allow;
        public final List<String> pathAllow;
        public final List<String> pathDeny;
        public final List<String> domainAllow;
        public final boolean requireApproval;

        public ToolPolicy(String tool, boolean allow, List<String> pathAllow,
                          List<String> pathDeny, List<String> domainAllow, boolean requireApproval) {
            this.tool = tool;
            this.allow = allow;
            this.pathAllow = pathAllow;
            this.pathDeny = pathDeny;
            this.domainAllow = domainAllow;
            this.requireApproval = requireApproval;
        }
    }

    public record Result(Decision decision, String reason) {}

    private final Map<String, ToolPolicy> tools = new HashMap<>();

    public Policy(List<ToolPolicy> policies) {
        for (ToolPolicy tp : policies) tools.put(tp.tool, tp);
    }

    public Result evaluate(ToolCall call) {
        ToolPolicy tp = tools.get(call.tool());
        if (tp == null || !tp.allow) {
            return new Result(Decision.DENY,
                "tool '" + call.tool() + "' not in allow-list (deny-by-default)");
        }

        String path = argString(call, "path");
        // Deny-by-default extends to constrained arguments: if a tool is restricted to
        // certain paths but the call provides none, we can't prove it's in bounds, so we
        // refuse rather than fall through to allow.
        if (!tp.pathAllow.isEmpty() && path.isEmpty()) {
            return new Result(Decision.DENY,
                "tool '" + call.tool() + "' requires a path within its allowed set");
        }
        if (!path.isEmpty()) {
            for (String pattern : tp.pathDeny) {
                if (fnmatch(path, pattern)) {
                    return new Result(Decision.DENY,
                        "path '" + path + "' matches deny pattern '" + pattern + "'");
                }
            }
            if (!tp.pathAllow.isEmpty() && tp.pathAllow.stream().noneMatch(p -> fnmatch(path, p))) {
                return new Result(Decision.DENY, "path '" + path + "' not in allowed paths");
            }
        }

        String domain = argString(call, "domain");
        if (!tp.domainAllow.isEmpty() && domain.isEmpty()) {
            return new Result(Decision.DENY,
                "tool '" + call.tool() + "' requires a domain within its allowed set");
        }
        if (!domain.isEmpty() && !tp.domainAllow.isEmpty() && !tp.domainAllow.contains(domain)) {
            return new Result(Decision.DENY, "domain '" + domain + "' not in allow-list");
        }

        if (tp.requireApproval) {
            return new Result(Decision.APPROVE, "tool '" + call.tool() + "' requires human approval");
        }

        return new Result(Decision.ALLOW, "ok");
    }

    private static String argString(ToolCall call, String key) {
        Object v = call.args().get(key);
        return v != null ? v.toString() : "";
    }

    // --- glob matching with Python fnmatch semantics (case-sensitive, full match) ---

    private static final Map<String, Pattern> CACHE = new HashMap<>();

    private static boolean fnmatch(String name, String pattern) {
        Pattern rx = CACHE.computeIfAbsent(pattern,
            p -> Pattern.compile(translate(p), Pattern.DOTALL));
        return rx.matcher(name).matches();
    }

    private static String translate(String pat) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < pat.length()) {
            char c = pat.charAt(i++);
            switch (c) {
                case '*' -> sb.append(".*");
                case '?' -> sb.append('.');
                case '[' -> {
                    int j = i;
                    if (j < pat.length() && (pat.charAt(j) == '!' || pat.charAt(j) == '^')) j++;
                    if (j < pat.length() && pat.charAt(j) == ']') j++;
                    while (j < pat.length() && pat.charAt(j) != ']') j++;
                    if (j >= pat.length()) {
                        sb.append("\\[");
                    } else {
                        String inner = pat.substring(i, j).replace("\\", "\\\\");
                        i = j + 1;
                        if (inner.startsWith("!")) inner = "^" + inner.substring(1);
                        sb.append('[').append(inner).append(']');
                    }
                }
                default -> sb.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return sb.toString();
    }
}
