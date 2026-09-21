package agentguard

import "testing"

func TestPolicyFromDictBuildsToolsAndDefaults(t *testing.T) {
	// Uses the []any tools shape and omits optional fields to exercise defaults.
	p := PolicyFromDict(map[string]any{
		"tools": []any{
			map[string]any{"tool": "read_file", "allow": true, "path_allow": []any{"/data/*"}},
			map[string]any{"tool": "audit"}, // allow omitted -> defaults false
		},
	})
	if d, _ := p.Evaluate(NewToolCall("read_file", map[string]any{"path": "/data/x"})); d != Allow {
		t.Fatalf("expected Allow, got %s", d)
	}
	// allow defaulted to false, so the tool is denied by default.
	if d, _ := p.Evaluate(NewToolCall("audit", nil)); d != Deny {
		t.Fatalf("expected Deny for allow-defaulted tool, got %s", d)
	}
}

func TestPolicyFromDictEmptySpecDeniesEverything(t *testing.T) {
	p := PolicyFromDict(map[string]any{})
	if d, _ := p.Evaluate(NewToolCall("anything", nil)); d != Deny {
		t.Fatalf("empty policy should deny, got %s", d)
	}
	if len(p.Tools) != 0 {
		t.Fatalf("expected no tools, got %d", len(p.Tools))
	}
}

func TestNewToolCallDefaultsArgsToEmpty(t *testing.T) {
	call := NewToolCall("x", nil)
	if call.Args == nil {
		t.Fatal("Args should default to a non-nil map")
	}
	// A tool with a required path but no args must still deny cleanly, not panic.
	p := NewPolicy([]ToolPolicy{{Tool: "x", Allow: true, PathAllow: []string{"/ok/*"}}})
	if d, _ := p.Evaluate(call); d != Deny {
		t.Fatalf("expected Deny, got %s", d)
	}
}

func TestStarGlobMatchesAcrossSlashes(t *testing.T) {
	// Python fnmatch '*' matches path separators too -- that is why '*secrets*'
	// catches a nested secrets directory.
	if !fnmatch("/workspace/sub/secrets/db.pem", "*secrets*") {
		t.Fatal("expected '*secrets*' to match a nested path")
	}
	if fnmatch("/workspaceX/evil.txt", "/workspace/*") {
		t.Fatal("prefix look-alike should not match /workspace/*")
	}
}

func TestQuestionMarkGlobMatchesSingleChar(t *testing.T) {
	if !fnmatch("/data/a.txt", "/data/?.txt") {
		t.Fatal("'?' should match a single char")
	}
	if fnmatch("/data/ab.txt", "/data/?.txt") {
		t.Fatal("'?' should not match two chars")
	}
}

func TestPathDenyWithoutAllowRootStillEnforced(t *testing.T) {
	// A tool with only a deny list: clean paths pass, denied globs are blocked.
	p := NewPolicy([]ToolPolicy{{Tool: "read_file", Allow: true, PathDeny: []string{"*.env"}}})
	if d, _ := p.Evaluate(NewToolCall("read_file", map[string]any{"path": "/anywhere/file.txt"})); d != Allow {
		t.Fatalf("clean path with only a deny list should Allow, got %s", d)
	}
	if d, _ := p.Evaluate(NewToolCall("read_file", map[string]any{"path": "/anywhere/prod.env"})); d != Deny {
		t.Fatalf("deny glob should block, got %s", d)
	}
}

func TestDomainRequiredButMissingIsDenied(t *testing.T) {
	p := NewPolicy([]ToolPolicy{{Tool: "http_get", Allow: true, DomainAllow: []string{"api.internal"}}})
	if d, _ := p.Evaluate(NewToolCall("http_get", nil)); d != Deny {
		t.Fatalf("a domain-constrained tool with no domain must Deny, got %s", d)
	}
}

func TestNilApprovalCallbackDefaultsToDeny(t *testing.T) {
	// No approval callback supplied -> the safe default denies approval-gated calls.
	g := NewAgentGuard(guardPolicy(), nil, nil)
	if _, err := g.Guard(NewToolCall("run_shell", map[string]any{"cmd": "ls"}), func(ToolCall) any { return "ran" }); !isBlocked(err) {
		t.Fatalf("expected default-deny for approval-gated tool, got %v", err)
	}
}
