package agentguard

import (
	"errors"
	"testing"
)

func guardPolicy() Policy {
	return NewPolicy([]ToolPolicy{
		{Tool: "read_file", Allow: true, PathAllow: []string{"/data/*"}, PathDeny: []string{"/data/secrets/*", "*.env"}},
		{Tool: "http_get", Allow: true, DomainAllow: []string{"api.company.com"}},
		{Tool: "run_shell", Allow: true, RequireApproval: true},
	})
}

func makeGuard(approve bool) *AgentGuard {
	return NewAgentGuard(guardPolicy(), func(ToolCall, string) bool { return approve }, nil)
}

func isBlocked(err error) bool {
	var tbe *ToolBlockedError
	return errors.As(err, &tbe)
}

func TestUnlistedToolDeniedByDefault(t *testing.T) {
	g := makeGuard(false)
	_, err := g.Guard(NewToolCall("write_file", map[string]any{"path": "/data/x"}), func(ToolCall) any { return "wrote" })
	if !isBlocked(err) {
		t.Fatalf("expected ToolBlockedError, got %v", err)
	}
}

func TestAllowedPathExecutes(t *testing.T) {
	g := makeGuard(false)
	out, err := g.Guard(NewToolCall("read_file", map[string]any{"path": "/data/report.txt"}), func(ToolCall) any { return "content" })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "content" {
		t.Fatalf("expected content, got %v", out)
	}
}

func TestDeniedPathBlocksSecretExfil(t *testing.T) {
	g := makeGuard(false)
	_, err := g.Guard(NewToolCall("read_file", map[string]any{"path": "/data/secrets/key.env"}), func(ToolCall) any { return "leak" })
	if !isBlocked(err) {
		t.Fatalf("expected block, got %v", err)
	}
}

func TestDomainAllowList(t *testing.T) {
	g := makeGuard(false)
	_, err := g.Guard(NewToolCall("http_get", map[string]any{"domain": "evil.com"}), func(ToolCall) any { return "resp" })
	if !isBlocked(err) {
		t.Fatalf("expected block, got %v", err)
	}
}

func TestHighRiskRequiresApproval(t *testing.T) {
	denied := makeGuard(false)
	if _, err := denied.Guard(NewToolCall("run_shell", map[string]any{"cmd": "rm -rf /"}), func(ToolCall) any { return "ran" }); !isBlocked(err) {
		t.Fatalf("expected block when approval denied, got %v", err)
	}

	approved := makeGuard(true)
	out, err := approved.Guard(NewToolCall("run_shell", map[string]any{"cmd": "ls"}), func(ToolCall) any { return "listed" })
	if err != nil || out != "listed" {
		t.Fatalf("expected listed with no error, got %v, %v", out, err)
	}
}

func TestAuditLogIsSignedAndChained(t *testing.T) {
	g := makeGuard(false)
	_, _ = g.Guard(NewToolCall("write_file", map[string]any{"path": "/x"}), func(ToolCall) any { return "x" })
	_, _ = g.Guard(NewToolCall("read_file", map[string]any{"path": "/data/a"}), func(ToolCall) any { return "a" })
	if len(g.Audit.Entries()) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(g.Audit.Entries()))
	}
	if !g.Audit.VerifyChain() {
		t.Fatal("expected chain to verify")
	}
}

func TestPolicyEvaluateDecisions(t *testing.T) {
	p := guardPolicy()
	if d, _ := p.Evaluate(NewToolCall("read_file", map[string]any{"path": "/data/a"})); d != Allow {
		t.Fatalf("expected Allow, got %s", d)
	}
	if d, _ := p.Evaluate(NewToolCall("run_shell", nil)); d != Approve {
		t.Fatalf("expected Approve, got %s", d)
	}
	if d, _ := p.Evaluate(NewToolCall("nope", nil)); d != Deny {
		t.Fatalf("expected Deny, got %s", d)
	}
}
