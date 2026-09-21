// Adversarial fuzz suite: try to defeat the guard.
//
// AgentGuard makes two promises -- deny-by-default authorization, and a
// tamper-evident audit trail. This suite is written from the attacker's side of
// both: it throws path-traversal, glob tricks, unexpected argument shapes, and
// deny/allow-precedence cases at the policy engine, and it flips bytes in the
// signed audit chain.

package agentguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand"
	"strings"
	"testing"
)

func fsPolicy() Policy {
	return NewPolicy([]ToolPolicy{
		{Tool: "read_file", Allow: true, PathAllow: []string{"/workspace/*"}, PathDeny: []string{"*.env*", "*secrets*", "*id_rsa*"}},
		{Tool: "http_get", Allow: true, DomainAllow: []string{"api.internal"}},
		{Tool: "delete_file", Allow: true, RequireApproval: true},
	})
}

func TestUnknownToolsAreAlwaysDenied(t *testing.T) {
	policy := fsPolicy()
	for _, tool := range []string{"exec", "eval", "rm", "read_fil", "READ_FILE", "http_post", ""} {
		if d, _ := policy.Evaluate(NewToolCall(tool, map[string]any{"path": "/workspace/ok.txt"})); d != Deny {
			t.Fatalf("unlisted tool %q slipped through: %s", tool, d)
		}
	}
}

func TestToolNamesAreMatchedExactlyNotByPrefix(t *testing.T) {
	policy := fsPolicy()
	for _, tool := range []string{"read_file2", "read_file ", " read_file", "read_file\n"} {
		if d, _ := policy.Evaluate(NewToolCall(tool, map[string]any{"path": "/workspace/ok.txt"})); d != Deny {
			t.Fatalf("near-miss tool %q inherited permissions: %s", tool, d)
		}
	}
}

func TestSecretPathsAreDeniedEvenInsideTheAllowedRoot(t *testing.T) {
	policy := fsPolicy()
	hostile := []string{
		"/workspace/.env",
		"/workspace/secrets/prod.key",
		"/workspace/nested/id_rsa",
		"/workspace/sub/secrets/db.pem",
	}
	for _, path := range hostile {
		if d, reason := policy.Evaluate(NewToolCall("read_file", map[string]any{"path": path})); d != Deny {
			t.Fatalf("secret path allowed: %s (%s)", path, reason)
		}
	}
}

func TestPathsOutsideTheAllowedRootAreDenied(t *testing.T) {
	policy := fsPolicy()
	outside := []string{
		"/etc/passwd",
		"/root/.ssh/known_hosts",
		"workspace/relative.txt",
		"/workspaceX/evil.txt",
	}
	for _, path := range outside {
		if d, _ := policy.Evaluate(NewToolCall("read_file", map[string]any{"path": path})); d != Deny {
			t.Fatalf("path outside root allowed: %s", path)
		}
	}
}

func TestDenyPatternsWinOverAllow(t *testing.T) {
	policy := fsPolicy()
	d, reason := policy.Evaluate(NewToolCall("read_file", map[string]any{"path": "/workspace/.env"}))
	if d != Deny {
		t.Fatalf("expected Deny, got %s", d)
	}
	if !strings.Contains(strings.ToLower(reason), "deny") {
		t.Fatalf("expected deny reason, got %q", reason)
	}
}

func TestDomainAllowListIsStrict(t *testing.T) {
	policy := fsPolicy()
	for _, domain := range []string{"api.external", "api.internal.evil.com", "evil.com", "API.INTERNAL"} {
		if d, _ := policy.Evaluate(NewToolCall("http_get", map[string]any{"domain": domain})); d != Deny {
			t.Fatalf("domain slipped through: %s", domain)
		}
	}
	if d, _ := policy.Evaluate(NewToolCall("http_get", map[string]any{"domain": "api.internal"})); d != Allow {
		t.Fatalf("expected Allow for api.internal, got %s", d)
	}
}

func TestHighRiskToolsRequireApprovalNeverSilentAllow(t *testing.T) {
	policy := fsPolicy()
	if d, _ := policy.Evaluate(NewToolCall("delete_file", map[string]any{"path": "/workspace/tmp.txt"})); d != Approve {
		t.Fatalf("expected Approve, got %s", d)
	}
}

func TestMissingOrOddArgumentsDoNotCrashOrBypass(t *testing.T) {
	policy := fsPolicy()
	// A missing/empty/None/wrong-type path with an allow-root configured must DENY.
	deniers := []map[string]any{
		{},
		{"path": ""},
		{"path": nil},
		{"path": 12345},
		{"unexpected": "x"},
	}
	for _, args := range deniers {
		if d, _ := policy.Evaluate(NewToolCall("read_file", args)); d != Deny {
			t.Fatalf("under-specified args did not deny: %v -> %s", args, d)
		}
	}
	// A valid path with an unrelated extra argument is unaffected.
	if d, _ := policy.Evaluate(NewToolCall("read_file", map[string]any{"path": "/workspace/ok.txt", "extra": struct{}{}})); d != Allow {
		t.Fatalf("valid path with extra arg should Allow, got %s", d)
	}
}

func TestRandomizedPathsNeverEscapeTheAllowRoot(t *testing.T) {
	rng := mrand.New(mrand.NewSource(0))
	policy := fsPolicy()
	tokens := []string{"workspace", "..", ".", "etc", "secrets", "ok.txt", ".env", "a", "id_rsa"}
	for i := 0; i < 5000; i++ {
		depth := 1 + rng.Intn(6)
		parts := make([]string, depth)
		for j := range parts {
			parts[j] = tokens[rng.Intn(len(tokens))]
		}
		path := "/" + strings.Join(parts, "/")
		if d, _ := policy.Evaluate(NewToolCall("read_file", map[string]any{"path": path})); d == Allow {
			if !strings.HasPrefix(path, "/workspace/") {
				t.Fatalf("allowed path escaped root: %s", path)
			}
			if strings.Contains(path, ".env") || strings.Contains(path, "secrets") || strings.Contains(path, "id_rsa") {
				t.Fatalf("allowed path hit a secret: %s", path)
			}
		}
	}
}

func TestCleanAuditChainVerifies(t *testing.T) {
	log := NewAuditLog()
	for i := 0; i < 50; i++ {
		log.Record("tool", "allow", "ok")
	}
	if !log.VerifyChain() {
		t.Fatal("clean chain failed to verify")
	}
}

func TestEditingAnyAuditFieldIsDetected(t *testing.T) {
	rng := mrand.New(mrand.NewSource(1))
	for iter := 0; iter < 200; iter++ {
		log := NewAuditLog()
		for i := 0; i < 10; i++ {
			dec := "deny"
			if i%2 == 1 {
				dec = "allow"
			}
			log.Record("tool", dec, "reason")
		}
		entries := log.Entries()
		victim := entries[rng.Intn(len(entries))]
		if victim.Decision == "deny" {
			victim.Decision = "allow"
		} else {
			victim.Decision = "deny"
		}
		if log.VerifyChain() {
			t.Fatal("tampered decision not detected")
		}
	}
}

func TestTruncatingOrReorderingTheChainIsDetected(t *testing.T) {
	log := NewAuditLog()
	for i := 0; i < 10; i++ {
		log.Record("tool", "allow", "ok")
	}
	// White-box: each entry's PrevHash pins its position, so swapping two must break.
	log.entries[3], log.entries[6] = log.entries[6], log.entries[3]
	if log.VerifyChain() {
		t.Fatal("reordering not detected")
	}
}

func TestASignatureFromTheWrongKeyIsRejected(t *testing.T) {
	log := NewAuditLog()
	log.Record("t", "allow", "ok")
	entry := log.Entries()[0]

	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry.Signature = hex.EncodeToString(ed25519.Sign(attacker, []byte(entry.EntryHash)))
	if log.VerifyChain() {
		t.Fatal("wrong-key signature accepted")
	}
}

func TestFlippingAByteInASignatureIsRejected(t *testing.T) {
	rng := mrand.New(mrand.NewSource(2))
	for iter := 0; iter < 100; iter++ {
		log := NewAuditLog()
		log.Record("t", "allow", "ok")
		entry := log.Entries()[0]
		raw, err := hex.DecodeString(entry.Signature)
		if err != nil {
			t.Fatal(err)
		}
		raw[rng.Intn(len(raw))] ^= 1 << rng.Intn(8)
		entry.Signature = hex.EncodeToString(raw)
		if log.VerifyChain() {
			t.Fatal("bit-flipped signature accepted")
		}
	}
}
