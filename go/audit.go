// Signed, append-only audit log for every tool-call decision.
//
// Each entry is chained (PrevHash) and Ed25519-signed, so the audit trail is
// tamper-evident -- you can prove after the fact exactly what the agent was
// allowed to do and why.

package agentguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// AuditEntry is one line in the audit log. Fields are exported and mutable so
// tests (and tampering) can mutate them after the fact -- the whole point is that
// verification catches any such edit.
type AuditEntry struct {
	Ts        float64
	Tool      string
	Decision  string
	Reason    string
	PrevHash  string
	EntryHash string
	Signature string
}

// AuditLog is a signed, append-only, hash-chained record of tool-call decisions.
// Each entry commits to the previous entry's hash and is individually Ed25519
// signed, making the trail tamper-evident.
type AuditLog struct {
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	entries []*AuditEntry
}

// NewAuditLog creates an audit log with a freshly generated Ed25519 key.
func NewAuditLog() *AuditLog {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &AuditLog{priv: priv, pub: pub}
}

// NewAuditLogWithKey creates an audit log that signs with the given private key.
func NewAuditLogWithKey(priv ed25519.PrivateKey) *AuditLog {
	return &AuditLog{priv: priv, pub: priv.Public().(ed25519.PublicKey)}
}

// PublicKey returns the verifying key for this log's signatures.
func (a *AuditLog) PublicKey() ed25519.PublicKey { return a.pub }

// Record appends a signed, chained entry for a tool-call decision and returns it.
func (a *AuditLog) Record(tool, decision, reason string) *AuditEntry {
	prevHash := ""
	if n := len(a.entries); n > 0 {
		prevHash = a.entries[n-1].EntryHash
	}
	ts := float64(time.Now().UnixMilli()) / 1000.0
	entryHash := sha256Hex(canonical(ts, tool, decision, reason, prevHash))
	signature := hex.EncodeToString(ed25519.Sign(a.priv, []byte(entryHash)))
	entry := &AuditEntry{
		Ts:        ts,
		Tool:      tool,
		Decision:  decision,
		Reason:    reason,
		PrevHash:  prevHash,
		EntryHash: entryHash,
		Signature: signature,
	}
	a.entries = append(a.entries, entry)
	return entry
}

// Entries returns a shallow copy of the entry list; the entries themselves are
// shared, so mutating a returned entry mutates the log (which verification detects).
func (a *AuditLog) Entries() []*AuditEntry {
	out := make([]*AuditEntry, len(a.entries))
	copy(out, a.entries)
	return out
}

// VerifyChain recomputes every entry's hash and checks its signature and its link
// to the previous entry, returning false if anything has been altered, reordered,
// truncated, or re-signed with the wrong key.
func (a *AuditLog) VerifyChain() bool {
	prev := ""
	for _, e := range a.entries {
		expected := sha256Hex(canonical(e.Ts, e.Tool, e.Decision, e.Reason, prev))
		if expected != e.EntryHash {
			return false
		}
		sig, err := hex.DecodeString(e.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(a.pub, []byte(e.EntryHash), sig) {
			return false
		}
		prev = e.EntryHash
	}
	return true
}

// canonical renders the sorted-key JSON form the reference hashes over:
// {"decision": ..., "prev_hash": ..., "reason": ..., "tool": ..., "ts": ...}. It
// only needs to be self-consistent between Record and VerifyChain.
func canonical(ts float64, tool, decision, reason, prevHash string) string {
	return "{" +
		`"decision": ` + jsonStr(decision) + ", " +
		`"prev_hash": ` + jsonStr(prevHash) + ", " +
		`"reason": ` + jsonStr(reason) + ", " +
		`"tool": ` + jsonStr(tool) + ", " +
		`"ts": ` + strconv.FormatFloat(ts, 'g', -1, 64) +
		"}"
}

func jsonStr(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
