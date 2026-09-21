// Package agentguard is a zero-trust runtime for AI agents: a deny-by-default
// policy engine, a human-approval gate for high-risk tools, and an Ed25519-signed,
// hash-chained audit log. This file is the policy engine: every agent tool call is
// evaluated against a policy before execution and resolves to ALLOW, DENY, or
// APPROVE (human-in-the-loop for high-risk actions).
package agentguard

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Decision is the outcome of evaluating a tool call against a policy.
type Decision string

const (
	// Allow permits the tool call to execute.
	Allow Decision = "allow"
	// Deny blocks the tool call.
	Deny Decision = "deny"
	// Approve requires human approval before the call may execute.
	Approve Decision = "approve"
)

// ToolCall is a single request by the agent to invoke a named tool with arguments.
type ToolCall struct {
	Tool string
	Args map[string]any
}

// NewToolCall builds a ToolCall, defaulting Args to an empty map when nil.
func NewToolCall(tool string, args map[string]any) ToolCall {
	if args == nil {
		args = map[string]any{}
	}
	return ToolCall{Tool: tool, Args: args}
}

// ToolPolicy is the set of constraints attached to one allowed tool. The zero
// value denies everything: Allow is false and every constraint list is empty.
type ToolPolicy struct {
	Tool            string
	Allow           bool
	PathAllow       []string // glob patterns a path argument must match
	PathDeny        []string // glob patterns a path argument must not match
	DomainAllow     []string // exact domains a domain argument must be one of
	RequireApproval bool
}

// Policy is a deny-by-default authorization table: only explicitly allowed
// tools, within their declared constraints, ever pass.
type Policy struct {
	Tools map[string]ToolPolicy
}

// NewPolicy builds a Policy from a slice of tool policies, keyed by tool name.
func NewPolicy(tools []ToolPolicy) Policy {
	m := make(map[string]ToolPolicy, len(tools))
	for _, t := range tools {
		m[t.Tool] = t
	}
	return Policy{Tools: m}
}

// PolicyFromDict builds a Policy from a decoded spec of the same shape the Python
// reference accepts: {"tools": [{"tool": ..., "allow": ..., ...}, ...]}. Missing
// fields default the same way (allow=false, empty constraint lists,
// require_approval=false).
func PolicyFromDict(spec map[string]any) Policy {
	tools := []ToolPolicy{}
	switch raw := spec["tools"].(type) {
	case []map[string]any:
		for _, t := range raw {
			tools = append(tools, toolPolicyFromMap(t))
		}
	case []any:
		for _, ti := range raw {
			if t, ok := ti.(map[string]any); ok {
				tools = append(tools, toolPolicyFromMap(t))
			}
		}
	}
	return NewPolicy(tools)
}

func toolPolicyFromMap(t map[string]any) ToolPolicy {
	return ToolPolicy{
		Tool:            asString(t["tool"]),
		Allow:           asBool(t["allow"]),
		PathAllow:       asStringSlice(t["path_allow"]),
		PathDeny:        asStringSlice(t["path_deny"]),
		DomainAllow:     asStringSlice(t["domain_allow"]),
		RequireApproval: asBool(t["require_approval"]),
	}
}

// Evaluate applies the deny-by-default policy to a tool call and returns the
// decision plus a human-readable reason.
func (p Policy) Evaluate(call ToolCall) (Decision, string) {
	tp, ok := p.Tools[call.Tool]
	if !ok || !tp.Allow {
		return Deny, fmt.Sprintf("tool '%s' not in allow-list (deny-by-default)", call.Tool)
	}

	path := argString(call, "path")
	// Deny-by-default extends to constrained arguments: if a tool is restricted
	// to certain paths but the call provides none, we can't prove it's in bounds,
	// so we refuse rather than fall through to allow.
	if len(tp.PathAllow) > 0 && path == "" {
		return Deny, fmt.Sprintf("tool '%s' requires a path within its allowed set", call.Tool)
	}
	if path != "" {
		for _, pattern := range tp.PathDeny {
			if fnmatch(path, pattern) {
				return Deny, fmt.Sprintf("path '%s' matches deny pattern '%s'", path, pattern)
			}
		}
		if len(tp.PathAllow) > 0 && !anyMatch(path, tp.PathAllow) {
			return Deny, fmt.Sprintf("path '%s' not in allowed paths", path)
		}
	}

	domain := argString(call, "domain")
	if len(tp.DomainAllow) > 0 && domain == "" {
		return Deny, fmt.Sprintf("tool '%s' requires a domain within its allowed set", call.Tool)
	}
	if domain != "" && len(tp.DomainAllow) > 0 && !contains(tp.DomainAllow, domain) {
		return Deny, fmt.Sprintf("domain '%s' not in allow-list", domain)
	}

	if tp.RequireApproval {
		return Approve, fmt.Sprintf("tool '%s' requires human approval", call.Tool)
	}
	return Allow, "ok"
}

// argString mirrors the reference's str(args.get(key)) with None -> "": a missing
// or nil value becomes the empty string; any other value is formatted like Python's
// str (e.g. the int 12345 becomes "12345").
func argString(call ToolCall, key string) string {
	v, ok := call.Args[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func anyMatch(path string, patterns []string) bool {
	for _, p := range patterns {
		if fnmatch(path, p) {
			return true
		}
	}
	return false
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func asBool(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func asStringSlice(v any) []string {
	switch xs := v.(type) {
	case []string:
		return xs
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			out = append(out, asString(x))
		}
		return out
	default:
		return nil
	}
}

// --- glob matching with Python fnmatch semantics (case-sensitive, full match) ---

var fnmatchCache sync.Map // pattern -> *regexp.Regexp

func fnmatch(name, pattern string) bool {
	return compileGlob(pattern).MatchString(name)
}

func compileGlob(pattern string) *regexp.Regexp {
	if v, ok := fnmatchCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	rx := regexp.MustCompile(`(?s)\A(?:` + translateGlob(pattern) + `)\z`)
	fnmatchCache.Store(pattern, rx)
	return rx
}

// translateGlob converts a shell glob into a regexp source, mirroring the simple
// form of Python's fnmatch.translate: '*' -> '.*', '?' -> '.', '[...]' character
// classes pass through, and everything else is escaped as a literal.
func translateGlob(pat string) string {
	var sb strings.Builder
	i := 0
	for i < len(pat) {
		c := pat[i]
		i++
		switch c {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteString(".")
		case '[':
			j := i
			if j < len(pat) && (pat[j] == '!' || pat[j] == '^') {
				j++
			}
			if j < len(pat) && pat[j] == ']' {
				j++
			}
			for j < len(pat) && pat[j] != ']' {
				j++
			}
			if j >= len(pat) {
				sb.WriteString(`\[`)
			} else {
				inner := strings.ReplaceAll(pat[i:j], `\`, `\\`)
				i = j + 1
				if strings.HasPrefix(inner, "!") {
					inner = "^" + inner[1:]
				}
				sb.WriteByte('[')
				sb.WriteString(inner)
				sb.WriteByte(']')
			}
		default:
			sb.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return sb.String()
}
