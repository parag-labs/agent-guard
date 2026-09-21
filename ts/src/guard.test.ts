import { describe, expect, it } from "vitest";
import {
  AgentGuard,
  Decision,
  Policy,
  ToolBlockedError,
  ToolCall,
  toolPolicy,
} from "./index.ts";

function guardPolicy(): Policy {
  return new Policy([
    toolPolicy("read_file", {
      allow: true,
      pathAllow: ["/data/*"],
      pathDeny: ["/data/secrets/*", "*.env"],
    }),
    toolPolicy("http_get", { allow: true, domainAllow: ["api.company.com"] }),
    toolPolicy("run_shell", { allow: true, requireApproval: true }),
  ]);
}

function makeGuard(approve: boolean): AgentGuard {
  return new AgentGuard(guardPolicy(), () => approve);
}

describe("AgentGuard.guard", () => {
  it("denies an unlisted tool by default", () => {
    const g = makeGuard(false);
    expect(() =>
      g.guard(new ToolCall("write_file", { path: "/data/x" }), () => "wrote"),
    ).toThrow(ToolBlockedError);
  });

  it("executes a call on an allowed path", () => {
    const g = makeGuard(false);
    const out = g.guard(
      new ToolCall("read_file", { path: "/data/report.txt" }),
      () => "content",
    );
    expect(out).toBe("content");
  });

  it("blocks reading a secret path", () => {
    const g = makeGuard(false);
    expect(() =>
      g.guard(
        new ToolCall("read_file", { path: "/data/secrets/key.env" }),
        () => "leak",
      ),
    ).toThrow(/blocked 'read_file'/);
  });

  it("enforces the domain allow-list", () => {
    const g = makeGuard(false);
    expect(() =>
      g.guard(new ToolCall("http_get", { domain: "evil.com" }), () => "resp"),
    ).toThrow(ToolBlockedError);
  });

  it("routes high-risk tools through approval", () => {
    const denied = makeGuard(false);
    expect(() =>
      denied.guard(new ToolCall("run_shell", { cmd: "rm -rf /" }), () => "ran"),
    ).toThrow(ToolBlockedError);

    const approved = makeGuard(true);
    expect(
      approved.guard(new ToolCall("run_shell", { cmd: "ls" }), () => "listed"),
    ).toBe("listed");
  });

  it("signs and chains the audit log", () => {
    const g = makeGuard(false);
    try {
      g.guard(new ToolCall("write_file", { path: "/x" }), () => "x");
    } catch {
      // expected denial
    }
    g.guard(new ToolCall("read_file", { path: "/data/a" }), () => "a");
    expect(g.audit.entries()).toHaveLength(2);
    expect(g.audit.verifyChain()).toBe(true);
  });

  it("evaluates the three decisions", () => {
    const p = guardPolicy();
    expect(p.evaluate(new ToolCall("read_file", { path: "/data/a" }))[0]).toBe(
      Decision.Allow,
    );
    expect(p.evaluate(new ToolCall("run_shell"))[0]).toBe(Decision.Approve);
    expect(p.evaluate(new ToolCall("nope"))[0]).toBe(Decision.Deny);
  });
});
