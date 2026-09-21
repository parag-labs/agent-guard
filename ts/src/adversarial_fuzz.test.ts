import { describe, expect, it } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import { AuditEntry, AuditLog, Decision, Policy, ToolCall } from "./index.ts";

function fsPolicy(): Policy {
  return Policy.fromDict({
    tools: [
      {
        tool: "read_file",
        allow: true,
        path_allow: ["/workspace/*"],
        path_deny: ["*.env*", "*secrets*", "*id_rsa*"],
      },
      { tool: "http_get", allow: true, domain_allow: ["api.internal"] },
      { tool: "delete_file", allow: true, require_approval: true },
    ],
  });
}

// A tiny deterministic PRNG (mulberry32) so the fuzz is reproducible.
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function below(rng: () => number, n: number): number {
  return Math.floor(rng() * n);
}

describe("deny-by-default is the floor", () => {
  it("always denies unknown tools", () => {
    const policy = fsPolicy();
    for (const tool of ["exec", "eval", "rm", "read_fil", "READ_FILE", "http_post", ""]) {
      const [decision] = policy.evaluate(
        new ToolCall(tool, { path: "/workspace/ok.txt" }),
      );
      expect(decision, `unlisted tool '${tool}' slipped through`).toBe(Decision.Deny);
    }
  });

  it("matches tool names exactly, not by prefix", () => {
    const policy = fsPolicy();
    for (const tool of ["read_file2", "read_file ", " read_file", "read_file\n"]) {
      const [decision] = policy.evaluate(
        new ToolCall(tool, { path: "/workspace/ok.txt" }),
      );
      expect(decision).toBe(Decision.Deny);
    }
  });
});

describe("path constraints hold under hostile inputs", () => {
  it("denies secret paths even inside the allowed root", () => {
    const policy = fsPolicy();
    for (const path of [
      "/workspace/.env",
      "/workspace/secrets/prod.key",
      "/workspace/nested/id_rsa",
      "/workspace/sub/secrets/db.pem",
    ]) {
      const [decision, reason] = policy.evaluate(
        new ToolCall("read_file", { path }),
      );
      expect(decision, `secret path allowed: ${path} (${reason})`).toBe(Decision.Deny);
    }
  });

  it("denies paths outside the allowed root", () => {
    const policy = fsPolicy();
    for (const path of [
      "/etc/passwd",
      "/root/.ssh/known_hosts",
      "workspace/relative.txt",
      "/workspaceX/evil.txt",
    ]) {
      const [decision] = policy.evaluate(new ToolCall("read_file", { path }));
      expect(decision, `path outside root allowed: ${path}`).toBe(Decision.Deny);
    }
  });

  it("lets deny patterns win over allow", () => {
    const policy = fsPolicy();
    const [decision, reason] = policy.evaluate(
      new ToolCall("read_file", { path: "/workspace/.env" }),
    );
    expect(decision).toBe(Decision.Deny);
    expect(reason.toLowerCase()).toContain("deny");
  });

  it("keeps the domain allow-list strict", () => {
    const policy = fsPolicy();
    for (const domain of ["api.external", "api.internal.evil.com", "evil.com", "API.INTERNAL"]) {
      const [decision] = policy.evaluate(new ToolCall("http_get", { domain }));
      expect(decision, `domain slipped through: ${domain}`).toBe(Decision.Deny);
    }
    const [ok] = policy.evaluate(new ToolCall("http_get", { domain: "api.internal" }));
    expect(ok).toBe(Decision.Allow);
  });

  it("never silently allows high-risk tools", () => {
    const policy = fsPolicy();
    const [decision] = policy.evaluate(
      new ToolCall("delete_file", { path: "/workspace/tmp.txt" }),
    );
    expect(decision).toBe(Decision.Approve);
  });

  it("handles missing or odd arguments without crashing or bypassing", () => {
    const policy = fsPolicy();
    const weird: Array<Record<string, unknown>> = [
      {},
      { path: "" },
      { path: null },
      { path: 12345 },
      { unexpected: "x" },
      { path: "/workspace/ok.txt", extra: {} },
    ];
    for (const args of weird) {
      const [decision] = policy.evaluate(new ToolCall("read_file", args));
      expect([Decision.Allow, Decision.Deny, Decision.Approve]).toContain(decision);
      const p = args.path;
      if (p === null || p === undefined || p === "" || p === 12345) {
        expect(decision).toBe(Decision.Deny);
      }
    }
  });

  it("never lets randomized paths escape the allow root", () => {
    const rng = mulberry32(0);
    const policy = fsPolicy();
    const tokens = ["workspace", "..", ".", "etc", "secrets", "ok.txt", ".env", "a", "id_rsa"];
    for (let n = 0; n < 5000; n++) {
      const depth = 1 + below(rng, 6);
      const parts: string[] = [];
      for (let d = 0; d < depth; d++) {
        parts.push(tokens[below(rng, tokens.length)]);
      }
      const path = "/" + parts.join("/");
      const [decision] = policy.evaluate(new ToolCall("read_file", { path }));
      if (decision === Decision.Allow) {
        expect(path.startsWith("/workspace/")).toBe(true);
        expect(
          !path.includes(".env") && !path.includes("secrets") && !path.includes("id_rsa"),
        ).toBe(true);
      }
    }
  });
});

describe("audit trail is tamper-evident", () => {
  it("verifies a clean chain", () => {
    const log = new AuditLog();
    for (let i = 0; i < 50; i++) {
      log.record(`tool-${i}`, "allow", "ok");
    }
    expect(log.verifyChain()).toBe(true);
  });

  it("detects editing any audit field", () => {
    const rng = mulberry32(1);
    for (let n = 0; n < 200; n++) {
      const log = new AuditLog();
      for (let i = 0; i < 10; i++) {
        log.record(`tool-${i}`, i % 2 === 1 ? "allow" : "deny", "reason");
      }
      const entries = log.entries();
      const victim = entries[below(rng, entries.length)];
      victim.decision = victim.decision === "deny" ? "allow" : "deny";
      expect(log.verifyChain()).toBe(false);
    }
  });

  it("detects truncating or reordering the chain", () => {
    const log = new AuditLog();
    for (let i = 0; i < 10; i++) {
      log.record(`tool-${i}`, "allow", "ok");
    }
    // Reorder the actual chain (white-box): each entry's prevHash pins its position,
    // so swapping two entries must break verification. entries() hands back a copy of
    // the array, so the swap has to happen in the backing store to be a real reorder.
    const backing = (log as unknown as { _entries: AuditEntry[] })._entries;
    const tmp = backing[3];
    backing[3] = backing[6];
    backing[6] = tmp;
    expect(log.verifyChain()).toBe(false);
  });

  it("rejects a signature from the wrong key", () => {
    const log = new AuditLog();
    log.record("t", "allow", "ok");
    const entry = log.entries()[0];
    const attacker = generateKeyPairSync("ed25519");
    entry.signature = sign(null, Buffer.from(entry.entryHash), attacker.privateKey).toString("hex");
    expect(log.verifyChain()).toBe(false);
  });

  it("rejects a flipped byte in a signature", () => {
    const rng = mulberry32(2);
    for (let n = 0; n < 100; n++) {
      const log = new AuditLog();
      log.record("t", "allow", "ok");
      const entry = log.entries()[0];
      const raw = Buffer.from(entry.signature, "hex");
      const idx = below(rng, raw.length);
      raw[idx] ^= 1 << below(rng, 8);
      entry.signature = raw.toString("hex");
      expect(log.verifyChain()).toBe(false);
    }
  });
});
