/**
 * Signed, append-only audit log for every tool-call decision.
 *
 * Each entry is chained (`prevHash`) and Ed25519-signed, so the audit trail is
 * tamper-evident -- you can prove after the fact exactly what the agent was
 * allowed to do and why.
 */

import {
  createHash,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

/**
 * One audit line. Fields are plain and mutable so tests (and tampering) can
 * mutate them after the fact -- verification is what catches any such edit.
 */
export interface AuditEntry {
  /** Wall-clock time the entry was recorded, in seconds. */
  ts: number;
  /** The tool the decision was about. */
  tool: string;
  /** The decision, as a wire string ("allow"/"deny"/"approve"). */
  decision: string;
  /** The human-readable reason for the decision. */
  reason: string;
  /** Hash of the previous entry, chaining this one to it. */
  prevHash: string;
  /** SHA-256 hash committing to this entry's fields. */
  entryHash: string;
  /** Ed25519 signature over `entryHash`, hex-encoded. */
  signature: string;
}

/** An Ed25519 key pair, as produced by `generateKeyPairSync("ed25519")`. */
export interface KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

/**
 * A signed, append-only, hash-chained record of tool-call decisions. Each entry
 * commits to the previous entry's hash and is individually Ed25519-signed, making
 * the trail tamper-evident.
 */
export class AuditLog {
  private readonly privateKey: KeyObject;
  private readonly pub: KeyObject;
  private readonly _entries: AuditEntry[] = [];

  constructor(keyPair?: KeyPair) {
    const kp = keyPair ?? generateKeyPairSync("ed25519");
    this.privateKey = kp.privateKey;
    this.pub = kp.publicKey;
  }

  /** The verifying (public) key for this log's signatures. */
  get publicKey(): KeyObject {
    return this.pub;
  }

  /** Append a signed, chained entry for a tool-call decision and return it. */
  record(tool: string, decision: string, reason: string): AuditEntry {
    const prevHash =
      this._entries.length > 0
        ? this._entries[this._entries.length - 1].entryHash
        : "";
    const ts = Date.now() / 1000;
    const entryHash = sha256Hex(canonical(ts, tool, decision, reason, prevHash));
    const signature = sign(null, Buffer.from(entryHash), this.privateKey).toString(
      "hex",
    );
    const entry: AuditEntry = {
      ts,
      tool,
      decision,
      reason,
      prevHash,
      entryHash,
      signature,
    };
    this._entries.push(entry);
    return entry;
  }

  /** A snapshot of the entry list (the entry objects themselves are shared). */
  entries(): AuditEntry[] {
    return [...this._entries];
  }

  /**
   * Recompute every entry's hash and check its signature and link to the
   * previous entry; returns false if anything has been altered, reordered,
   * truncated, or re-signed with the wrong key.
   */
  verifyChain(): boolean {
    let prev = "";
    for (const e of this._entries) {
      const expected = sha256Hex(
        canonical(e.ts, e.tool, e.decision, e.reason, prev),
      );
      if (expected !== e.entryHash) {
        return false;
      }
      if (!this.verifySig(e.entryHash, e.signature)) {
        return false;
      }
      prev = e.entryHash;
    }
    return true;
  }

  private verifySig(message: string, signatureHex: string): boolean {
    const sigBuf = Buffer.from(signatureHex, "hex");
    if (sigBuf.length !== 64) {
      return false;
    }
    try {
      return verify(null, Buffer.from(message), this.pub, sigBuf);
    } catch {
      return false;
    }
  }
}

// Canonical, sorted-key form matching the reference (decision, prev_hash, reason,
// tool, ts). Only needs to be self-consistent between record and verifyChain.
function canonical(
  ts: number,
  tool: string,
  decision: string,
  reason: string,
  prevHash: string,
): string {
  return (
    `{"decision": ${jsonStr(decision)}, "prev_hash": ${jsonStr(prevHash)}, ` +
    `"reason": ${jsonStr(reason)}, "tool": ${jsonStr(tool)}, "ts": ${tsStr(ts)}}`
  );
}

function jsonStr(s: string): string {
  let out = '"';
  for (const ch of s) {
    if (ch === '"') {
      out += '\\"';
    } else if (ch === "\\") {
      out += "\\\\";
    } else {
      out += ch;
    }
  }
  return out + '"';
}

function tsStr(ts: number): string {
  return String(ts);
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}
