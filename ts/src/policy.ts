/**
 * AgentGuard policy engine: deny-by-default, least-privilege tool authorization.
 *
 * Every agent tool call is evaluated against a policy before execution. Decisions
 * are ALLOW, DENY, or APPROVE (human-in-the-loop for high-risk actions).
 */

/** The outcome of evaluating a tool call against a policy. */
export enum Decision {
  Allow = "allow",
  Deny = "deny",
  Approve = "approve",
}

/** Arbitrary tool-call arguments, mirroring the reference's dynamic dict. */
export type Args = Record<string, unknown>;

/** A single request by the agent to invoke a named tool with arguments. */
export class ToolCall {
  constructor(
    public readonly tool: string,
    public readonly args: Args = {},
  ) {}
}

/** The constraints attached to one allowed tool. Defaults deny everything. */
export interface ToolPolicy {
  /** The tool this policy governs. */
  tool: string;
  /** Whether the tool is allowed at all. */
  allow: boolean;
  /** Glob patterns a `path` argument must match. */
  pathAllow: string[];
  /** Glob patterns a `path` argument must not match. */
  pathDeny: string[];
  /** Exact domains a `domain` argument must be one of. */
  domainAllow: string[];
  /** Whether the tool requires human approval. */
  requireApproval: boolean;
}

/** Build a {@link ToolPolicy}, defaulting every unset constraint to deny/empty. */
export function toolPolicy(
  tool: string,
  opts: Partial<Omit<ToolPolicy, "tool">> = {},
): ToolPolicy {
  return {
    tool,
    allow: opts.allow ?? false,
    pathAllow: opts.pathAllow ?? [],
    pathDeny: opts.pathDeny ?? [],
    domainAllow: opts.domainAllow ?? [],
    requireApproval: opts.requireApproval ?? false,
  };
}

/** The snake_case spec for a single tool, as loaded by {@link Policy.fromDict}. */
export interface ToolSpec {
  tool: string;
  allow?: boolean;
  path_allow?: string[];
  path_deny?: string[];
  domain_allow?: string[];
  require_approval?: boolean;
}

/** A whole-policy spec, e.g. parsed from a JSON policy file. */
export interface PolicySpec {
  tools?: ToolSpec[];
}

/** Deny-by-default: only explicitly allowed tools/constraints pass. */
export class Policy {
  readonly tools: Map<string, ToolPolicy>;

  constructor(tools: ToolPolicy[] = []) {
    this.tools = new Map(tools.map((t) => [t.tool, t]));
  }

  /** Build a policy from a plain spec object (mirrors the Python `from_dict`). */
  static fromDict(spec: PolicySpec): Policy {
    const tools = (spec.tools ?? []).map((t) =>
      toolPolicy(t.tool, {
        allow: t.allow ?? false,
        pathAllow: t.path_allow ?? [],
        pathDeny: t.path_deny ?? [],
        domainAllow: t.domain_allow ?? [],
        requireApproval: t.require_approval ?? false,
      }),
    );
    return new Policy(tools);
  }

  /** Evaluate a tool call, returning the decision and a human-readable reason. */
  evaluate(call: ToolCall): [Decision, string] {
    const tp = this.tools.get(call.tool);
    if (!tp || !tp.allow) {
      return [
        Decision.Deny,
        `tool '${call.tool}' not in allow-list (deny-by-default)`,
      ];
    }

    const path = argString(call.args.path);
    // Deny-by-default extends to constrained arguments: a restricted tool called
    // with no path can't be proven in-bounds, so we refuse rather than allow.
    if (tp.pathAllow.length > 0 && path === "") {
      return [
        Decision.Deny,
        `tool '${call.tool}' requires a path within its allowed set`,
      ];
    }
    if (path !== "") {
      for (const pattern of tp.pathDeny) {
        if (fnmatch(path, pattern)) {
          return [
            Decision.Deny,
            `path '${path}' matches deny pattern '${pattern}'`,
          ];
        }
      }
      if (tp.pathAllow.length > 0 && !tp.pathAllow.some((p) => fnmatch(path, p))) {
        return [Decision.Deny, `path '${path}' not in allowed paths`];
      }
    }

    const domain = argString(call.args.domain);
    if (tp.domainAllow.length > 0 && domain === "") {
      return [
        Decision.Deny,
        `tool '${call.tool}' requires a domain within its allowed set`,
      ];
    }
    if (domain !== "" && tp.domainAllow.length > 0 && !tp.domainAllow.includes(domain)) {
      return [Decision.Deny, `domain '${domain}' not in allow-list`];
    }

    if (tp.requireApproval) {
      return [Decision.Approve, `tool '${call.tool}' requires human approval`];
    }
    return [Decision.Allow, "ok"];
  }
}

/** Mirror Python's `str(x) if x is not None else ""`: null/undefined become "". */
function argString(value: unknown): string {
  if (value === undefined || value === null) {
    return "";
  }
  return String(value);
}

// --- glob matching with Python fnmatch semantics (case-sensitive, full match) ---

type Tok =
  | { kind: "star" }
  | { kind: "any" }
  | { kind: "lit"; ch: string }
  | { kind: "class"; neg: boolean; ranges: Array<[number, number]> };

/**
 * Match `name` against a shell glob using Python `fnmatch` semantics: case
 * sensitive, whole-string, `*` matches any run (including `/`), `?` any single
 * char, and `[...]`/`[!...]` character classes.
 */
export function fnmatch(name: string, pattern: string): boolean {
  const toks = compile(pattern);
  const chars = Array.from(name);

  let i = 0;
  let j = 0;
  let star = -1;
  let starI = 0;
  while (i < chars.length) {
    if (j < toks.length && toks[j].kind !== "star" && tokMatches(toks[j], chars[i])) {
      i += 1;
      j += 1;
    } else if (j < toks.length && toks[j].kind === "star") {
      star = j;
      starI = i;
      j += 1;
    } else if (star !== -1) {
      j = star + 1;
      starI += 1;
      i = starI;
    } else {
      return false;
    }
  }
  while (j < toks.length && toks[j].kind === "star") {
    j += 1;
  }
  return j === toks.length;
}

function tokMatches(tok: Tok, c: string): boolean {
  switch (tok.kind) {
    case "any":
      return true;
    case "lit":
      return tok.ch === c;
    case "class": {
      const cc = c.codePointAt(0) ?? -1;
      const inside = tok.ranges.some(([lo, hi]) => lo <= cc && cc <= hi);
      return inside !== tok.neg;
    }
    case "star":
      return false;
  }
}

function compile(pattern: string): Tok[] {
  const p = Array.from(pattern);
  const toks: Tok[] = [];
  let i = 0;
  while (i < p.length) {
    const c = p[i];
    if (c === "*") {
      toks.push({ kind: "star" });
      i += 1;
    } else if (c === "?") {
      toks.push({ kind: "any" });
      i += 1;
    } else if (c === "[") {
      let j = i + 1;
      if (j < p.length && p[j] === "!") {
        j += 1;
      }
      if (j < p.length && p[j] === "]") {
        j += 1;
      }
      while (j < p.length && p[j] !== "]") {
        j += 1;
      }
      if (j >= p.length) {
        // No closing bracket: treat '[' as a literal.
        toks.push({ kind: "lit", ch: "[" });
        i += 1;
      } else {
        toks.push(parseClass(p.slice(i + 1, j)));
        i = j + 1;
      }
    } else {
      toks.push({ kind: "lit", ch: c });
      i += 1;
    }
  }
  return toks;
}

function parseClass(body: string[]): Tok {
  let neg = false;
  let idx = 0;
  if (body.length > 0 && body[0] === "!") {
    neg = true;
    idx = 1;
  }
  const ranges: Array<[number, number]> = [];
  while (idx < body.length) {
    if (idx + 2 < body.length && body[idx + 1] === "-") {
      ranges.push([body[idx].codePointAt(0) ?? -1, body[idx + 2].codePointAt(0) ?? -1]);
      idx += 3;
    } else {
      const cp = body[idx].codePointAt(0) ?? -1;
      ranges.push([cp, cp]);
      idx += 1;
    }
  }
  return { kind: "class", neg, ranges };
}
