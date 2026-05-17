// AgentShield MCP Server — runtime configuration.
//
// Two-token security model:
//   AGENTSHIELD_READ_TOKEN  — required for all read operations
//                             (get_status, get_anomalies, query_receipts, list_rules, inspect_content)
//   AGENTSHIELD_WRITE_TOKEN — required for all write/destructive operations
//                             (trigger_rule, configure_session, deconfigure_session)
//
// The model (Claude) should only receive the READ token in its environment.
// The WRITE token stays with the operator process that spawns this server.
// Never put AGENTSHIELD_WRITE_TOKEN in Claude Desktop config — use a wrapper script
// that injects it from a secrets manager at spawn time.
//
// Hard failure: server will not start if AGENTSHIELD_WRITE_TOKEN is unset.
// Set to a random 32+ byte hex string: openssl rand -hex 32

export const config = {
  agentshieldHost: process.env.AGENTSHIELD_HOST ?? "127.0.0.1",
  agentshieldPort: parseInt(process.env.AGENTSHIELD_PORT ?? "7160"),
  aegisPort:       parseInt(process.env.AEGIS_PORT ?? "7170"),
  receiptdHost:    process.env.RECEIPTD_HOST ?? "127.0.0.1:8445",

  // Two-token model. Both are validated at startup.
  readToken:  process.env.AGENTSHIELD_READ_TOKEN  ?? "",
  writeToken: process.env.AGENTSHIELD_WRITE_TOKEN ?? "",

  // Legacy single-token compat (used as write token if write-specific var not set)
  controlToken: process.env.CM_AGENTSHIELD_CONTROL_TOKEN ?? "",

  rulesDir: process.env.AGENTSHIELD_RULES_DIR ?? "",

  // inspect_content rate limit: max calls per minute per session_id
  inspectRateLimitPerMin: parseInt(process.env.AGENTSHIELD_INSPECT_RATE_LIMIT ?? "30"),
};

// ── Startup validation ────────────────────────────────────────────────────────

const effectiveWriteToken = config.writeToken || config.controlToken;
const effectiveReadToken  = config.readToken  || config.controlToken;

if (!effectiveWriteToken) {
  process.stderr.write(
    "[AgentShield MCP] FATAL: AGENTSHIELD_WRITE_TOKEN (or CM_AGENTSHIELD_CONTROL_TOKEN) not set.\n" +
    "  Write operations (trigger_rule, configure_session) require this token.\n" +
    "  Generate one: openssl rand -hex 32\n" +
    "  Set on cm-agentshieldd: CM_AGENTSHIELD_CONTROL_TOKEN=<same value>\n"
  );
  process.exit(1);
}

// Warn but don't fail if read token is unset — read endpoints on agentshieldd are open,
// but cm-receiptd read access will be attempted without auth.
if (!effectiveReadToken) {
  process.stderr.write(
    "[AgentShield MCP] WARN: AGENTSHIELD_READ_TOKEN not set — read endpoints will use write token.\n"
  );
}

export const WRITE_TOKEN = effectiveWriteToken;
export const READ_TOKEN  = effectiveReadToken || effectiveWriteToken;

// ── Header builders ───────────────────────────────────────────────────────────

export function readHeaders(): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${READ_TOKEN}`,
  };
}

export function writeHeaders(): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${WRITE_TOKEN}`,
  };
}

// ── URL builders ──────────────────────────────────────────────────────────────

export const agentshieldBase = () =>
  `http://${config.agentshieldHost}:${config.agentshieldPort}`;

export const aegisBase = () =>
  `http://${config.agentshieldHost}:${config.aegisPort}`;

export const receiptdBase = () =>
  `http://${config.receiptdHost}`;

// ── Session ID validation ─────────────────────────────────────────────────────

const SESSION_ID_RE = /^[a-zA-Z0-9_\-]{4,128}$/;

export function validateSessionId(sid: string): string | null {
  if (!SESSION_ID_RE.test(sid)) {
    return `Invalid session_id '${sid}' — must match [a-zA-Z0-9_-]{4,128}`;
  }
  return null;
}

// ── inspect_content rate limiter ──────────────────────────────────────────────
// Sliding window per session_id. Prevents pattern-probing attacks where an
// adversary repeatedly calls inspect_content to map detection thresholds.

const inspectCounts = new Map<string, { count: number; windowStart: number }>();

export function checkInspectRateLimit(sessionId: string): string | null {
  const limit = config.inspectRateLimitPerMin;
  const now   = Date.now();
  const key   = sessionId || "__anonymous__";
  const entry = inspectCounts.get(key);

  if (!entry || now - entry.windowStart > 60_000) {
    inspectCounts.set(key, { count: 1, windowStart: now });
    return null;
  }
  if (entry.count >= limit) {
    const resetIn = Math.ceil((60_000 - (now - entry.windowStart)) / 1000);
    return `Rate limit: ${limit} inspect_content calls/minute per session. Resets in ${resetIn}s.`;
  }
  entry.count++;
  return null;
}
