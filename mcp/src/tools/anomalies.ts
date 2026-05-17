import { agentshieldBase, readHeaders, writeHeaders, validateSessionId } from "../config.js";

export const triggerRuleTool = {
  name: "trigger_rule",
  description:
    "Fire an anomaly rule trigger against cm-agentshieldd. " +
    "HIGH severity substrate rules trigger ATCS session termination — this is destructive and irreversible. " +
    "Requires write token. Operator confirmation recommended before firing substrate rules.",
  inputSchema: {
    type: "object" as const,
    properties: {
      session_id: { type: "string" },
      rule: {
        type: "string",
        description: "Rule ID. Substrate rules (exfiltration-correlation etc.) + HIGH severity = immediate session kill.",
      },
      severity: {
        type: "string",
        enum: ["HIGH", "MEDIUM", "LOW"],
        description: "HIGH on a substrate rule triggers ATCS session termination. Cannot be undone.",
      },
      confirm_destructive: {
        type: "boolean",
        description: "Must be true to proceed with HIGH severity on a substrate rule. Prevents accidental session kills.",
      },
    },
    required: ["session_id", "rule"],
  },
};

export const getAnomaliesTool = {
  name: "get_anomalies",
  description: "Retrieve recorded anomalies from cm-agentshieldd. Read-only.",
  inputSchema: {
    type: "object" as const,
    properties: {
      session_id: { type: "string", description: "Optional: filter by session ID" },
    },
    required: [],
  },
};

export const getStatusTool = {
  name: "get_agentshield_status",
  description: "Get cm-agentshieldd daemon status: rule counts, sessions, anomaly count, fingerprint.",
  inputSchema: { type: "object" as const, properties: {}, required: [] },
};

const SUBSTRATE_RULES = new Set([
  "exfiltration-correlation",
  "host-network-escape-attempt",
  "rootfs-write-attempt",
  "vsock-bypass-attempt",
]);

export async function handleTriggerRule(args: {
  session_id: string;
  rule: string;
  severity?: string;
  confirm_destructive?: boolean;
}) {
  // Validate session_id format
  const sidErr = validateSessionId(args.session_id);
  if (sidErr) return { content: [{ type: "text" as const, text: sidErr }], isError: true };

  const severity = args.severity ?? "HIGH";

  // Guard: substrate rule + HIGH = irreversible session kill — require explicit confirmation
  if (SUBSTRATE_RULES.has(args.rule) && severity === "HIGH" && !args.confirm_destructive) {
    return {
      content: [{
        type: "text" as const,
        text:
          `BLOCKED: '${args.rule}' is a substrate rule. Firing with severity=HIGH will immediately ` +
          `terminate session '${args.session_id}' via ATCS enforcement. This cannot be undone.\n\n` +
          `To proceed, call trigger_rule again with confirm_destructive: true.\n` +
          `Ensure the session ID is correct and you have operator authorization.`,
      }],
      isError: true,
    };
  }

  const url = `${agentshieldBase()}/trigger`;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: writeHeaders(),  // write token required
      body: JSON.stringify({
        session_id: args.session_id,
        rule: args.rule,
        severity,
      }),
    });
    const data = await resp.json() as Record<string, unknown>;

    if (!resp.ok) {
      const err = data as { error?: string; detail?: string };
      return {
        content: [{ type: "text" as const, text: `Trigger rejected: ${err.error} — ${err.detail}` }],
        isError: true,
      };
    }

    return {
      content: [{
        type: "text" as const,
        text: [
          `Rule triggered: ${data.rule}`,
          `Receipt ID: ${data.receipt_id}`,
          `Severity: ${data.severity}`,
          `ATCS enforced: ${data.atcs_enforced}`,
          `Session terminated: ${data.terminated}`,
          `Chain emission: ${data.chain_emission_ok ? "OK" : "FAILED"}`,
          `Elapsed: ${data.elapsed_ms}ms`,
        ].join("\n"),
      }],
    };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `Error: ${err}` }], isError: true };
  }
}

export async function handleGetAnomalies(args: { session_id?: string }) {
  if (args.session_id) {
    const sidErr = validateSessionId(args.session_id);
    if (sidErr) return { content: [{ type: "text" as const, text: sidErr }], isError: true };
  }

  const url = `${agentshieldBase()}/anomalies`;
  try {
    const resp = await fetch(url, { headers: readHeaders() });
    let data = await resp.json() as Array<Record<string, unknown>>;
    if (args.session_id) data = data.filter(a => a.session_id === args.session_id);
    if (!data.length) return { content: [{ type: "text" as const, text: "No anomalies recorded." }] };

    const lines = data.map(a =>
      `[${a.detected_at}] ${a.rule} | ${a.severity} | session:${a.session_id} | terminated:${a.terminated} | ${(a.receipt_id as string).slice(0, 24)}...`
    );
    return { content: [{ type: "text" as const, text: `${data.length} anomaly record(s):\n\n${lines.join("\n")}` }] };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `Error: ${err}` }], isError: true };
  }
}

export async function handleGetStatus() {
  const url = `${agentshieldBase()}/status`;
  try {
    const resp = await fetch(url, { headers: readHeaders() });
    const d = await resp.json() as Record<string, unknown>;
    return {
      content: [{
        type: "text" as const,
        text: [
          `AgentShield: ${d.agentshield}`,
          `Rules loaded: ${d.rules_loaded} (${(d.substrate_rules as string[]).length} substrate + ${(d.known_opt_in_rules as string[]).length} opt-in)`,
          `Substrate rules: ${(d.substrate_rules as string[]).join(", ")}`,
          `Known opt-in rules: ${(d.known_opt_in_rules as string[]).join(", ")}`,
          `Anomalies recorded: ${d.anomalies_count}`,
          `Configured sessions: ${d.configured_sessions}`,
          `VM: ${d.vm_name}`,
          `Daemon pubkey fingerprint: ${d.daemon_pubkey_fingerprint}`,
        ].join("\n"),
      }],
    };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `cm-agentshieldd not reachable: ${err}` }], isError: true };
  }
}
