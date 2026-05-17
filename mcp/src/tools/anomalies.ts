import { agentshieldBase, authHeaders } from "../config.js";

export const triggerRuleTool = {
  name: "trigger_rule",
  description:
    "Fire an anomaly rule trigger against cm-agentshieldd. " +
    "HIGH severity substrate rules terminate the session immediately (ATCS enforcement). " +
    "Opt-in rules must be registered for the session via configure_session first.",
  inputSchema: {
    type: "object" as const,
    properties: {
      session_id: { type: "string" },
      rule: {
        type: "string",
        description: "Rule ID (e.g. phi-exfil-pattern, cross-agent-delegation-gate)",
      },
      severity: {
        type: "string",
        enum: ["HIGH", "MEDIUM", "LOW"],
        description: "Severity level. HIGH triggers ATCS session termination for substrate rules.",
      },
    },
    required: ["session_id", "rule"],
  },
};

export const getAnomaliesTool = {
  name: "get_anomalies",
  description: "Retrieve recorded anomalies from cm-agentshieldd. Returns all anomalies or filtered by session.",
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
  description: "Get cm-agentshieldd daemon status: rule counts, configured sessions, anomaly count, ATCS enforcement state.",
  inputSchema: { type: "object" as const, properties: {}, required: [] },
};

export async function handleTriggerRule(args: {
  session_id: string;
  rule: string;
  severity?: string;
}) {
  const url = `${agentshieldBase()}/trigger`;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        session_id: args.session_id,
        rule: args.rule,
        severity: args.severity ?? "HIGH",
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

    const lines = [
      `Rule triggered: ${data.rule}`,
      `Receipt ID: ${data.receipt_id}`,
      `Severity: ${data.severity}`,
      `ATCS enforced: ${data.atcs_enforced} (substrate rule — unconditional termination)`,
      `Session terminated: ${data.terminated}`,
      `Chain emission: ${data.chain_emission_ok ? "OK" : "FAILED"}`,
      `Elapsed: ${data.elapsed_ms}ms`,
      `Rule origin: ${data.rule_origin}`,
    ];

    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `Error: ${err}` }], isError: true };
  }
}

export async function handleGetAnomalies(args: { session_id?: string }) {
  const url = `${agentshieldBase()}/anomalies`;
  try {
    const resp = await fetch(url, { headers: authHeaders() });
    let data = await resp.json() as Array<Record<string, unknown>>;

    if (args.session_id) {
      data = data.filter(a => a.session_id === args.session_id);
    }

    if (!data.length) {
      return { content: [{ type: "text" as const, text: "No anomalies recorded." }] };
    }

    const lines = data.map(a =>
      `[${a.detected_at}] ${a.rule} | severity: ${a.severity} | session: ${a.session_id} | terminated: ${a.terminated} | receipt: ${(a.receipt_id as string).slice(0, 24)}...`
    );

    return {
      content: [{
        type: "text" as const,
        text: `${data.length} anomaly record(s):\n\n${lines.join("\n")}`,
      }],
    };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `Error: ${err}` }], isError: true };
  }
}

export async function handleGetStatus() {
  const url = `${agentshieldBase()}/status`;
  try {
    const resp = await fetch(url, { headers: authHeaders() });
    const d = await resp.json() as Record<string, unknown>;

    const lines = [
      `AgentShield: ${d.agentshield}`,
      `Rules loaded: ${d.rules_loaded} (${(d.substrate_rules as string[]).length} substrate + ${(d.known_opt_in_rules as string[]).length} opt-in)`,
      `Substrate rules: ${(d.substrate_rules as string[]).join(", ")}`,
      `Known opt-in rules (${(d.known_opt_in_rules as string[]).length}): ${(d.known_opt_in_rules as string[]).join(", ")}`,
      `Anomalies recorded: ${d.anomalies_count}`,
      `Configured sessions: ${d.configured_sessions}`,
      `VM: ${d.vm_name}`,
      `Daemon pubkey fingerprint: ${d.daemon_pubkey_fingerprint}`,
    ];

    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `cm-agentshieldd not reachable: ${err}` }], isError: true };
  }
}
