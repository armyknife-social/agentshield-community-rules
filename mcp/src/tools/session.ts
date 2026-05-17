import { agentshieldBase, writeHeaders, readHeaders, validateSessionId } from "../config.js";

export const configureSessionTool = {
  name: "configure_session",
  description:
    "Register opt-in AgentShield rules for a session. Requires write token. " +
    "Substrate rules are always-on and do not need registration.",
  inputSchema: {
    type: "object" as const,
    properties: {
      session_id: { type: "string" },
      plugin_id:  { type: "string" },
      rules: {
        type: "array",
        items: { type: "string" },
        description: "Rule IDs to register",
      },
      expires_at: { type: "string", description: "Optional RFC3339 expiry" },
    },
    required: ["session_id", "plugin_id", "rules"],
  },
};

export const deconfigureSessionTool = {
  name: "deconfigure_session",
  description: "Remove opt-in rule registrations for a session. Requires write token.",
  inputSchema: {
    type: "object" as const,
    properties: {
      session_id: { type: "string" },
    },
    required: ["session_id"],
  },
};

export const getSessionsTool = {
  name: "get_sessions",
  description: "List all active session rule configurations. Read-only.",
  inputSchema: { type: "object" as const, properties: {}, required: [] },
};

export async function handleConfigureSession(args: {
  session_id: string;
  plugin_id: string;
  rules: string[];
  expires_at?: string;
}) {
  const sidErr = validateSessionId(args.session_id);
  if (sidErr) return { content: [{ type: "text" as const, text: sidErr }], isError: true };

  const body: Record<string, unknown> = {
    session_id: args.session_id,
    plugin_id:  args.plugin_id,
    rules:      args.rules,
  };
  if (args.expires_at) body.expires_at = args.expires_at;

  try {
    const resp = await fetch(`${agentshieldBase()}/anomalies/configure-session`, {
      method: "POST",
      headers: writeHeaders(),
      body: JSON.stringify(body),
    });

    if (resp.status === 401) {
      return { content: [{ type: "text" as const, text: "Unauthorized — AGENTSHIELD_WRITE_TOKEN invalid or missing." }], isError: true };
    }

    const data = await resp.json() as Record<string, unknown>;
    const accepted = (data.accepted_rules as string[]) ?? [];
    const rejected = (data.rejected_rules as string[]) ?? [];
    const lines = [
      `Session ${args.session_id} configured.`,
      `Accepted rules (${accepted.length}): ${accepted.join(", ") || "none"}`,
      ...(rejected.length > 0 ? [`Rejected (unknown IDs): ${rejected.join(", ")}`] : []),
      `Expires: ${data.expires_at}`,
    ];
    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `Error: ${err}` }], isError: true };
  }
}

export async function handleDeconfigureSession(args: { session_id: string }) {
  const sidErr = validateSessionId(args.session_id);
  if (sidErr) return { content: [{ type: "text" as const, text: sidErr }], isError: true };

  try {
    const resp = await fetch(
      `${agentshieldBase()}/anomalies/configure-session/${encodeURIComponent(args.session_id)}`,
      { method: "DELETE", headers: writeHeaders() }
    );
    if (resp.status === 401) {
      return { content: [{ type: "text" as const, text: "Unauthorized — AGENTSHIELD_WRITE_TOKEN required." }], isError: true };
    }
    if (resp.status === 404) {
      return { content: [{ type: "text" as const, text: `Session ${args.session_id} not found (already expired?).` }] };
    }
    return { content: [{ type: "text" as const, text: `Session ${args.session_id} deconfigured.` }] };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `Error: ${err}` }], isError: true };
  }
}

export async function handleGetSessions() {
  try {
    const resp = await fetch(`${agentshieldBase()}/anomalies/sessions`, { headers: readHeaders() });
    const data = await resp.json() as Array<Record<string, unknown>>;
    if (!data.length) return { content: [{ type: "text" as const, text: "No active session configurations." }] };

    const lines = data.map(s =>
      `${s.session_id} (plugin: ${s.plugin_id})\n  rules: ${(s.rules as string[]).join(", ")}\n  expires: ${s.expires_at}`
    );
    return { content: [{ type: "text" as const, text: `${data.length} active session(s):\n\n${lines.join("\n\n")}` }] };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `Error: ${err}` }], isError: true };
  }
}
