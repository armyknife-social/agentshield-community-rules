import { agentshieldBase, authHeaders } from "../config.js";

export const configureSessionTool = {
  name: "configure_session",
  description:
    "Register opt-in AgentShield rules for a session. Rules in this list will fire " +
    "for this session when detected by Aegis. Substrate rules (exfiltration-correlation etc.) " +
    "are always-on and do not need to be registered.",
  inputSchema: {
    type: "object" as const,
    properties: {
      session_id: { type: "string", description: "Session identifier" },
      plugin_id:  { type: "string", description: "Plugin or agent identifier" },
      rules: {
        type: "array",
        items: { type: "string" },
        description: "Rule IDs to register (must be in KNOWN_OPT_IN_RULES)",
      },
      expires_at: {
        type: "string",
        description: "Optional RFC3339 expiry. Defaults to now + 1 hour.",
      },
    },
    required: ["session_id", "plugin_id", "rules"],
  },
};

export const deconfigureSessionTool = {
  name: "deconfigure_session",
  description: "Remove all opt-in rule registrations for a session. Called at session end.",
  inputSchema: {
    type: "object" as const,
    properties: {
      session_id: { type: "string", description: "Session identifier to clear" },
    },
    required: ["session_id"],
  },
};

export const getSessionsTool = {
  name: "get_sessions",
  description: "List all active session rule configurations (registered sessions + their opt-in rules).",
  inputSchema: { type: "object" as const, properties: {}, required: [] },
};

export async function handleConfigureSession(args: {
  session_id: string;
  plugin_id: string;
  rules: string[];
  expires_at?: string;
}) {
  const url = `${agentshieldBase()}/anomalies/configure-session`;
  const body: Record<string, unknown> = {
    session_id: args.session_id,
    plugin_id:  args.plugin_id,
    rules:      args.rules,
  };
  if (args.expires_at) body.expires_at = args.expires_at;

  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(body),
    });
    const data = await resp.json() as Record<string, unknown>;
    const accepted = (data.accepted_rules as string[]) ?? [];
    const rejected = (data.rejected_rules as string[]) ?? [];
    const expires  = data.expires_at as string;

    const lines = [
      `Session ${args.session_id} configured.`,
      `Accepted rules (${accepted.length}): ${accepted.join(", ") || "none"}`,
      rejected.length > 0 ? `Rejected rules (unknown IDs): ${rejected.join(", ")}` : null,
      `Expires: ${expires}`,
    ].filter(Boolean);

    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `Error: ${err}` }], isError: true };
  }
}

export async function handleDeconfigureSession(args: { session_id: string }) {
  const url = `${agentshieldBase()}/anomalies/configure-session/${encodeURIComponent(args.session_id)}`;
  try {
    const resp = await fetch(url, { method: "DELETE", headers: authHeaders() });
    if (resp.status === 404) {
      return { content: [{ type: "text" as const, text: `Session ${args.session_id} not found (may have already expired).` }] };
    }
    return { content: [{ type: "text" as const, text: `Session ${args.session_id} deconfigured. Rules cleared.` }] };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `Error: ${err}` }], isError: true };
  }
}

export async function handleGetSessions() {
  const url = `${agentshieldBase()}/anomalies/sessions`;
  try {
    const resp = await fetch(url, { headers: authHeaders() });
    const data = await resp.json() as Array<Record<string, unknown>>;
    if (!data.length) return { content: [{ type: "text" as const, text: "No active session configurations." }] };

    const lines = data.map(s =>
      `${s.session_id} (plugin: ${s.plugin_id})\n  rules: ${(s.rules as string[]).join(", ")}\n  expires: ${s.expires_at}`
    );
    return { content: [{ type: "text" as const, text: `${data.length} active sessions:\n\n${lines.join("\n\n")}` }] };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `Error: ${err}` }], isError: true };
  }
}
