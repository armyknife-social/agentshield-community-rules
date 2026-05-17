import { receiptdBase, readHeaders, validateSessionId } from "../config.js";

export const queryReceiptsTool = {
  name: "query_receipts",
  description:
    "Query the ContextOS receipt chain via cm-receiptd. " +
    "Returns signed anomaly receipts, session events, and tool calls. " +
    "Read-only. Requires read token.",
  inputSchema: {
    type: "object" as const,
    properties: {
      session_id: { type: "string", description: "Filter by session ID" },
      kind: {
        type: "string",
        description: "Filter by kind: AnomalyDetected, SessionStarted, SessionEnded, ToolCall",
      },
      since: { type: "string", description: "Time window: '1h', '24h', '7d', or RFC3339" },
      limit:  { type: "number", description: "Max receipts to return (default 20, max 100)" },
    },
    required: [],
  },
};

export const getFanoutStatusTool = {
  name: "get_fanout_status",
  description: "Get cm-receiptd fan-out engine status: destinations, circuit breakers, dead-letter queue.",
  inputSchema: {
    type: "object" as const,
    properties: {
      show_dlq: { type: "boolean", description: "Include DLQ entries (default false)" },
    },
    required: [],
  },
};

export async function handleQueryReceipts(args: {
  session_id?: string;
  kind?: string;
  since?: string;
  limit?: number;
}) {
  if (args.session_id) {
    const sidErr = validateSessionId(args.session_id);
    if (sidErr) return { content: [{ type: "text" as const, text: sidErr }], isError: true };
  }

  const params = new URLSearchParams();
  if (args.session_id) params.set("session_id", args.session_id);
  if (args.kind)       params.set("kind", args.kind);
  if (args.since)      params.set("since", args.since);
  // Cap at 100 to prevent bulk data extraction
  params.set("limit", String(Math.min(args.limit ?? 20, 100)));

  try {
    const resp = await fetch(`${receiptdBase()}/receipts?${params}`, {
      headers: readHeaders(),
    });

    if (resp.status === 401) {
      return { content: [{ type: "text" as const, text: "Unauthorized — AGENTSHIELD_READ_TOKEN required for receipt chain access." }], isError: true };
    }

    const data = await resp.json() as Array<Record<string, unknown>>;
    if (!data.length) return { content: [{ type: "text" as const, text: "No receipts found." }] };

    const lines = data.map(r => {
      const kind = r.kind as string ?? "Unknown";
      const ts   = (r._ingest_ts as string ?? "").slice(0, 19);
      const sid  = r.session_id as string ?? "";
      const rid  = (r.receipt_id as string ?? "").slice(0, 24);
      const rule = r.rule as string ?? (r.extra as Record<string, unknown>)?.rule as string ?? "";
      const sev  = r.severity as string ?? (r.extra as Record<string, unknown>)?.severity as string ?? "";
      const term = r.terminated !== undefined ? ` terminated:${r.terminated}` : "";
      return `[${ts}] ${kind}${rule ? ` rule:${rule}` : ""}${sev ? ` sev:${sev}` : ""}${term} session:${sid.slice(0, 20)} id:${rid}`;
    });

    return { content: [{ type: "text" as const, text: `${data.length} receipt(s):\n\n${lines.join("\n")}` }] };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `cm-receiptd not reachable: ${err}` }], isError: true };
  }
}

export async function handleGetFanoutStatus(args: { show_dlq?: boolean }) {
  try {
    const resp = await fetch(`${receiptdBase()}/fanout/status`, { headers: readHeaders() });
    const status = await resp.json() as Record<string, unknown>;
    const lines: string[] = [];

    if (status.fanout === "disabled") {
      lines.push("Fan-out disabled (CM_RECEIPTD_FANOUT_CONFIG not set).");
    } else {
      lines.push(`Fan-out active — ${status.destinations} destination(s)`);
      const cb = status.circuit_breakers as Record<string, unknown> ?? {};
      if (Object.keys(cb).length > 0) {
        lines.push("\nCircuit breakers:");
        for (const [k, v] of Object.entries(cb)) {
          const s = v as Record<string, unknown>;
          const open = s.open_until ? ` OPEN until ${s.open_until}` : " closed";
          lines.push(`  ${k.replace("cb:", "")}: failures=${s.failures}${open}`);
        }
      }
    }

    if (args.show_dlq) {
      const dlqResp = await fetch(`${receiptdBase()}/fanout/dlq?limit=10`, { headers: readHeaders() });
      const dlq = await dlqResp.json() as Array<Record<string, unknown>>;
      lines.push(dlq.length > 0
        ? `\nDLQ (${dlq.length} entries):\n${dlq.map(e => `  [${e.dlq_at}] ${e.dest_id} — ${e.error} (${e.attempts} attempts)`).join("\n")}`
        : "\nDLQ: empty"
      );
    }

    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  } catch (err) {
    return { content: [{ type: "text" as const, text: `Error: ${err}` }], isError: true };
  }
}
