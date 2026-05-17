import { aegisBase, authHeaders } from "../config.js";

export const inspectContentTool = {
  name: "inspect_content",
  description:
    "Inspect content through Aegis inline detector. Returns verdict (allow/warn/mirror/block), " +
    "confidence score, matched rule IDs, and elapsed_ms. " +
    "Use content_type='user_input' for incoming requests, 'retrieval' for RAG/tool output, " +
    "'response' for model output before sending to the user.",
  inputSchema: {
    type: "object" as const,
    properties: {
      content: {
        type: "string",
        description: "Content to inspect",
      },
      content_type: {
        type: "string",
        enum: ["user_input", "retrieval", "response"],
        description: "Which pipeline stage this content comes from",
      },
      session_id: {
        type: "string",
        description: "Session identifier (optional — used for logging)",
      },
    },
    required: ["content", "content_type"],
  },
};

export async function handleInspectContent(args: {
  content: string;
  content_type: string;
  session_id?: string;
}) {
  const url = `${aegisBase()}/inspect`;
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        content: args.content,
        content_type: args.content_type,
        session_id: args.session_id ?? "",
      }),
    });
  } catch (err) {
    return {
      content: [{
        type: "text" as const,
        text: `Aegis not reachable at ${aegisBase()} — is cm-aegisd running? Error: ${err}`,
      }],
      isError: true,
    };
  }

  const data = await resp.json() as Record<string, unknown>;

  const verdict = data.verdict as string;
  const confidence = data.confidence as number;
  const matched = (data.matched_rules as string[]) ?? [];
  const elapsed = data.elapsed_ms as number;
  const shadow = data.shadow as boolean;

  const verdictLine =
    verdict === "block"  ? `BLOCK (confidence ${(confidence * 100).toFixed(0)}%)` :
    verdict === "mirror" ? `MIRROR — forward to Minerva (confidence ${(confidence * 100).toFixed(0)}%)` :
    verdict === "warn"   ? `WARN — log and allow (confidence ${(confidence * 100).toFixed(0)}%)` :
                          `ALLOW`;

  const lines = [
    `Verdict: ${verdictLine}`,
    `Elapsed: ${elapsed}ms`,
    shadow ? `Mode: SHADOW (enforcement disabled — real verdict logged only)` : `Mode: ENFORCING`,
    matched.length > 0
      ? `Matched rules:\n${matched.map(r => `  - ${r}`).join("\n")}`
      : `Matched rules: none`,
  ];

  if (data.signals && Array.isArray(data.signals) && data.signals.length > 0) {
    lines.push(`Signals:\n${(data.signals as string[]).map(s => `  ${s}`).join("\n")}`);
  }

  return {
    content: [{ type: "text" as const, text: lines.join("\n") }],
  };
}
