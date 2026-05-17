#!/usr/bin/env node
/**
 * AgentShield MCP Server
 *
 * Exposes AgentShield substrate capabilities to Claude and other MCP clients:
 *   Tools:     inspect_content, trigger_rule, configure_session, deconfigure_session,
 *              get_sessions, get_anomalies, get_agentshield_status,
 *              query_receipts, get_fanout_status,
 *              list_rules, get_rule, validate_rule
 *   Resources: agentshield://rules, agentshield://profiles, agentshield://schema
 *   Prompts:   write_rule, investigate_anomaly, compliance_check
 *
 * Configuration (environment variables):
 *   AGENTSHIELD_HOST           cm-agentshieldd host (default: 127.0.0.1)
 *   AGENTSHIELD_PORT           cm-agentshieldd port (default: 7160)
 *   AEGIS_PORT                 cm-aegisd port       (default: 7170)
 *   RECEIPTD_HOST              cm-receiptd host:port (default: 127.0.0.1:8445)
 *   CM_AGENTSHIELD_CONTROL_TOKEN  bearer token for write endpoints
 *   AGENTSHIELD_RULES_DIR      path to community rules repo root (default: auto-detect)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { inspectContentTool,    handleInspectContent }    from "./tools/inspect.js";
import { triggerRuleTool,       handleTriggerRule }        from "./tools/anomalies.js";
import { getAnomaliesTool,      handleGetAnomalies }       from "./tools/anomalies.js";
import { getStatusTool,         handleGetStatus }          from "./tools/anomalies.js";
import { configureSessionTool,  handleConfigureSession }   from "./tools/session.js";
import { deconfigureSessionTool,handleDeconfigureSession } from "./tools/session.js";
import { getSessionsTool,       handleGetSessions }        from "./tools/session.js";
import { queryReceiptsTool,     handleQueryReceipts }      from "./tools/receipts.js";
import { getFanoutStatusTool,   handleGetFanoutStatus }    from "./tools/receipts.js";
import { listRulesTool,         handleListRules }          from "./tools/rules.js";
import { getRuleTool,           handleGetRule }            from "./tools/rules.js";
import { validateRuleTool,      handleValidateRule }       from "./tools/rules.js";
import { listRuleResources, readRuleResource }             from "./resources/rules-resource.js";
import {
  PROMPTS,
  getWriteRulePrompt,
  getInvestigateAnomalyPrompt,
  getComplianceCheckPrompt,
} from "./prompts/prompts.js";

const server = new Server(
  { name: "agentshield-mcp", version: "0.1.0" },
  { capabilities: { tools: {}, resources: {}, prompts: {} } }
);

// ── Tools ──────────────────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    inspectContentTool,
    triggerRuleTool,
    getAnomaliesTool,
    getStatusTool,
    configureSessionTool,
    deconfigureSessionTool,
    getSessionsTool,
    queryReceiptsTool,
    getFanoutStatusTool,
    listRulesTool,
    getRuleTool,
    validateRuleTool,
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;

  switch (name) {
    case "inspect_content":
      return handleInspectContent(args as Parameters<typeof handleInspectContent>[0]);
    case "trigger_rule":
      return handleTriggerRule(args as Parameters<typeof handleTriggerRule>[0]);
    case "get_anomalies":
      return handleGetAnomalies(args as Parameters<typeof handleGetAnomalies>[0]);
    case "get_agentshield_status":
      return handleGetStatus();
    case "configure_session":
      return handleConfigureSession(args as Parameters<typeof handleConfigureSession>[0]);
    case "deconfigure_session":
      return handleDeconfigureSession(args as Parameters<typeof handleDeconfigureSession>[0]);
    case "get_sessions":
      return handleGetSessions();
    case "query_receipts":
      return handleQueryReceipts(args as Parameters<typeof handleQueryReceipts>[0]);
    case "get_fanout_status":
      return handleGetFanoutStatus(args as Parameters<typeof handleGetFanoutStatus>[0]);
    case "list_rules":
      return handleListRules(args as Parameters<typeof handleListRules>[0]);
    case "get_rule":
      return handleGetRule(args as Parameters<typeof handleGetRule>[0]);
    case "validate_rule":
      return handleValidateRule(args as Parameters<typeof handleValidateRule>[0]);
    default:
      return {
        content: [{ type: "text" as const, text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
});

// ── Resources ─────────────────────────────────────────────────────────────────

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: listRuleResources(),
}));

server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
  return readRuleResource(req.params.uri);
});

// ── Prompts ───────────────────────────────────────────────────────────────────

server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: PROMPTS }));

server.setRequestHandler(GetPromptRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;

  switch (name) {
    case "write_rule":
      return getWriteRulePrompt(args as { threat_description?: string; category?: string });
    case "investigate_anomaly":
      return getInvestigateAnomalyPrompt(args as { session_id?: string; rule?: string });
    case "compliance_check":
      return getComplianceCheckPrompt(args as { profile?: string });
    default:
      throw new Error(`Unknown prompt: ${name}`);
  }
});

// ── Start ──────────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("AgentShield MCP server started\n");
}

main().catch(err => {
  process.stderr.write(`Fatal: ${err}\n`);
  process.exit(1);
});
