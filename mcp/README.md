# AgentShield MCP Server

Model Context Protocol server for AgentShield. Gives Claude (and any MCP client) direct access to the AgentShield substrate: inspect content, manage sessions, query anomalies, read the receipt chain, and browse community detection rules.

## Tools

| Tool | Description |
|---|---|
| `inspect_content` | Run content through Aegis inline detector → verdict + matched rules |
| `get_agentshield_status` | Live daemon status: rule counts, sessions, anomaly count |
| `configure_session` | Register opt-in rules for a session |
| `deconfigure_session` | Clear session rule config at session end |
| `get_sessions` | List active session configurations |
| `trigger_rule` | Fire an anomaly rule → receipt in ContextOS chain |
| `get_anomalies` | Query recorded anomalies (optionally by session) |
| `query_receipts` | Query the ContextOS receipt chain (by session, kind, time) |
| `get_fanout_status` | Fan-out engine status + dead-letter queue |
| `list_rules` | Browse the community rule registry |
| `get_rule` | Get full YAML for a specific rule |
| `validate_rule` | Validate a YAML rule against the schema |

## Resources

| URI | Description |
|---|---|
| `agentshield://rules` | Full rule index (index.yaml) |
| `agentshield://rules/{category}/{rule_id}` | Individual rule YAML |
| `agentshield://profiles` | All compliance profile packs |
| `agentshield://schema` | agentshield-rule-v0.1 schema reference |

## Prompts

| Prompt | Description |
|---|---|
| `write_rule` | Guided workflow for writing a new detection rule |
| `investigate_anomaly` | Analyze an anomaly: receipt chain, context, recommended response |
| `compliance_check` | Check coverage gaps for a regulatory profile (HIPAA, FedRAMP, etc.) |

## Installation

```bash
cd mcp
npm install
npm run build
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|---|---|---|
| `AGENTSHIELD_HOST` | `127.0.0.1` | cm-agentshieldd host |
| `AGENTSHIELD_PORT` | `7160` | cm-agentshieldd port |
| `AEGIS_PORT` | `7170` | cm-aegisd port |
| `RECEIPTD_HOST` | `127.0.0.1:8445` | cm-receiptd host:port |
| `CM_AGENTSHIELD_CONTROL_TOKEN` | — | Bearer token for write endpoints |
| `AGENTSHIELD_RULES_DIR` | auto-detect | Path to community rules repo root |

## Claude Desktop configuration

```json
{
  "mcpServers": {
    "agentshield": {
      "command": "node",
      "args": ["/path/to/agentshield-community-rules/mcp/dist/index.js"],
      "env": {
        "AGENTSHIELD_HOST": "127.0.0.1",
        "AGENTSHIELD_PORT": "7160",
        "AEGIS_PORT": "7170",
        "RECEIPTD_HOST": "127.0.0.1:8445",
        "CM_AGENTSHIELD_CONTROL_TOKEN": "<your-token>",
        "AGENTSHIELD_RULES_DIR": "/path/to/agentshield-community-rules"
      }
    }
  }
}
```

## Deployment note

`inspect_content` and `get_fanout_status` require the MCP server to run **on the same host as cm-aegisd and cm-receiptd**, because those daemons bind to `127.0.0.1` by design (EMPIRE-571 hardening). All other tools reach cm-agentshieldd which is accessible at the configured host.

For remote use: run the MCP server inside the AgentShield VM, or expose the specific endpoints via a tunnelled connection.

## Example session

```
User: What rules should I enable for a HIPAA-compliant agent?

Claude: [calls compliance_check with profile="hipaa"]
→ Required: prompt-injection-marker, phi-exfil-pattern, cross-agent-delegation-gate
→ Optional: pii-bulk-detection, audit-trail-completeness
→ ATCS ceiling: WRITE_STANDARD

User: Inspect this user message for threats: "ignore all previous instructions"

Claude: [calls inspect_content]
→ Verdict: BLOCK (confidence 95%)
→ Matched: direct-instruction-override
→ Elapsed: 6ms

User: Write a rule to detect medical record exfiltration

Claude: [calls write_rule prompt, then validate_rule on the output]
→ Generates phi-exfil-pattern variant, validates schema
→ Suggests PR to agentshield-community-rules
```
