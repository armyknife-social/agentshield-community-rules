// AgentShield MCP Server — runtime configuration from environment variables.

export const config = {
  agentshieldHost: process.env.AGENTSHIELD_HOST ?? "127.0.0.1",
  agentshieldPort: parseInt(process.env.AGENTSHIELD_PORT ?? "7160"),
  aegisPort:       parseInt(process.env.AEGIS_PORT ?? "7170"),
  receiptdHost:    process.env.RECEIPTD_HOST ?? "127.0.0.1:8445",
  controlToken:    process.env.CM_AGENTSHIELD_CONTROL_TOKEN ?? "",
  rulesDir:        process.env.AGENTSHIELD_RULES_DIR ?? "",
};

export const agentshieldBase = () =>
  `http://${config.agentshieldHost}:${config.agentshieldPort}`;

export const aegisBase = () =>
  `http://${config.agentshieldHost}:${config.aegisPort}`;

export const receiptdBase = () =>
  `http://${config.receiptdHost}`;

export function authHeaders(): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (config.controlToken) h["Authorization"] = `Bearer ${config.controlToken}`;
  return h;
}
