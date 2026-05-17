import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import yaml from "js-yaml";
import { config } from "../config.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function rulesDir(): string {
  if (config.rulesDir) return config.rulesDir;
  // Default: two levels up from mcp/dist/tools/ → repo root
  return join(__dirname, "../../../..");
}

export const listRulesTool = {
  name: "list_rules",
  description: "List all available AgentShield community rules. Filter by category or severity.",
  inputSchema: {
    type: "object" as const,
    properties: {
      category: {
        type: "string",
        description: "Filter by category: prompt-injection, data-exfiltration, tool-abuse, llm-owasp, experimental",
      },
      severity: {
        type: "string",
        enum: ["HIGH", "MEDIUM", "LOW"],
        description: "Filter by severity",
      },
    },
    required: [],
  },
};

export const getRuleTool = {
  name: "get_rule",
  description: "Get the full YAML definition of a community rule by rule_id.",
  inputSchema: {
    type: "object" as const,
    properties: {
      rule_id: { type: "string", description: "Rule ID (e.g. phi-exfil-pattern)" },
    },
    required: ["rule_id"],
  },
};

export const validateRuleTool = {
  name: "validate_rule",
  description: "Validate a YAML rule definition against the agentshield-rule-v0.1 schema. Returns pass/fail with error details.",
  inputSchema: {
    type: "object" as const,
    properties: {
      yaml_content: { type: "string", description: "Full YAML content of the rule to validate" },
    },
    required: ["yaml_content"],
  },
};

interface RuleFile {
  rule_id: string;
  name: string;
  severity: string;
  category: string;
  owasp_llm?: string;
  content_types?: string[];
  action?: string;
  description?: string;
}

function walkRules(): Array<{ path: string; data: RuleFile }> {
  const dir = join(rulesDir(), "rules");
  if (!existsSync(dir)) return [];
  const results: Array<{ path: string; data: RuleFile }> = [];

  for (const cat of readdirSync(dir)) {
    const catPath = join(dir, cat);
    if (!statSync(catPath).isDirectory()) continue;
    for (const file of readdirSync(catPath)) {
      if (!file.endsWith(".yaml")) continue;
      const p = join(catPath, file);
      try {
        const data = yaml.load(readFileSync(p, "utf8")) as RuleFile;
        if (data?.rule_id) results.push({ path: p, data });
      } catch { /* skip malformed */ }
    }
  }
  return results;
}

export async function handleListRules(args: { category?: string; severity?: string }) {
  let rules = walkRules();

  if (args.category) rules = rules.filter(r => r.path.includes(`/${args.category}/`));
  if (args.severity) rules = rules.filter(r => r.data.severity === args.severity!.toUpperCase());

  if (!rules.length) return { content: [{ type: "text" as const, text: "No rules found matching filters." }] };

  const byCategory: Record<string, typeof rules> = {};
  for (const r of rules) {
    const cat = r.path.split("/").slice(-2)[0];
    (byCategory[cat] ??= []).push(r);
  }

  const lines: string[] = [`${rules.length} rule(s):\n`];
  for (const [cat, rs] of Object.entries(byCategory).sort()) {
    lines.push(`── ${cat} (${rs.length})`);
    for (const r of rs.sort((a, b) => a.data.rule_id.localeCompare(b.data.rule_id))) {
      const owasp = r.data.owasp_llm ? ` [${r.data.owasp_llm}]` : "";
      lines.push(`  ${r.data.rule_id.padEnd(40)} ${r.data.severity.padEnd(8)}${owasp} — ${r.data.name}`);
    }
  }

  return { content: [{ type: "text" as const, text: lines.join("\n") }] };
}

export async function handleGetRule(args: { rule_id: string }) {
  const rules = walkRules();
  const match = rules.find(r => r.data.rule_id === args.rule_id);

  if (!match) {
    return {
      content: [{ type: "text" as const, text: `Rule '${args.rule_id}' not found. Use list_rules to browse available rules.` }],
      isError: true,
    };
  }

  const content = readFileSync(match.path, "utf8");
  return { content: [{ type: "text" as const, text: content }] };
}

const REQUIRED_FIELDS = ["schema_version", "rule_id", "name", "description", "severity", "category", "content_types", "action", "detector"];
const VALID_SEVERITIES = ["HIGH", "MEDIUM", "LOW"];
const VALID_ACTIONS    = ["block", "mirror", "warn", "log"];
const VALID_TYPES      = ["user_input", "retrieval", "response"];

export async function handleValidateRule(args: { yaml_content: string }) {
  let data: Record<string, unknown>;
  try {
    data = yaml.load(args.yaml_content) as Record<string, unknown>;
  } catch (e) {
    return { content: [{ type: "text" as const, text: `FAIL — YAML parse error: ${e}` }], isError: true };
  }

  const errors: string[] = [];

  for (const f of REQUIRED_FIELDS) {
    if (!(f in data)) errors.push(`Missing required field: ${f}`);
  }

  if (data.schema_version !== "agentshield-rule-v0.1") {
    errors.push(`schema_version must be 'agentshield-rule-v0.1', got '${data.schema_version}'`);
  }
  if (typeof data.rule_id === "string" && !/^[a-z0-9-]+$/.test(data.rule_id)) {
    errors.push(`rule_id must be kebab-case [a-z0-9-], got '${data.rule_id}'`);
  }
  if (data.severity && !VALID_SEVERITIES.includes(data.severity as string)) {
    errors.push(`severity must be HIGH|MEDIUM|LOW, got '${data.severity}'`);
  }
  if (data.action && !VALID_ACTIONS.includes(data.action as string)) {
    errors.push(`action must be block|mirror|warn|log, got '${data.action}'`);
  }
  if (Array.isArray(data.content_types)) {
    for (const ct of data.content_types as string[]) {
      if (!VALID_TYPES.includes(ct)) errors.push(`content_types: invalid value '${ct}' (valid: ${VALID_TYPES.join(", ")})`);
    }
  }

  const detector = data.detector as Record<string, unknown> ?? {};
  if (!detector.type) errors.push("detector.type is required");
  if (detector.type === "regex" && !detector.pattern) errors.push("detector.pattern is required when type is regex");

  if (errors.length === 0) {
    return {
      content: [{
        type: "text" as const,
        text: `PASS — rule '${data.rule_id}' is valid (schema_version: agentshield-rule-v0.1)`,
      }],
    };
  }

  return {
    content: [{
      type: "text" as const,
      text: `FAIL — ${errors.length} error(s):\n${errors.map(e => `  - ${e}`).join("\n")}`,
    }],
    isError: true,
  };
}
