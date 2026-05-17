import { readFileSync, readdirSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { config } from "../config.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function repoRoot(): string {
  if (config.rulesDir) return config.rulesDir;
  return join(__dirname, "../../../..");
}

export function listRuleResources() {
  return [
    {
      uri: "agentshield://rules",
      name: "Community Rule Index",
      description: "Index of all AgentShield community detection rules",
      mimeType: "text/plain",
    },
    {
      uri: "agentshield://profiles",
      name: "Compliance Profiles",
      description: "Compliance profile rule packs (hipaa, pci-dss, soc2, fedramp, gdpr, iso-42001)",
      mimeType: "text/plain",
    },
    {
      uri: "agentshield://schema",
      name: "Rule Schema",
      description: "agentshield-rule-v0.1 schema reference and field documentation",
      mimeType: "text/plain",
    },
  ];
}

export function readRuleResource(uri: string): {
  contents: Array<{ uri: string; mimeType: string; text: string }>;
} {
  const root = repoRoot();

  if (uri === "agentshield://rules") {
    const indexPath = join(root, "index.yaml");
    const content = existsSync(indexPath)
      ? readFileSync(indexPath, "utf8")
      : "index.yaml not found — run: python scripts/generate_index.py";
    return { contents: [{ uri, mimeType: "text/plain", text: content }] };
  }

  if (uri === "agentshield://profiles") {
    const profilesDir = join(root, "profiles");
    if (!existsSync(profilesDir)) {
      return { contents: [{ uri, mimeType: "text/plain", text: "profiles/ directory not found" }] };
    }
    const sections = readdirSync(profilesDir)
      .filter(f => f.endsWith(".yaml"))
      .sort()
      .map(f => `# ${f}\n${readFileSync(join(profilesDir, f), "utf8")}`);
    return { contents: [{ uri, mimeType: "text/plain", text: sections.join("\n\n---\n\n") }] };
  }

  if (uri === "agentshield://schema") {
    const schemaPath = join(root, "rule-schema.md");
    const content = existsSync(schemaPath)
      ? readFileSync(schemaPath, "utf8")
      : "rule-schema.md not found";
    return { contents: [{ uri, mimeType: "text/plain", text: content }] };
  }

  // agentshield://rules/{category}/{rule_id}
  const match = uri.match(/^agentshield:\/\/rules\/([^/]+)\/([^/]+)$/);
  if (match) {
    const [, category, ruleId] = match;
    const ruleFile = join(root, "rules", category, `${ruleId}.yaml`);
    if (!existsSync(ruleFile)) {
      return { contents: [{ uri, mimeType: "text/plain", text: `Rule not found: ${uri}` }] };
    }
    return { contents: [{ uri, mimeType: "text/plain", text: readFileSync(ruleFile, "utf8") }] };
  }

  return { contents: [{ uri, mimeType: "text/plain", text: `Unknown resource URI: ${uri}` }] };
}
