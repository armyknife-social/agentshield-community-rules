// AgentShield MCP — guided prompts for common workflows.

export const PROMPTS = [
  {
    name: "write_rule",
    description: "Guided prompt for writing a new AgentShield community detection rule",
    arguments: [
      { name: "threat_description", description: "What attack pattern or threat you want to detect", required: true },
      { name: "category",           description: "Rule category: prompt-injection, data-exfiltration, tool-abuse, etc.", required: false },
    ],
  },
  {
    name: "investigate_anomaly",
    description: "Analyze an AgentShield anomaly: receipt chain, rule that fired, session context, recommended response",
    arguments: [
      { name: "session_id",  description: "Session ID where the anomaly was detected", required: true },
      { name: "rule",        description: "Rule that fired (e.g. phi-exfil-pattern)", required: false },
    ],
  },
  {
    name: "compliance_check",
    description: "Check which AgentShield rules apply to a given regulatory compliance profile and identify coverage gaps",
    arguments: [
      { name: "profile", description: "Compliance profile: hipaa, pci-dss, soc2, iso-42001, fedramp, gdpr", required: true },
    ],
  },
];

export function getWriteRulePrompt(args: { threat_description?: string; category?: string }) {
  return {
    messages: [{
      role: "user" as const,
      content: {
        type: "text" as const,
        text: `Write an AgentShield community detection rule for the following threat:

Threat: ${args.threat_description ?? "(describe the threat)"}
Category: ${args.category ?? "(prompt-injection | data-exfiltration | tool-abuse | model-attacks | agent-identity)"}

Use this schema (agentshield-rule-v0.1):

\`\`\`yaml
schema_version: agentshield-rule-v0.1
rule_id: <kebab-case-unique-id>
name: "<Human readable name>"
description: "<What it detects and why>"
severity: HIGH  # HIGH=block | MEDIUM=mirror/warn | LOW=warn
category: <category>
owasp_llm: <LLM01-LLM10 if applicable>
tags: []
content_types: [user_input]  # subset of: user_input, retrieval, response
action: block  # block | mirror | warn | log
detector:
  type: regex
  pattern: "<Rust regex — no lookahead/lookbehind, those are unsupported>"
mitigation: "<What to do when this fires>"
references: []
test_cases:
  should_match:
    - "<example that should trigger the rule>"
  should_not_match:
    - "<similar but benign example>"
author: <your name>
license: MIT
\`\`\`

Important constraints:
- rule_id must be kebab-case [a-z0-9-] only
- Rust regex crate does NOT support lookahead (?=) or lookbehind (?<=) — avoid them
- content_types determines which pipeline stage is inspected
- Include at least 2 should_match and 2 should_not_match test cases
- Validate with: python scripts/test_rules.py --rule <rule_id>

Then use the validate_rule tool to check the YAML before submitting a PR.`,
      },
    }],
  };
}

export function getInvestigateAnomalyPrompt(args: { session_id?: string; rule?: string }) {
  return {
    messages: [{
      role: "user" as const,
      content: {
        type: "text" as const,
        text: `Investigate the following AgentShield anomaly:

Session ID: ${args.session_id ?? "(unknown)"}
Rule fired: ${args.rule ?? "(check get_anomalies)"}

Steps:
1. Call get_anomalies with session_id="${args.session_id ?? ""}" to get the full anomaly record
2. Call query_receipts with session_id="${args.session_id ?? ""}" to get the full receipt chain
3. Call get_agentshield_status to confirm system state
4. Analyze:
   - Which rule fired and what it detected
   - Whether the session was terminated (ATCS enforcement)
   - Receipt chain completeness (SessionStarted → AnomalyDetected → SessionEnded)
   - Recommended response (escalate, notify, no action)
   - Whether this is a true positive or likely false positive

Report your findings with a severity assessment and recommended next steps.`,
      },
    }],
  };
}

export function getComplianceCheckPrompt(args: { profile?: string }) {
  const profileRules: Record<string, { required: string[]; optional: string[]; ceiling: string }> = {
    hipaa:      { required: ["prompt-injection-marker", "phi-exfil-pattern", "cross-agent-delegation-gate"], optional: ["pii-bulk-detection", "audit-trail-completeness"], ceiling: "WRITE_STANDARD" },
    "pci-dss":  { required: ["prompt-injection-marker", "pci-pattern-detector", "cross-agent-delegation-gate"], optional: ["pii-bulk-detection", "network-egress-audit"], ceiling: "WRITE_STANDARD" },
    soc2:       { required: ["prompt-injection-marker", "audit-trail-completeness"], optional: ["network-egress-audit"], ceiling: "WRITE_STANDARD" },
    "iso-42001":{ required: ["prompt-injection-marker", "ai-system-boundary-check"], optional: ["audit-trail-completeness"], ceiling: "WRITE_STANDARD" },
    fedramp:    { required: ["prompt-injection-marker", "phi-exfil-pattern", "cross-agent-delegation-gate", "network-egress-audit"], optional: ["ai-system-boundary-check"], ceiling: "READ_ONLY" },
    gdpr:       { required: ["prompt-injection-marker", "pii-bulk-detection", "cross-agent-delegation-gate"], optional: ["network-egress-audit"], ceiling: "WRITE_STANDARD" },
    default:    { required: ["prompt-injection-marker"], optional: ["pii-bulk-detection"], ceiling: "WRITE_STANDARD" },
  };

  const profile = args.profile ?? "default";
  const def = profileRules[profile] ?? profileRules.default;

  return {
    messages: [{
      role: "user" as const,
      content: {
        type: "text" as const,
        text: `Perform a compliance check for the AgentShield ${profile.toUpperCase()} profile.

Required opt-in rules for this profile:
${def.required.map(r => `  - ${r}`).join("\n")}

Optional rules:
${def.optional.map(r => `  - ${r}`).join("\n")}

ATCS authority ceiling: ${def.ceiling}

Steps:
1. Call get_agentshield_status to see which rules are currently registered in KNOWN_OPT_IN_RULES
2. Compare against the required rules above
3. Call list_rules with category filter to verify the rule definitions exist in the community repo
4. Check any active sessions via get_sessions to see if sessions have the required rules configured
5. Report:
   - Which required rules are present and which are missing
   - Any configuration gaps (rules exist but sessions don't have them enabled)
   - ATCS authority ceiling enforcement status
   - Recommended remediation steps`,
      },
    }],
  };
}
