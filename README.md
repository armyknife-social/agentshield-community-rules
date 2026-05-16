# AgentShield Community Rules

> Sigma rules for LLM agents.

Open-source detection rules for [AgentShield](https://contextos.armyknifelabs.com) — the AI-native security perimeter for agent fleets. MIT licensed. Community contributed.

## What this is

AgentShield detects AI-directed attacks at the session layer: prompt injection, data exfiltration, tool abuse, cross-agent delegation abuse, and more. These rules power the inline Aegis content inspector and integrate with Splunk, PagerDuty, OpenSearch, CEF/LEEF SIEMs, and AWS Security Hub.

This repo is the community rule registry. Same model as [Sigma](https://github.com/SigmaHQ/sigma) and [Falco](https://github.com/falcosecurity/rules) — rules are format-defined, schema-validated, and maintained as a commons.

## Rule count

| Category | Rules |
|---|---|
| Prompt Injection | 12 |
| Data Exfiltration | 11 |
| Tool Abuse | 11 |
| OWASP LLM Top 10 | 10 |
| Experimental | 5 |
| **Total** | **49** |

Compliance profiles: 7 (default, hipaa, pci-dss, soc2, iso-42001, fedramp, gdpr)

## OWASP LLM Top 10 mapping

Every OWASP LLM Top 10 category (2025) maps to one or more AgentShield rule IDs. See [OWASP-MAPPING.md](OWASP-MAPPING.md).

## Quick start

```bash
# Use rules with cm-aegisd
CM_AEGIS_SHADOW=true cm-aegisd --bind 127.0.0.1:7170

# Validate a rule
pip install pyyaml jsonschema
python scripts/validate.py rules/prompt-injection/direct-instruction-override.yaml

# List all rule IDs
cat index.yaml
```

## Rule format

See [rule-schema.md](rule-schema.md) for the full schema definition and [schema/rule.schema.json](schema/rule.schema.json) for the JSON Schema validator.

```yaml
schema_version: agentshield-rule-v0.1
rule_id: my-custom-rule
name: "My Custom Rule"
severity: HIGH
category: prompt-injection
content_types: [user_input]
action: block
detector:
  type: regex
  pattern: "(?i)your pattern here"
```

## Directory structure

```
rules/
  prompt-injection/   # Direct injection, role hijack, jailbreak, retrieval injection
  data-exfiltration/  # PII, secrets, PHI, PCI, bulk exfil patterns
  tool-abuse/         # Cross-agent delegation, plugin abuse, filesystem escape
  llm-owasp/          # One rule per OWASP LLM Top 10 category (LLM01-LLM10)
  experimental/       # Community-contributed rules, unreviewed
profiles/             # Compliance profiles: hipaa, pci-dss, soc2, fedramp, gdpr, iso-42001
schema/               # JSON Schema for validation
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All PRs run schema validation and are reviewed for false-positive risk before merge into `rules/`. Unreviewed rules go in `experimental/`.

## Integration

Rules map to `cm-agentshieldd` opt-in rule IDs. Register them per-session:

```bash
curl -X POST http://127.0.0.1:7160/anomalies/configure-session \
  -H "Authorization: Bearer $CM_AGENTSHIELD_CONTROL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "sess-001", "plugin_id": "my-plugin", "rules": ["direct-instruction-override", "phi-exfil-pattern"]}'
```

## License

MIT — see [LICENSE](LICENSE).

## Maintained by

[ArmyKnifeLabs](https://contextos.armyknifelabs.com) · [AgentShield](https://contextos.armyknifelabs.com/#agentshield)
