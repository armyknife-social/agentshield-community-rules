# AgentShield Community Rules

Detection rules for AI agent security. Schema-validated, MIT licensed, community maintained.

**[armyknife-social.github.io/agentshield-community-rules](https://armyknife-social.github.io/agentshield-community-rules)** &mdash; platform overview, architecture diagram, rule browser, compliance profiles.

---

## The problem with existing tooling

Traditional WAFs pattern-match known attack signatures against fixed HTTP fields. AI-directed attacks do not behave like known attacks. They are semantically valid, mutate on every request, route through the model itself, and can weaponize your own LLM endpoints against your infrastructure.

A prompt injection attack does not look like a SQL injection attack. It looks like a user message. A data exfiltration attempt via a compromised RAG pipeline does not trigger rate limits or IP reputation checks. It looks like a document retrieval. Cross-agent delegation abuse travels over authenticated A2A channels and carries valid ATCS identity tokens.

AgentShield is built for this threat model. These community rules are the detection layer.

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │             Agent Request                │
                    └──────────────────┬──────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────┐
                    │               Cerberus                   │
                    │        Ingress gateway (cm-cerberusd)    │
                    │   Rate limiting · TLS · Request routing  │
                    └──────────────────┬──────────────────────┘
                                       │ POST /inspect
                    ┌──────────────────▼──────────────────────┐
                    │                Aegis                     │
                    │   Inline content inspector (cm-aegisd)   │
                    │   19 rules compiled at startup           │
                    │   5-20ms inline budget · shadow mode     │
                    └──────────────────┬──────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────┐
                    │            Verdict routing               │
                    │                                          │
                    │   allow ──────────────────► upstream     │
                    │   warn  ─────────────────► upstream      │
                    │                             + log        │
                    │   mirror ────────────────► upstream      │
                    │                             + Minerva    │
                    │   block ─────────────────► 403          │
                    │                             + trigger    │
                    └──────────────────┬──────────────────────┘
                                       │ block path only
                    ┌──────────────────▼──────────────────────┐
                    │           cm-agentshieldd               │
                    │      Session anomaly daemon (:7160)      │
                    │   ATCS enforcement · session termination  │
                    │   Substrate rules always-on              │
                    │   Opt-in rules registered per-session    │
                    └──────────────────┬──────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────┐
                    │            ContextOS Chain               │
                    │   Merkle-linked receipt chain            │
                    │   AnomalyDetected · signed · timestamped │
                    └──────────────────┬──────────────────────┘
                                       │ fan-out
             ┌─────────┬──────────────┬┴─────────────┬────────────┐
             │         │              │               │            │
        Splunk HEC  PagerDuty    OpenSearch       CEF/LEEF    Datadog
```

The substrate also enforces four rules unconditionally at the Firecracker microVM layer, regardless of session configuration:

```
exfiltration-correlation     — volume/pattern-based data exfil detection
host-network-escape-attempt  — unauthorized host network interface access
rootfs-write-attempt         — writes outside ephemeral overlay
vsock-bypass-attempt         — unauthorized vsock channel opening
```

These fire regardless of what opt-in rules are registered. They cannot be disabled.

---

## How community rules plug in

Community rules are **opt-in rules**. They are registered per-session when a plugin declares them in its manifest, and they run inside cm-aegisd's inline content inspector.

### Registration flow

```
1. Factory emits plugin manifest with compliance profile
   ┌─────────────────────────────────────────────┐
   │ manifest.json                               │
   │ {                                           │
   │   "agentshield_rules": [                   │
   │     "phi-exfil-pattern",                   │
   │     "cross-agent-delegation-gate",         │
   │     "prompt-injection-marker"              │
   │   ],                                       │
   │   "required_opt_in_rules": [               │
   │     "phi-exfil-pattern",                   │
   │     "cross-agent-delegation-gate"          │
   │   ]                                        │
   │ }                                          │
   └─────────────────────────────────────────────┘

2. agentos-runtime registers rules at session spawn
   POST http://127.0.0.1:7160/anomalies/configure-session
   {
     "session_id": "fcc-abc123",
     "plugin_id":  "acme-intake-agent",
     "rules":      ["phi-exfil-pattern", "cross-agent-delegation-gate", ...]
   }

3. Cerberus calls Aegis inline on every request
   POST http://127.0.0.1:7170/inspect
   {
     "content":      "<request body>",
     "content_type": "user_input",
     "session_id":   "fcc-abc123"
   }
   → { "verdict": "block", "matched_rules": ["phi-exfil-pattern"], "elapsed_ms": 7 }

4. On block: Cerberus fires trigger → cm-agentshieldd emits receipt
   POST http://127.0.0.1:7160/trigger
   { "session_id": "fcc-abc123", "rule": "phi-exfil-pattern", "severity": "HIGH" }
   → AnomalyDetected receipt enters the ContextOS chain
```

### Rule IDs must be registered

For a community rule to fire in production, its `rule_id` must appear in `cm-agentshieldd`'s `KNOWN_OPT_IN_RULES` constant. All 49 rules in this repository are registered in the upstream AgentShield substrate. If you write a new rule, open a PR to add its ID to `KNOWN_OPT_IN_RULES` alongside the YAML.

---

## Rule format

```yaml
schema_version: agentshield-rule-v0.1
rule_id: phi-exfil-pattern
name: "PHI Data Exfiltration Pattern"
description: >
  Detects Protected Health Information in model responses: ICD-10 diagnostic codes
  adjacent to clinical context terms, MRN identifiers, NDC drug codes, and
  patient record fields. Fires on content_type: response only.
severity: HIGH
category: data-exfiltration
owasp_llm: LLM06
tags: [hipaa, phi, healthcare, compliance]
content_types: [response]
action: block
detector:
  type: regex
  pattern: >
    (?i)(?:[A-Z]\d{2}\.?\d{0,4}[A-Za-z]?\s+(?:diagnosis|condition|disorder|disease|syndrome))
    |(?:patient\s+(?:id|record|name|dob)[\s:]+[A-Za-z0-9\-\/]+)
    |(?:mrn[\s:]+[A-Za-z0-9\-]{4,})
    |(?:ndc[\s:]+\d{4,5}-\d{3,4}-\d{1,2})
mitigation: >
  Terminate the session. Log session_id and matched content for HIPAA incident review.
  Do not cache or forward the response.
references:
  - https://owasp.org/www-project-top-10-for-large-language-model-applications/
  - https://www.hhs.gov/hipaa/for-professionals/privacy/special-topics/de-identification/
test_cases:
  should_match:
    - "Patient diagnosis: F32.0 Major depressive disorder. DOB: 1985-03-12"
    - "MRN: P-447291, prescribed NDC 0069-0150-01"
  should_not_match:
    - "The patient portal is available at our website"
    - "Please enter the patient ID in the system field"
author: ArmyKnifeLabs
license: MIT
```

### Detector types

| Type | Description | When to use |
|---|---|---|
| `regex` | Compiled Rust `regex` crate pattern. Applied per-request at inline inspect time. | Content pattern matching. The common case. |
| `heuristic` | No pattern. Description documents the multi-signal logic. | Behavioral or statistical rules that cannot be expressed as a single regex. |
| `external` | Calls an external HTTP endpoint for classification. | ML-based classifiers, external threat intel feeds. |

**Rust regex crate limitations:** lookahead and lookbehind (`(?!...)`, `(?=...)`) are not supported. Named capture groups, non-greedy quantifiers, and Unicode character classes are supported. Test patterns at [regex101.com](https://regex101.com) with the Rust flavor.

---

## OWASP LLM Top 10 coverage

Every OWASP LLM Top 10 category (2025) maps to one or more rules in this repository. See [OWASP-MAPPING.md](OWASP-MAPPING.md) for the complete mapping.

```
LLM01  Prompt Injection               10 rules
LLM02  Insecure Output Handling        1 rule
LLM03  Training Data Poisoning         1 rule
LLM04  Model Denial of Service         1 rule
LLM05  Supply Chain Vulnerabilities    1 rule
LLM06  Sensitive Information Disclosure 4 rules (phi, pci, secrets, training data)
LLM07  Insecure Plugin Design          3 rules
LLM08  Excessive Agency               3 rules
LLM09  Overreliance                   1 rule
LLM10  Model Theft                    1 rule
```

---

## Compliance profiles

Profiles map a regulatory framework to a set of required opt-in rules. The AgentShield factory selects the right profile at plugin manifest emit time and writes the corresponding `agentshield_rules` array into the manifest.

```
profiles/
  default.yaml    — prompt-injection-marker
  hipaa.yaml      — phi-exfil-pattern, cross-agent-delegation-gate
  pci-dss.yaml    — pci-pattern-detector, cross-agent-delegation-gate
  soc2.yaml       — audit-trail-completeness
  iso-42001.yaml  — ai-system-boundary-check
  fedramp.yaml    — four required rules, READ_ONLY ATCS ceiling
  gdpr.yaml       — pii-bulk-detection, cross-agent-delegation-gate
```

Profile YAML format:

```yaml
schema_version: agentos-rule-pack-v0.1
compliance_profile: hipaa
description: "HIPAA PHI-scope agent substrate rules."
substrate_rules:
  - exfiltration-correlation
  - host-network-escape-attempt
  - rootfs-write-attempt
  - vsock-bypass-attempt
required_opt_in_rules:
  - prompt-injection-marker
  - phi-exfil-pattern
  - cross-agent-delegation-gate
optional_rules:
  - pii-bulk-detection
  - audit-trail-completeness
atcs_authority_ceiling: WRITE_STANDARD
```

The `substrate_rules` list is documentation only — those rules are always-on in the substrate regardless of profile. The `required_opt_in_rules` list is what gets written to `manifest.agentshield_rules` by the factory.

---

## Repository layout

```
rules/
  prompt-injection/      12 rules — direct override, role hijack, jailbreak,
                                    system prompt extraction, token manipulation,
                                    retrieval injection, hidden unicode, multimodal
  data-exfiltration/     11 rules — API keys, PAN, SSN, PHI, PCI track data,
                                    PII bulk, AWS credentials, private keys,
                                    DB connection strings, training data probing
  tool-abuse/            11 rules — cross-agent delegation, network egress,
                                    AI system boundary, plugin chain bypass,
                                    SSRF, shell injection, A2A lateral movement
  llm-owasp/             10 rules — one canonical rule per OWASP LLM Top 10
  experimental/           5 rules — adversarial suffix, hallucination amplification,
                                    model distillation probe, agent impersonation,
                                    RAG context injection
profiles/
  default.yaml hipaa.yaml pci-dss.yaml soc2.yaml iso-42001.yaml fedramp.yaml gdpr.yaml
schema/
  rule.schema.json        JSON Schema (draft-07) for rule validation
scripts/
  validate.py             Schema validation — runs on every PR via CI
  generate_index.py       Generates index.yaml from all rules
  test_rules.py           Unit tests — runs should_match/should_not_match per rule
  smoke-test.sh           Live integration test against a running AgentShield substrate
index.yaml                Auto-generated rule index (do not edit manually)
```

---

## Quickstart

**Validate a rule:**
```bash
pip install pyyaml jsonschema
python scripts/validate.py rules/prompt-injection/direct-instruction-override.yaml
```

**Run unit tests (all rules, no infrastructure needed):**
```bash
python scripts/test_rules.py
# Results: 42 passed  0 failed  7 skipped (heuristic rules)
```

**Run live smoke test against a substrate VM:**
```bash
CM_AGENTSHIELD_CONTROL_TOKEN=<token> \
VM=<your-agentshield-vm-ip> \
    bash scripts/smoke-test.sh
```

The smoke test verifies:
- All community rule IDs are registered in `KNOWN_OPT_IN_RULES`
- All rules can be registered for a session via `configure-session`
- Triggers fire and produce receipts in the ContextOS chain
- If cm-aegisd is reachable, known-bad payloads produce the expected verdicts

---

## Writing a rule

1. Copy an existing rule from the relevant category as a starting point
2. Set a unique `rule_id` (kebab-case)
3. Write your `detector.pattern` and validate it with the Rust flavor at regex101.com
4. Add `test_cases.should_match` and `test_cases.should_not_match` — at least 2 of each
5. Run `python scripts/test_rules.py --rule <your-rule-id>`
6. Run `python scripts/validate.py rules/<category>/<your-rule>.yaml`
7. Submit a PR

Rules go in `rules/experimental/` on first submission. After one review cycle confirming false-positive rate is acceptable, they graduate to the main category directory.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full review process and severity guidelines.

---

## Severity and verdict mapping

```
HIGH   → block  (confidence 0.95)  session kill / request denied
MEDIUM + MEDIUM → mirror (0.75)    allowed + forwarded to Minerva for review
MEDIUM → warn   (0.60)             allowed + logged
LOW    → warn   (0.50)             logged only
```

When cm-aegisd returns `block`, Cerberus fires `POST /trigger` to cm-agentshieldd. For substrate rules, the ATCS enforcement policy terminates the session unconditionally regardless of severity. For opt-in rules, HIGH-severity triggers a session kill; MEDIUM and LOW are logged only.

---

## Enterprise integration

AgentShield receipt fan-out sends every `AnomalyDetected`, `SessionStarted`, `SessionEnded`, and `ToolCall` event to configured enterprise sinks in real time.

```yaml
# cm-receiptd-fanout.yaml
destinations:
  - id: splunk-prod
    adapter: splunk-hec
    url: "${SPLUNK_HEC_URL}/services/collector/event"
    headers:
      Authorization: "Splunk ${SPLUNK_HEC_TOKEN}"
    filter:
      kind: []

  - id: pagerduty-agentshield
    adapter: pagerduty-events-v2
    url: https://events.pagerduty.com/v2/enqueue
    headers:
      X-PagerDuty-Routing-Key: "${PAGERDUTY_ROUTING_KEY}"
    filter:
      kind: [AnomalyDetected]
      severity: [HIGH, CRITICAL]
```

Every receipt carries per-tool-call attribution with a cryptographic chain of custody anchored to the operator's YubiKey. The `AnomalyDetected` receipt includes `rule`, `severity`, `session_id`, `elapsed_ms`, and `terminated` at the top level — fields that land directly in Splunk's index without requiring field extraction.

This is the differentiator. A CVE scanner can tell you what vulnerabilities exist on a host. AgentShield tells you which tool call by which agent identity triggered which anomaly rule at which point in a session, with a receipt signed by the operator's hardware key and linked into an immutable chain.

---

## License

MIT. See [LICENSE](LICENSE).

Rules in `rules/experimental/` are community-contributed and carry their own author attribution. All other rules are maintained by ArmyKnifeLabs.

---

## Links

- [armyknife-social.github.io/agentshield-community-rules](https://armyknife-social.github.io/agentshield-community-rules) — platform overview and architecture
- [AgentShield](https://contextos.armyknifelabs.com/#agentshield)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [rule-schema.md](rule-schema.md) — full schema reference
- [OWASP-MAPPING.md](OWASP-MAPPING.md) — complete OWASP coverage map
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guidelines
