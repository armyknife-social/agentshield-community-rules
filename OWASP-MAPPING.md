# OWASP LLM Top 10 → AgentShield Rule Mapping

OWASP LLM Top 10 (2025 edition) mapped to AgentShield community rule IDs.
Every enterprise security team searching for "OWASP LLM AgentShield" lands here.

| OWASP ID | Name | AgentShield Rules |
|---|---|---|
| LLM01 | Prompt Injection | `direct-instruction-override`, `role-hijack`, `jailbreak-keyword`, `system-prompt-extraction`, `escape-sequence`, `token-manipulation`, `retrieval-embedded-system-tag`, `retrieval-instruction-delimiter`, `hidden-unicode-instruction`, `shadow-prompt-encoded` |
| LLM02 | Insecure Output Handling | `secret-key-exfil`, `pii-email-bulk`, `ssn-pattern`, `credit-card-pattern`, `phi-exfil-pattern`, `pci-pattern-detector` |
| LLM03 | Training Data Poisoning | `rag-context-injection`, `persistent-instruction-injection`, `memory-cross-session-contamination` |
| LLM04 | Model Denial of Service | `context-window-overflow`, `token-flood-dos`, `recursive-tool-loop` |
| LLM05 | Supply Chain Vulnerabilities | `plugin-manifest-tampering`, `unsigned-plugin-execution` |
| LLM06 | Sensitive Information Disclosure | `training-data-extraction`, `system-prompt-extraction`, `phi-exfil-pattern`, `pci-pattern-detector`, `secret-key-exfil` |
| LLM07 | Insecure Plugin Design | `plugin-chain-bypass`, `tool-call-injection`, `cross-agent-delegation-gate` |
| LLM08 | Excessive Agency | `ai-system-boundary-check`, `network-egress-audit`, `filesystem-write-attempt`, `cross-agent-delegation-gate` |
| LLM09 | Overreliance | `adversarial-suffix`, `hallucination-amplification` |
| LLM10 | Model Theft | `model-distillation-probe`, `api-key-harvest`, `training-data-extraction` |

## Detailed mapping

### LLM01 — Prompt Injection
The most prevalent LLM attack. Includes direct injection (user input overrides system prompt)
and indirect injection (malicious content in retrieved documents, tool outputs, or memory).

**Primary rules:** `direct-instruction-override`, `role-hijack`, `jailbreak-keyword`
**Secondary rules:** `shadow-prompt-encoded`, `retrieval-embedded-system-tag`, `hidden-unicode-instruction`

### LLM02 — Insecure Output Handling
Model output is passed to downstream systems (browser, shell, API) without sanitization.
AgentShield scans responses for patterns that indicate unsafe content before it leaves the session.

**Primary rules:** `secret-key-exfil`, `credit-card-pattern`, `ssn-pattern`

### LLM03 — Training Data Poisoning
Malicious content injected into training data or RAG context to manipulate model behavior
over multiple sessions.

**Primary rules:** `rag-context-injection`, `persistent-instruction-injection`

### LLM04 — Model Denial of Service
Crafted inputs that consume excessive compute, exhaust context windows, or trigger
recursive tool call loops.

**Primary rules:** `context-window-overflow`, `token-flood-dos`, `recursive-tool-loop`

### LLM05 — Supply Chain Vulnerabilities
Compromised plugin binaries, tampered manifests, or unsigned components in the agent
delivery pipeline.

**Primary rules:** `plugin-manifest-tampering`
**Note:** YubiKey signing enforcement (AgentShield substrate) mitigates this at the platform layer.

### LLM06 — Sensitive Information Disclosure
Model reveals training data, system prompts, or other sensitive context in its responses.

**Primary rules:** `system-prompt-extraction`, `training-data-extraction`, `phi-exfil-pattern`

### LLM07 — Insecure Plugin Design
Plugins with overly broad permissions, lack of input validation, or exploitable tool interfaces.

**Primary rules:** `plugin-chain-bypass`, `tool-call-injection`, `cross-agent-delegation-gate`

### LLM08 — Excessive Agency
Agent takes actions beyond its intended scope — writing files, making network requests,
delegating to other agents — without authorization.

**Primary rules:** `ai-system-boundary-check`, `network-egress-audit`, `filesystem-write-attempt`

### LLM09 — Overreliance
Users or systems blindly trust model output, enabling adversarially-crafted responses
to cause real-world harm.

**Primary rules:** `adversarial-suffix`, `hallucination-amplification`

### LLM10 — Model Theft
Extracting model weights or functionality through systematic API queries, distillation probes,
or credential theft enabling unauthorized access.

**Primary rules:** `model-distillation-probe`, `api-key-harvest`

---

*Based on [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)*
