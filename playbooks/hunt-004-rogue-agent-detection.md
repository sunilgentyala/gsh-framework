# GSH Hunt Playbook 004 - Rogue Agent Detection

**Framework:** Governed Security Hunting (GSH) v1.3.0
**Threat Class:** Rogue Agent / Unauthorized Tool Use / Indirect Prompt Injection
**Severity:** Critical
**Author:** Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
**Contact:** sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
**NIST CSF 2.0 Mapping:** PR.PS-04, DE.CM-01, DE.AE-02, RS.AN-03, RS.MI-02
**MITRE ATLAS Mapping:** AML.T0051 (LLM Prompt Injection), AML.T0053 (LLM Plugin Compromise), AML.T0054 (LLM Jailbreak)
**Last Updated:** 2026-07-15

---

## 1. Threat Hypothesis

> A deployed AI agent has deviated from its authorized behavioral envelope. It is executing tool calls outside its declared capability manifest, accessing data namespaces beyond its scope, exfiltrating context window contents, or operating under adversarially injected instructions introduced through retrieved documents, tool outputs, or MCP server responses. The agent maintains the outward appearance of normal operation while serving adversarial objectives.

Rogue agent behavior is the terminal stage of most agentic attack chains. Prompt injection, MCP server compromise, and memory poisoning are all mechanisms; the rogue agent executing unauthorized actions is the impact. This playbook detects the impact stage directly, so it provides coverage even when the initial compromise mechanism was novel or unknown.

---

## 2. Threat Profile

| Attribute | Detail |
|---|---|
| Threat Actor | External adversary via indirect prompt injection; compromised MCP server or tool; poisoned RAG corpus or vector memory; malicious insider using an agent as a proxy |
| Attack Vector | Adversarial content in retrieved documents, tool return values, agent-to-agent messages, or MCP server responses that overrides or supplements the system prompt |
| Target Asset | Agent tool ecosystem, API credentials, connected data stores, downstream agents in the pipeline |
| Business Impact | Unauthorized data access, privilege escalation, lateral movement through connected tools, regulatory exposure, reputational damage |
| Detection Difficulty | High - the agent's transport-layer identity remains valid; only its behavior diverges from baseline |

---

## 3. Rogue Behavior Indicators

### 3.1 Capability Manifest Violations

- **Out-of-manifest tool invocation:** Agent requests a tool that does not appear in its declared capability manifest
- **Parameter range breach:** Tool call parameters fall outside declared ranges (file paths above the permitted root, record counts far above task norms, wildcard queries where scoped queries are declared)
- **Namespace boundary crossing:** Agent reads or writes data namespaces outside its declared scope, including other agents' memory keys
- **Capability probing sequence:** A run of blocked invocation attempts across multiple distinct unauthorized tools within one session, indicating systematic boundary discovery

### 3.2 Semantic Injection Signals

- **Instruction-shaped retrieved content:** Retrieved documents or tool outputs containing imperative phrasing directed at the agent ("ignore previous instructions", "you must now", role reassignment language)
- **System prompt echo divergence:** Agent restates its objective in a form semantically distant from its configured system prompt (embedding cosine distance above threshold)
- **Behavioral pivot after retrieval:** Tool call pattern changes category immediately following a retrieval or MCP tool response event
- **Credential-shaped output:** Agent output or tool call parameters contain API-key-shaped strings, JWT fragments, or connection-string patterns

### 3.3 Exfiltration and Persistence Signals

- **Context-to-network correlation:** Sensitive strings observed in the agent context window subsequently appear encoded in outbound DNS queries or HTTP parameters (cross-correlate with Hunt-002)
- **Memory write anomaly:** Agent writes instruction-like content to persistent memory stores, creating a self-reinfection vector for future sessions
- **Session scope creep:** Cumulative count of distinct tools invoked per session exceeds the 95th percentile of the agent's 30-day baseline
- **Off-hours autonomy:** Agent activity in periods with no correlated upstream user requests or scheduled triggers

---

## 4. Data Sources Required

| Source | Purpose | Collection Method |
|---|---|---|
| ZTLV Gate Decision Log | Manifest violations, blocked invocations, parameter inspection results | Sovereign Sentinel enforcement gate audit log |
| LLM Gateway Logs | Full prompt/response payloads, session lineage, token accounting | API middleware logging layer |
| Agent Orchestration Logs | Tool call sequences, retrieval events, agent-to-agent messages | LangChain / AutoGen / CrewAI / MCP host callback hooks |
| Vector Memory Store Audit Logs | Memory write anomalies, cross-namespace reads | Pinecone / Weaviate / Chroma audit logs |
| DDI-AI Fusion Output | Exfiltration correlation signals | GSH DDI telemetry pipeline (see Hunt-002) |

---

## 5. Detection Logic

### 5.1 Sovereign Sentinel Deployment

```bash
python scripts/gsh-sentinel-deploy.py \
  --target "llm-gateway-01" \
  --mode "standard" \
  --playbook "hunt-004" \
  --policy configs/sentinel-policy-default.yaml \
  --baseline-window 30d
```

### 5.2 Composite Rogue Score

The Sentinel computes a per-session composite rogue score R as a weighted sum:

```
R = 0.35 * manifest_violation_score
  + 0.25 * semantic_injection_score
  + 0.20 * exfiltration_correlation_score
  + 0.20 * behavioral_drift_score
```

- `manifest_violation_score`: normalized count of ZTLV blocks and near-boundary invocations in the session
- `semantic_injection_score`: maximum instruction-likelihood score across all retrieved content and tool outputs entering the context window
- `exfiltration_correlation_score`: strength of correlation between context window sensitive-string set and outbound encoded traffic
- `behavioral_drift_score`: distance between session tool call distribution and the agent's 30-day baseline distribution

**Thresholds (default policy):**

| R Score | Action |
|---|---|
| R < 0.4 | Log only |
| 0.4 <= R < 0.7 | Alert to SIEM; elevate session to enhanced telemetry |
| R >= 0.7 | Quarantine session; revoke session-scoped tokens; alert with full context capture |

### 5.3 Pseudocode

```python
def evaluate_session(session, manifest, baseline):
    r = (0.35 * manifest_violations(session, manifest)
       + 0.25 * max_injection_score(session.context_inputs)
       + 0.20 * exfil_correlation(session, ddi_stream)
       + 0.20 * drift(session.tool_calls, baseline))
    if r >= 0.7:
        quarantine(session); revoke_tokens(session); alert(session, r, "critical")
    elif r >= 0.4:
        alert(session, r, "high"); enhance_telemetry(session)
    return r
```

---

## 6. Triage Decision Tree

1. **Was the triggering signal a manifest violation?**
   - Yes: check whether a recent legitimate capability change was not yet reflected in the manifest. If the manifest is current, treat as confirmed unauthorized action and proceed to response.
   - No: continue.
2. **Did a high injection score precede the behavioral pivot?**
   - Yes: capture the retrieved content or tool output that carried the injection; identify the source (document, URL, MCP server, upstream agent) for containment.
   - No: continue.
3. **Does exfiltration correlation exist?**
   - Yes: escalate immediately to incident response; invoke Hunt-002 response actions in parallel.
   - No: evaluate as behavioral drift; compare against Hunt-003 findings to rule out model-level causes.
4. **False positive check:** new task types, newly integrated tools, and prompt template updates all legitimately shift behavior. Confirm with the owning team before enforcement tuning.

---

## 7. Response Actions

| Priority | Action | NIST CSF 2.0 |
|---|---|---|
| P1 | Quarantine the agent session; freeze its memory namespace snapshot for forensics | RS.MI-02 |
| P1 | Revoke session-scoped API tokens and rotate any credentials observed in the context window | PR.AA-05, RS.MI-02 |
| P2 | Trace and neutralize the injection source: purge poisoned documents, disconnect the offending MCP server or tool | RS.AN-03 |
| P2 | Audit persistent memory for injected instruction content before the agent is returned to service | RS.AN-03 |
| P3 | Update the capability manifest and ZTLV policy with findings; add the injection pattern to the semantic inspection corpus | ID.IM-03 |
| P3 | Feed confirmed indicators into the adaptive baseline update (GSH Defense Loop Stage 4) | ID.IM-01 |

---

## 8. Related Playbooks

- **Hunt-002** for the network exfiltration leg of a rogue agent attack chain
- **Hunt-003** to rule out model poisoning as the root cause of behavioral change
- **Hunt-005** when the injection source is an MCP server or tool description

---

**Author:** Sunil Gentyala, HCLTech
**Contact:** sunil.gentyala@ieee.org
