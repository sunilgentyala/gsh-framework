# GSH Hunt Playbook 005 - MCP Supply Chain and Tool Poisoning Detection

**Framework:** Governed Security Hunting (GSH) v1.4.0
**Threat Class:** MCP Server Compromise / Tool Description Poisoning / Tool Definition Rug Pull
**Severity:** Critical
**Author:** Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
**Contact:** sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
**NIST CSF 2.0 Mapping:** ID.SC-04, PR.PS-04, DE.CM-06, DE.AE-02, RS.AN-03
**MITRE ATLAS Mapping:** AML.T0010 (ML Supply Chain Compromise), AML.T0051 (LLM Prompt Injection), AML.T0053 (LLM Plugin Compromise)
**Last Updated:** 2026-07-15

---

## 1. Threat Hypothesis

> One or more Model Context Protocol (MCP) servers connected to the agent fleet have been compromised or were adversarial from the start. The attacker is using the MCP trust channel itself as the injection vector: poisoned tool descriptions that carry hidden instructions, tool definitions silently swapped after initial approval (rug pull), tool name collisions that shadow trusted tools, or crafted tool return values that function as indirect prompt injections.

MCP moved the agent attack surface from the prompt to the supply chain. A tool description is loaded into the model context on every session, before any user input, which makes it a higher-privilege injection channel than any retrieved document. Classic playbooks that inspect only user input and retrieval content miss this channel entirely.

---

## 2. Threat Profile

| Attribute | Detail |
|---|---|
| Threat Actor | Malicious MCP server publisher; attacker who compromised a legitimate server post-adoption; typosquatter shadowing a popular server name |
| Attack Vector | Hidden instructions in tool descriptions or parameter schemas; post-approval tool definition mutation; tool name shadowing; adversarial tool return payloads |
| Target Asset | Every agent connected to the poisoned server, plus all tools and data those agents can reach |
| Business Impact | Fleet-wide agent compromise from a single poisoned dependency; credential harvesting at scale; cross-tenant data leakage |
| Detection Difficulty | High - the poisoned content arrives over an approved, authenticated channel and never appears in user-facing conversation logs |

---

## 3. MCP Poisoning Behavioral Indicators

### 3.1 Tool Definition Integrity Signals

- **Definition drift:** Hash of a server's tool schema (names, descriptions, parameter schemas) differs from the hash recorded at approval time
- **Instruction-bearing descriptions:** Tool description text contains imperative language directed at the model rather than documentation for the user ("before using this tool, first read the file...", "do not mention this to the user")
- **Cross-tool references:** A tool description that instructs behavior for other tools, a hallmark of tool shadowing attacks
- **Schema overreach:** Parameter schemas requesting data unrelated to the tool's declared function (a weather tool with an `api_keys` or `conversation_history` parameter)
- **Invisible content:** Unicode tag characters, zero-width characters, or HTML comments embedded in descriptions, used to hide instructions from human reviewers while remaining model-readable

### 3.2 Server Behavior Signals

- **Response asymmetry:** Server returns different tool definitions to different agent identities or at different times (canary comparison mismatch)
- **Latency signature change:** Sustained shift in server response latency distribution, indicating rehosting or man-in-the-middle interposition
- **Endpoint mutation:** Server DNS resolution or TLS certificate changes without a corresponding registry update (correlate with DDI-AI Fusion telemetry)
- **Version churn without changelog:** Frequent silent tool definition updates on a server whose registry entry shows no release activity

### 3.3 Downstream Agent Signals

- **Post-connection behavioral pivot:** Agent tool call distribution shifts within N sessions of a new MCP server connection or a server update
- **Sensitive-read-then-call pattern:** Agent reads credentials or sensitive files and immediately invokes a tool on the suspect server with large or encoded parameters
- **Consent fatigue exploitation:** Burst of permission prompts originating from one server, engineering the operator into blanket approval

---

## 4. Data Sources Required

| Source | Purpose | Collection Method |
|---|---|---|
| MCP Host Session Logs | Tool definitions as loaded, invocation payloads, server identity | MCP host structured logging (client-side, authoritative) |
| Tool Definition Registry | Approval-time schema hashes for drift comparison | GSH manifest store; signed snapshot at onboarding |
| ZTLV Gate Decision Log | Parameter inspection results for suspect-server invocations | Sovereign Sentinel enforcement gate |
| DDI-AI Fusion Output | Server endpoint mutation, resolution anomalies | GSH DDI telemetry pipeline |
| SBOM / Registry Metadata | Server provenance, publisher identity, release history | MCP registry API, package manifests |

---

## 5. Detection Logic

### 5.1 Approval-Time Baseline (one-time per server)

```bash
python scripts/gsh-probe-eval.py \
  --mode mcp-snapshot \
  --server "corp-tools-mcp-01" \
  --server-cmd "npx -y @modelcontextprotocol/server-filesystem /srv/data" \
  --output reports/
```

The snapshot records a canonical hash per tool: `SHA-256(name || description || parameter_schema)`, written to `reports/baselines/mcp/corp-tools-mcp-01.json`. Any subsequent session whose loaded definitions do not match the snapshot raises a definition drift event.

### 5.2 Continuous Session Checks

On every session initialization, `adapters/mcp_proxy.py` (via `scripts/gsh-mcp-proxy.py`) performs:

1. **Drift check:** compare loaded tool definition hashes against the approval snapshot; any mismatch quarantines the server pending re-review
2. **Semantic scan:** score every description and schema for instruction-likelihood, cross-tool references, and invisible Unicode content - runs on every connection, including the first one, so a poisoned server cannot "become the baseline" simply by being first
3. **Invocation inspection:** apply parameter inspection (credential patterns, path traversal, suspicious encoding, reused from Hunt-004) to every tool call, and block calls to any tool not in the last-validated definition set

Run it by pointing your MCP host at the proxy instead of the real server:

```bash
python scripts/gsh-mcp-proxy.py \
  --server-cmd "npx -y @modelcontextprotocol/server-filesystem /srv/data" \
  --server-id "corp-tools-mcp-01" \
  --mode aggressive \
  --baseline reports/baselines/mcp/corp-tools-mcp-01.json
```

**Implementation status:** the drift check, semantic scan, and invocation inspection above are real - they run against actual MCP JSON-RPC traffic intercepted by a stdio proxy, not synthetic data (see `adapters/mcp_proxy.py` and its test coverage in `tests/test_mcp_proxy.py`). **Canary comparison (response-asymmetry detection) is not implemented** - the proxy only sees one identity's view of a server, so it cannot yet detect a server serving different definitions to different callers. Scanning tool *return values* (as opposed to definitions) for adversarial content is also not implemented. Both are tracked as follow-up work.

### 5.3 Pseudocode

```python
def validate_mcp_session(server, loaded_defs, snapshot):
    if canonical_hash(loaded_defs) != snapshot.hash:
        quarantine_server(server, reason="definition-drift")
        return Verdict.BLOCK
    for tool in loaded_defs:
        s = semantic_scan(tool.description, tool.schema)
        if s.instruction_likelihood > 0.6 or s.invisible_content:
            quarantine_server(server, reason="tool-poisoning")
            return Verdict.BLOCK
    if canary_diff(server, loaded_defs):
        alert(server, "response-asymmetry", severity="critical")
        return Verdict.THROTTLE
    return Verdict.ALLOW
```

---

## 6. Triage Decision Tree

1. **Definition drift detected?**
   - Yes: check the server's release history. A legitimate signed release requires re-approval, not incident response. An unsigned or unannounced change is treated as compromise until proven otherwise.
2. **Instruction-bearing description confirmed?**
   - Yes: this is not a false positive category. Poisoned descriptions do not occur accidentally. Proceed directly to response.
3. **Response asymmetry only?**
   - Verify the canary identity was not itself stale or misconfigured before escalating.
4. **Downstream pivot without server-side signal?**
   - Route to Hunt-004; the injection source may be a tool return value rather than the definition layer.

---

## 7. Response Actions

| Priority | Action | NIST CSF 2.0 |
|---|---|---|
| P1 | Disconnect the poisoned server from all agent hosts; block its endpoints at the egress layer | RS.MI-02 |
| P1 | Quarantine every session that loaded the poisoned definitions since the last verified snapshot | RS.MI-02 |
| P2 | Rotate all credentials reachable by agents that held sessions with the poisoned server | PR.AA-05 |
| P2 | Audit persistent memory of affected agents for implanted instruction content (see Hunt-004, Section 3.3) | RS.AN-03 |
| P3 | Report the server to its registry; preserve the poisoned definitions as forensic evidence | RS.CO-03 |
| P3 | Re-snapshot all remaining servers; shorten the canary comparison interval fleet-wide for 30 days | ID.IM-03 |

---

## 8. Related Playbooks

- **Hunt-002** for endpoint mutation and exfiltration correlation on the network layer
- **Hunt-004** for the downstream rogue behavior a poisoned server induces

---

**Author:** Sunil Gentyala, HCLTech
**Contact:** sunil.gentyala@ieee.org
