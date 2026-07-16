# Governed Security Hunting (GSH) Framework

[![License](https://img.shields.io/github/license/sunilgentyala/gsh-framework)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.5.0-brightgreen)](https://github.com/sunilgentyala/gsh-framework)
[![Paper](https://img.shields.io/badge/paper-in%20preparation-lightgrey)](https://github.com/sunilgentyala/gsh-framework#research)
[![Website](https://img.shields.io/badge/website-live-blue)](https://sunilgentyala.github.io/gsh-framework/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-red)](https://atlas.mitre.org/)
[![NIST CSF](https://img.shields.io/badge/NIST-CSF%202.0-blue)](https://www.nist.gov/cyberframework)
[![Stars](https://img.shields.io/github/stars/sunilgentyala/gsh-framework?style=social)](https://github.com/sunilgentyala/gsh-framework/stargazers)

**Author:** Sunil Gentyala, IEEE Senior Member | Lead Cybersecurity and AI Security Consultant, HCLTech
**Contact:** [sunil.gentyala@ieee.org](mailto:sunil.gentyala@ieee.org)
**Website:** [sunilgentyala.github.io/gsh-framework](https://sunilgentyala.github.io/gsh-framework/)
**License:** [Apache 2.0](LICENSE)

---

Most enterprise security stacks were not built for the threat surface that agentic AI creates. Endpoint agents cannot see what an LLM gateway is doing. SIEMs have no baselines for multi-agent tool call chains. The GSH Framework closes that gap.

GSH is an open-source research artifact for autonomous agentic AI threat hunting. It provides structured detection playbooks, behavioral baselining logic, and a policy-driven enforcement engine (Sovereign Sentinel) designed for the cognitive cyber domain: the operational layer where large language models, autonomous agents, and multi-agent pipelines interact with enterprise infrastructure.

All detection signals are mapped to MITRE ATLAS and NIST CSF 2.0, giving practitioners framework-aligned coverage they can operationalize immediately.

---

## Current Status

The hunt playbooks, detection logic, thresholds, and policy schema are complete and documented.

**Hunt-001 through Hunt-004** (`scripts/gsh-sentinel-deploy.py`, `scripts/gsh-probe-eval.py`) implement the full baselining, drift-scoring, and ZTLV enforcement logic end-to-end, but ship with a **synthetic telemetry generator** (clearly marked `SIMULATION MODE` in the script output and `# Replace this block` in source) so you can see the detection logic run without a live environment first. Wiring `--target` to a real LLM gateway event stream is the integration step you complete before using this for actual enforcement.

**Hunt-005** (`adapters/mcp_proxy.py`, `scripts/gsh-mcp-proxy.py`) is different: it is a real MCP JSON-RPC stdio proxy that intercepts *actual* tool definitions and tool calls between a real MCP host and a real MCP server - approval-time schema hashing, drift detection, semantic poisoning scans, and per-call enforcement (permit/alert/block) all run against live traffic, not synthetic data. See `tests/test_mcp_proxy.py` for a subprocess-driven end-to-end test of the CLI. Known gaps: canary/response-asymmetry comparison and tool-return-value scanning are not implemented yet (see `playbooks/hunt-005-mcp-tool-poisoning.md` section 5.2 for details), and only the stdio transport is supported (not streamable HTTP/SSE MCP servers).

**SIEM output** (`adapters/splunk_hec.py`, `adapters/elastic_bulk.py`, `adapters/windows_eventlog.py`) is also real: set `siem_output: splunk`, `siem_output: elastic`, or `siem_output: windows_eventlog` in your policy YAML (see `configs/sentinel-policy-default.yaml`) and both `gsh-sentinel-deploy.py` and `gsh-mcp-proxy.py` will send findings there (Splunk HEC / Elasticsearch `_bulk` over real HTTP, or a registered source in the local Windows Application Event Log). A failed or unconfigured send always falls back to local file output - a finding is never silently dropped. The Windows Event Log adapter is Windows-only and requires `pywin32`; on any other platform (or without `pywin32`) it logs a warning and falls back like any other unconfigured destination. See `tests/test_siem_adapters.py` and `tests/test_windows_eventlog.py` (the latter includes a test that writes a real event and reads it back, not just a mocked one).

**LangChain telemetry** (`adapters/langchain_callback.py`) is a fourth real integration: `GSHCallbackHandler` attaches to any LangChain `Runnable`/agent via `config={"callbacks": [handler]}` and evaluates real tool-call rate, token velocity, unauthorized-tool invocations, and suspicious call parameters against Hunt-001/Hunt-004 thresholds - no synthetic data. **Important limitation:** LangChain callback handlers are notification hooks, not gates - by default LangChain swallows exceptions raised inside a callback rather than stopping the tool call, so this adapter can only alert, never block. Every finding it emits is explicitly marked `enforcement_mode: "alert_only"` and `action_taken: "ALERTED"`, regardless of policy mode. It also has no visibility into DNS queries (Hunt-002). See `tests/test_langchain_callback.py`, tested against `langchain-core` 1.4.x.

See [open issues](https://github.com/sunilgentyala/gsh-framework/issues) for remaining work (SARIF reporting, the Hunt-006 playbook, and the Docker Compose demo).

---

## Version History

Full release notes (including known limitations at each release) are on the [Releases page](https://github.com/sunilgentyala/gsh-framework/releases). Summary:

| Version | Highlights |
|---|---|
| [v1.5.0](https://github.com/sunilgentyala/gsh-framework/releases/tag/v1.5.0) | Real Windows Application Event Log output adapter (`adapters/windows_eventlog.py`); optional and Windows-only, safe no-op elsewhere |
| [v1.4.0](https://github.com/sunilgentyala/gsh-framework/releases/tag/v1.4.0) | Real LangChain callback adapter (`adapters/langchain_callback.py`) for Hunt-001/Hunt-004 telemetry - alert-only by design, since LangChain callbacks cannot block a tool call |
| [v1.3.0](https://github.com/sunilgentyala/gsh-framework/releases/tag/v1.3.0) | Real Splunk HEC and Elastic bulk SIEM output adapters, wired into both the Sentinel and the MCP proxy via a shared dispatcher; a failed/unconfigured SIEM send now always falls back to local file output |
| [v1.2.0](https://github.com/sunilgentyala/gsh-framework/releases/tag/v1.2.0) | Real MCP JSON-RPC stdio proxy for Hunt-005 (`adapters/mcp_proxy.py`) - schema-hash drift detection, semantic poisoning scan, and real per-call enforcement against live MCP traffic, not simulated |
| [v1.1.0](https://github.com/sunilgentyala/gsh-framework/releases/tag/v1.1.0) | Hunt-004 (rogue agent) completed; Hunt-005 (MCP supply chain / tool poisoning) added as a playbook; project website launched |
| v1.0.0-beta | Initial public release: Hunt-001 through Hunt-003 playbooks, Sentinel reference scripts (synthetic telemetry), default policy schema |

---

## Framework Components

| Component | Description |
|---|---|
| **Sovereign Sentinel** | Policy-driven behavioral enforcement agent deployed alongside LLM gateways |
| **Hunt Playbooks** | Structured threat detection playbooks for high-severity agentic AI threats |
| **DDI-AI Fusion** | DNS/DHCP/IPAM telemetry layer with AI-agent-aware baselining |
| **Zero-Trust Logic Validation (ZTLV) Gate** | Per-invocation tool call authorization engine |
| **Behavioral Baseline Engine** | Continuous model output drift detection and probe evaluation pipeline |

---

## Hunt Playbooks

| Playbook | Threat Class | Severity | Status |
|---|---|---|---|
| [Hunt-001](playbooks/hunt-001-agentic-loop-detection.md) | Agentic Loop / Resource Exhaustion | High | Active |
| [Hunt-002](playbooks/hunt-002-ddi-tunneling-anomaly.md) | DDI Covert Channel / C2 via DNS | Critical | Active |
| [Hunt-003](playbooks/hunt-003-model-poisoning-baseline.md) | ML Model Poisoning / Behavioral Drift | Critical | Active |
| [Hunt-004](playbooks/hunt-004-rogue-agent-detection.md) | Rogue Agent / Unauthorized Tool Use | Critical | Active |
| [Hunt-005](playbooks/hunt-005-mcp-tool-poisoning.md) | MCP Supply Chain / Tool Poisoning | Critical | Active |

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/sunilgentyala/gsh-framework.git
cd gsh-framework
pip install -r requirements.txt
```

### 2. Review the Sentinel Policy

```bash
cat configs/sentinel-policy-default.yaml
```

Edit it to set your organization name, SIEM output destination, and egress allowlist before deploying.

### 3. Deploy a Sovereign Sentinel

Start in passive mode to build a 7-day behavioral baseline, then move to standard enforcement:

```bash
python scripts/gsh-sentinel-deploy.py \
  --target "llm-gateway-01" \
  --mode passive \
  --policy configs/sentinel-policy-default.yaml \
  --baseline-window 7d
```

As shipped, this generates synthetic telemetry (`SIMULATION MODE`, logged at startup) so you can watch the baselining and scoring logic run immediately. Replace the telemetry-generation block noted in the script (real LLM gateway/API metrics or LangChain callbacks) to run it against live traffic.

### 4. Run the MCP Proxy (Hunt-005 - real enforcement, not simulated)

Unlike step 3, this runs against real MCP traffic. First record an approval-time snapshot of the server's tool definitions:

```bash
python scripts/gsh-probe-eval.py --mode mcp-snapshot \
  --server "corp-tools-mcp-01" \
  --server-cmd "npx -y @modelcontextprotocol/server-filesystem /srv/data"
```

Then configure your MCP host to launch the proxy instead of the real server directly:

```bash
python scripts/gsh-mcp-proxy.py \
  --server-cmd "npx -y @modelcontextprotocol/server-filesystem /srv/data" \
  --server-id "corp-tools-mcp-01" \
  --mode standard \
  --baseline reports/baselines/mcp/corp-tools-mcp-01.json
```

The proxy will alert on (or, in `--mode aggressive`, block) definition drift, poisoned tool descriptions, invisible Unicode content, and unauthorized tool calls. See `playbooks/hunt-005-mcp-tool-poisoning.md` for the full detection logic.

### 5. Wire a LangChain Agent to a Sentinel (real telemetry, alert-only)

```bash
pip install langchain-core
```

```python
from adapters.langchain_callback import GSHCallbackHandler

handler = GSHCallbackHandler(
    target="my-langchain-agent",
    allowlist=["web_search", "calculator"],   # unlisted tools trigger an immediate alert
)

# Attach to any LLM, tool, or chain via the standard LangChain callbacks config:
llm.invoke(prompt, config={"callbacks": [handler]})
my_tool.invoke(args, config={"callbacks": [handler]})

handler.flush()  # evaluate any partial window at the end of a run
```

This is alert-only, not enforcement - see `adapters/langchain_callback.py`'s module docstring for why LangChain callback handlers cannot reliably block a tool call.

### 6. Run a Hunt Playbook

Each playbook is a self-contained Markdown document with detection logic, data sources, MITRE ATLAS mapping, triage decision tree, and response actions. Start with Hunt-001 for loop detection:

```bash
cat playbooks/hunt-001-agentic-loop-detection.md
```

---

## Research

A companion research paper covering the full technical rationale, design decisions, and threat model is in preparation and not yet submitted. Per publication policy, the manuscript is not included in this repository. For research inquiries, contact [sunil.gentyala@ieee.org](mailto:sunil.gentyala@ieee.org).

---

## Repository Structure

```
gsh-framework/
├── README.md
├── LICENSE
├── CITATION.cff
├── CONTRIBUTING.md
├── requirements.txt
├── adapters/
│   ├── mcp_proxy.py                 # Real MCP JSON-RPC proxy (Hunt-005)
│   ├── langchain_callback.py        # Real LangChain telemetry, alert-only (Hunt-001/004)
│   ├── splunk_hec.py                # Real Splunk HTTP Event Collector output
│   ├── elastic_bulk.py              # Real Elasticsearch/OpenSearch _bulk output
│   ├── windows_eventlog.py          # Real Windows Application Event Log output
│   └── siem_dispatch.py             # Shared dispatcher used by all three SIEM adapters
├── configs/
│   └── sentinel-policy-default.yaml
├── docs/
│   └── index.html                  # Project website (GitHub Pages)
├── playbooks/
│   ├── hunt-001-agentic-loop-detection.md
│   ├── hunt-002-ddi-tunneling-anomaly.md
│   ├── hunt-003-model-poisoning-baseline.md
│   ├── hunt-004-rogue-agent-detection.md
│   └── hunt-005-mcp-tool-poisoning.md
├── probes/
│   └── standardized-probe-set-v1.json
├── scripts/
│   ├── ddi-log-parser-ai.py
│   ├── gsh-mcp-proxy.py            # CLI for adapters/mcp_proxy.py
│   ├── gsh-probe-eval.py
│   └── gsh-sentinel-deploy.py
├── tests/
│   ├── test_mcp_proxy.py
│   ├── test_siem_adapters.py
│   ├── test_windows_eventlog.py
│   ├── test_langchain_callback.py
│   └── fixtures/
│       ├── mock_mcp_server.py      # Minimal MCP stdio server for testing
│       └── mock_http_sink.py       # Minimal HTTP server for testing SIEM adapters
├── baselines/
└── reports/
```

---

## Threat Coverage

| Threat | MITRE ATLAS | MITRE ATT&CK | NIST CSF 2.0 |
|---|---|---|---|
| Agentic Loop / Resource Exhaustion | AML.T0048, AML.T0040 | | DE.AE-02, DE.CM-01, RS.MI-01 |
| DDI Covert Channel Exfiltration | AML.T0048, AML.T0051 | T1071.004, T1048, T1568 | DE.CM-01, DE.AE-04, PR.DS-01 |
| ML Model Poisoning / Behavioral Drift | AML.T0020, AML.T0043, AML.T0044 | | ID.RA-01, DE.AE-02, DE.CM-06 |
| Rogue Agent / Unauthorized Tool Use | AML.T0051, AML.T0053, AML.T0054 | | PR.PS-04, DE.CM-01, RS.AN-03 |
| MCP Supply Chain / Tool Poisoning | AML.T0010, AML.T0051, AML.T0053 | T1195 | ID.SC-04, PR.PS-04, DE.CM-06 |

---

## Contributing

Security practitioners, AI safety researchers, and detection engineers are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a Pull Request.

High-priority contributions include: additional hunt playbooks, refined detection thresholds, and integration adapters for LangChain, AutoGen, CrewAI, and MCP host platforms.

---

## Citation

If you use the GSH Framework in your research, please cite:

```bibtex
@misc{gentyala2026gsh,
  author       = {Gentyala, Sunil},
  title        = {The Governed Security Hunting (GSH): An Autonomous Agentic Framework
                  for Defending the Cognitive Cyber Domain},
  year         = {2026},
  howpublished = {Open Source Research Artifact, GitHub},
  url          = {https://github.com/sunilgentyala/gsh-framework}
}
```

---

## Security Vulnerabilities

To report a vulnerability in the GSH Framework itself, use [GitHub's private vulnerability reporting](https://github.com/sunilgentyala/gsh-framework/security/advisories/new) or email [sunil.gentyala@ieee.org](mailto:sunil.gentyala@ieee.org) with the subject `[GSH Security Vulnerability] - [brief description]`. Do not open a public GitHub Issue. See [SECURITY.md](SECURITY.md) for the full policy, supported versions, and response timeline.

---

## Related Work

- [ContextGuard](https://github.com/sunilgentyala/contextguard): Zero-trust middleware for Model Context Protocol (MCP) server security. Precision 100%, Recall 96.7%, F1 98.3% at 1.005ms latency.
- [ARGUS](https://github.com/sunilgentyala/argus): LLM application security scanner.
- IEEE Senior Member Profile: [ORCID 0009-0005-2642-3479](https://orcid.org/0009-0005-2642-3479)
