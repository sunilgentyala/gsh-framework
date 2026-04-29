
# Gentyala-Sovereign Hunt (GSH) Framework

[![License](https://img.shields.io/github/license/sunilgentyala/gsh-framework)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0--beta-orange)](https://github.com/sunilgentyala/gsh-framework)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-red)](https://atlas.mitre.org/)
[![NIST CSF](https://img.shields.io/badge/NIST-CSF%202.0-blue)](https://www.nist.gov/cyberframework)
[![Stars](https://img.shields.io/github/stars/sunilgentyala/gsh-framework?style=social)](https://github.com/sunilgentyala/gsh-framework/stargazers)

**Author:** Sunil Gentyala, IEEE Senior Member | Lead Cybersecurity and AI Security Consultant, HCLTech  
**Contact:** [sunil.gentyala@ieee.org](mailto:sunil.gentyala@ieee.org)  
**License:** [Apache 2.0](LICENSE)

---

Most enterprise security stacks were not built for the threat surface that agentic AI creates. Endpoint agents cannot see what an LLM gateway is doing. SIEMs have no baselines for multi-agent tool call chains. The GSH Framework closes that gap.

GSH is an open-source research artifact for autonomous agentic AI threat hunting. It provides structured detection playbooks, behavioral baselining logic, and a policy-driven enforcement engine (Sovereign Sentinel) designed for the cognitive cyber domain: the operational layer where large language models, autonomous agents, and multi-agent pipelines interact with enterprise infrastructure.

All detection signals are mapped to MITRE ATLAS and NIST CSF 2.0, giving practitioners framework-aligned coverage they can operationalize immediately.

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
| [Hunt-001](https://github.com/sunilgentyala/gsh-framework/blob/main/playbooks/hunt-001-agentic-loop-detection.md) | Agentic Loop / Resource Exhaustion | High | Active |
| [Hunt-002](https://github.com/sunilgentyala/gsh-framework/blob/main/playbooks/hunt-002-ddi-tunneling-anomaly.md) | DDI Covert Channel / C2 via DNS | Critical | Active |
| [Hunt-003](https://github.com/sunilgentyala/gsh-framework/blob/main/playbooks/hunt-003-model-poisoning-baseline.md) | ML Model Poisoning / Behavioral Drift | Critical | Active |
| Hunt-004 | Rogue Agent / Unauthorized Tool Use | Critical | Coming Soon |

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/sunilgentyala/gsh-framework.git
cd gsh-framework
```

### 2. Review the Sentinel Policy

The default policy file is at the root of the repository:

```bash
cat sentinel-policy-default.yaml
```

Edit it to set your organization name, SIEM output destination, and egress allowlist before deploying.

### 3. Run a Hunt Playbook

Each playbook is a self-contained Markdown document with detection logic, data sources, MITRE ATLAS mapping, and response actions. Start with Hunt-001 for loop detection:

```bash
cat hunt-001-agentic-loop-detection.md
```

### 4. Read the Whitepaper

The full technical rationale, design decisions, and threat model are in:

```bash
cat GSH_Framework_Whitepaper.md
```

---

## Repository Structure

## Repository Structure

```
gsh-framework/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── GSH_Framework_Whitepaper.md
├── sentinel-policy-default.yaml
├── hunt-001-agentic-loop-detection.md
├── hunt-002-ddi-tunneling-anomaly.md
└── hunt-003-model-poisoning-baseline.md
```

---

## Threat Coverage

| Threat | MITRE ATLAS | MITRE ATT&CK | NIST CSF 2.0 |
|---|---|---|---|
| Agentic Loop / Resource Exhaustion | AML.T0048, AML.T0040 | | DE.AE-02, DE.CM-01, RS.MI-01 |
| DDI Covert Channel Exfiltration | AML.T0048, AML.T0051 | T1071.004, T1048, T1568 | DE.CM-01, DE.AE-04, PR.DS-01 |
| ML Model Poisoning / Behavioral Drift | AML.T0020, AML.T0043, AML.T0044 | | ID.RA-01, DE.AE-02, DE.CM-06 |
| Rogue Agent / Unauthorized Tool Use | AML.T0053 | | PR.PS-04, RS.AN-03 |

---

## Contributing

Security practitioners, AI safety researchers, and detection engineers are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a Pull Request.

High-priority contributions include: additional hunt playbooks, refined detection thresholds, and integration adapters for LangChain, AutoGen, CrewAI, and Haystack.

---

## Citation

If you use the GSH Framework in your research, please cite:

```bibtex
@misc{gentyala2026gsh,
  author       = {Gentyala, Sunil},
  title        = {The Gentyala-Sovereign Hunt (GSH): An Autonomous Agentic Framework
                  for Defending the Cognitive Cyber Domain},
  year         = {2026},
  howpublished = {Open Source Research Artifact, GitHub},
  url          = {https://github.com/sunilgentyala/gsh-framework}
}
```

---

## Security Vulnerabilities

To report a vulnerability in the GSH Framework itself, email [sunil.gentyala@ieee.org](mailto:sunil.gentyala@ieee.org) with the subject `[GSH Security Vulnerability] — [brief description]`. Do not open a public GitHub Issue. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full responsible disclosure policy.

---

## Related Work

- [ContextGuard](https://github.com/sunilgentyala/contextguard): Zero-trust middleware for Model Context Protocol (MCP) server security. Precision 100%, Recall 96.7%, F1 98.3% at 1.005ms latency.
- SC World: [MCP is the Backdoor Your Zero-Trust Architecture Forgot to Close](https://www.scworld.com)
- IEEE Senior Member Profile: [ORCID 0009-0005-2642-3479](https://orcid.org/0009-0005-2642-3479)
