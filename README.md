# Gentyala-Sovereign Hunt (GSH) Framework

**Version:** 1.0.0-beta  
**Author:** Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech  
**Contact:** sunil.gentyala@ieee.org | gentyalas@hcltech.com
**License:** See [LICENSE](LICENSE)

---

## Overview

The Gentyala-Sovereign Hunt (GSH) Framework is an open-source research artifact for autonomous agentic AI threat hunting. It provides structured detection playbooks, behavioral baselining logic, and a policy-driven enforcement engine (Sovereign Sentinel) designed to defend the cognitive cyber domain — the operational layer where large language models, autonomous agents, and multi-agent pipelines interact with enterprise infrastructure.

GSH addresses a fundamental gap in the current security tooling landscape: existing endpoint and network detection frameworks were not designed for the threat surface introduced by agentic AI systems. The framework maps all detection signals to MITRE ATLAS and NIST CSF 2.0, providing practitioner-ready coverage for the threats that matter most in AI-enabled enterprise environments.

---

## Framework Components

| Component | Description |
|---|---|
| **Sovereign Sentinel** | Policy-driven behavioral enforcement agent deployed alongside LLM gateways |
| **Hunt Playbooks** | Structured threat detection playbooks (see `/playbooks/`) |
| **DDI-AI Fusion** | DNS/DHCP/IPAM telemetry layer with AI-agent-aware baselining |
| **Zero-Trust Logic Validation (ZTLV) Gate** | Per-invocation tool call authorization engine |
| **Behavioral Baseline Engine** | Continuous model output drift detection and probe evaluation pipeline |

---

## Hunt Playbooks

| Playbook | Threat Class | Severity |
|---|---|---|
| [Hunt-001](playbooks/hunt-001-agentic-loop-detection.md) | Agentic Loop / Resource Exhaustion | High |
| [Hunt-002](playbooks/hunt-002-ddi-tunneling-anomaly.md) | DDI Covert Channel / C2 via DNS | Critical |
| [Hunt-003](playbooks/hunt-003-model-poisoning-baseline.md) | ML Model Poisoning / Behavioral Drift | Critical |
| [Hunt-004](https://github.com/sunilgentyala/gsh-framework/blob/main/playbooks/hunt-004-rogue-agent-detection.md) | Rogue Agent Detection | Critical |

---

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/sunilgentyala/gsh-framework.git
cd gsh-framework
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure the Sentinel Policy

Edit `configs/sentinel-policy-default.yaml` to set your organization name, SIEM output destination, and egress allowlist.

### 4. Run Passive Baseline (Recommended First Step)
```bash
python scripts/gsh-sentinel-deploy.py \
  --target "llm-gateway-01" \
  --mode "passive" \
  --baseline-window 7d
```

Allow the sentinel to operate in passive mode for at least 7 days before activating enforcement to establish accurate behavioral baselines.

### 5. Activate Standard Enforcement
```bash
python scripts/gsh-sentinel-deploy.py \
  --target "llm-gateway-01" \
  --mode "standard" \
  --policy configs/sentinel-policy-default.yaml
```

---

## Repository Structure
```
gsh-framework/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── requirements.txt
├── playbooks/
│   ├── hunt-001-agentic-loop-detection.md
│   ├── hunt-002-ddi-tunneling-anomaly.md
│   └── hunt-003-model-poisoning-baseline.md
├── configs/
│   └── sentinel-policy-default.yaml
├── scripts/
│   ├── gsh-sentinel-deploy.py
│   ├── ddi-log-parser-ai.py
│   └── gsh-probe-eval.py
├── probes/
│   └── standardized-probe-set-v1.json
├── baselines/
├── agents/
│   └── manifests/
├── docs/
│   └── GSH_Framework_Whitepaper.md
├── reports/
├── tests/
└── logs/
```

---

## Threat Coverage

| Threat | MITRE ATLAS | MITRE ATT&CK | NIST CSF 2.0 |
|---|---|---|---|
| Agentic Loop / Resource Exhaustion | AML.T0048, AML.T0040 | | DE.AE-02, DE.CM-01, RS.MI-01 |
| DDI Covert Channel Exfiltration | AML.T0048, AML.T0051 | T1071.004, T1048, T1568 | DE.CM-01, DE.AE-04, PR.DS-01 |
| ML Model Poisoning | AML.T0020, AML.T0043, AML.T0044 | | ID.RA-01, DE.AE-02, DE.CM-06 |
| Rogue Agent / Unauthorized Tool Use | AML.T0053 | | PR.PS-04, RS.AN-03 |

---

## Contributing

Contributions from security practitioners, AI safety researchers, and detection engineers are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a Pull Request.

High-priority contributions include additional hunt playbooks, refined detection thresholds, and integration adapters for LangChain, AutoGen, CrewAI, and Haystack.

---

## Citation

If you use the GSH framework in your research, please cite:
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

To report a security vulnerability in the GSH framework itself, please email sunil.gentyala@ieee.org with the subject line `[GSH Security Vulnerability] — [brief description]`. Do not open a public GitHub Issue. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full responsible disclosure policy.


---

## License

See [LICENSE](LICENSE) for terms.
