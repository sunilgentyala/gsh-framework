# Contributing to the Gentyala-Sovereign Hunt (GSH) Framework

Thank you for your interest in contributing to the GSH framework. This project is an open-source research artifact designed to advance the practice of agentic AI threat hunting. Contributions from security practitioners, AI safety researchers, and detection engineers are welcome and encouraged.

---

## Table of Contents

1. [Code of Conduct](#1-code-of-conduct)
2. [What We Are Looking For](#2-what-we-are-looking-for)
3. [What We Are Not Looking For](#3-what-we-are-not-looking-for)
4. [How to Contribute](#4-how-to-contribute)
5. [Playbook Contribution Standards](#5-playbook-contribution-standards)
6. [Detection Logic Standards](#6-detection-logic-standards)
7. [Pull Request Process](#7-pull-request-process)
8. [Issue Reporting](#8-issue-reporting)
9. [Security Vulnerabilities](#9-security-vulnerabilities)
10. [Attribution and Citation](#10-attribution-and-citation)

---

## 1. Code of Conduct

All contributors are expected to engage professionally and constructively. This project operates in the intersection of AI security and threat intelligence research. Contributions must be made in good faith for defensive purposes. Any contribution that could primarily serve to facilitate attacks against AI systems or their users will be rejected without discussion.

---

## 2. What We Are Looking For

### High-Priority Contributions

- **Additional hunt playbooks** for agentic threat classes not yet covered (see the open issues list for requested playbooks)
- **Refined detection thresholds** supported by data from real-world deployments or controlled experiments
- **False positive mitigation patterns** documented from operational experience with the existing playbooks
- **Integration adapters** for additional LLM gateways, orchestration frameworks (LangChain, AutoGen, CrewAI, Haystack, DSPy), DDI platforms, and SIEM systems
- **Probe set expansions** for the model poisoning detection playbook (Hunt-003), particularly for specialized domain models
- **CDN and known-good domain allowlist contributions** for the DDI tunneling playbook (Hunt-002)
- **MITRE ATLAS technique mappings** for new or updated agentic threat techniques

### Secondary Contributions

- Documentation improvements, clarifications, and corrections
- Translation of playbooks into additional languages for global practitioner accessibility
- Architecture diagrams and visual aids for the framework documentation
- Performance benchmarking data for the detection scripts

---

## 3. What We Are Not Looking For

- Offensive tooling, attack scripts, or content that primarily serves to facilitate prompt injection, model poisoning, or other agentic attacks
- Contributions that introduce dependencies on proprietary, non-auditable third-party services without a clear open-source alternative
- Threshold changes that reduce detection sensitivity without documented justification from operational data
- Playbooks targeting specific vendor products in ways that could constitute disparagement rather than neutral security research

---

## 4. How to Contribute

### Step 1: Open an Issue First

Before writing code or a playbook, open a GitHub Issue to describe what you want to contribute and why. This prevents duplicate effort and allows the maintainers to provide early guidance on whether the contribution fits the project's direction.

Use the appropriate issue template:
- **New Playbook Proposal** — for new hunt playbooks
- **Threshold Refinement** — for changes to existing detection thresholds
- **Integration Adapter** — for new platform integrations
- **Bug Report** — for errors in existing detection logic or documentation
- **General Enhancement** — for anything else

### Step 2: Fork and Branch

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR-USERNAME/gsh-framework.git
cd gsh-framework

# Create a branch named for your contribution
git checkout -b playbook/hunt-005-supply-chain-compromise
# or
git checkout -b fix/hunt-002-cdn-false-positive
# or
git checkout -b adapter/langchain-callback-hook
```

### Step 3: Make Your Changes

Follow the standards in Sections 5 and 6 for playbooks and detection logic respectively.

### Step 4: Test Your Changes

For detection scripts:

```bash
# Run the test suite
python -m pytest tests/ -v

# If adding new detection logic, include tests in tests/
# Test files must be named test_{component}.py
```

For playbooks, have at least one colleague review the logic before submitting. Document any test environment used to validate the detection thresholds.

### Step 5: Submit a Pull Request

Submit a Pull Request from your branch to `main`. Reference the Issue number in the PR description. Complete all sections of the PR template.

---

## 5. Playbook Contribution Standards

All hunt playbooks must follow the GSH Playbook Template structure. The required sections are:

1. **Metadata block** — Framework version, threat class, severity, author contact, NIST CSF 2.0 mapping, MITRE ATLAS mapping, last updated date
2. **Threat Hypothesis** — A single declarative statement of the threat condition the playbook detects, written in the present tense
3. **Threat Profile** — Tabular format covering threat actor, attack vector, target asset, business impact, and detection difficulty
4. **Behavioral Indicators** — Organized into subsections by signal type (tool call, network, infrastructure, etc.)
5. **Data Sources Required** — Tabular format with source, purpose, and collection method
6. **Detection Logic** — Includes Sentinel deployment command, at least one Python detection function, and a threshold reference table
7. **Triage Decision Tree** — ASCII art decision tree following the established GSH format
8. **Response Actions** — Separated into Immediate (automated), Short-Term (human analyst), and Long-Term (post-incident)
9. **False Positive Considerations** — At least three documented false positive scenarios with mitigations
10. **NIST CSF 2.0 and MITRE ATLAS Mapping** — Full tabular mapping of each detection signal
11. **References** — Minimum three, maximum eight, all verified and accessible

**Naming convention:** `hunt-{NNN}-{threat-class-slug}.md` where NNN is a zero-padded three-digit number.

**Severity ratings:**

| Rating | Definition |
|---|---|
| Critical | Immediate containment required; direct evidence of active compromise or data exfiltration |
| High | Strong indicators of malicious activity; manual triage required within 1 hour |
| Medium | Anomalous behavior detected; triage required within 4 hours |
| Low | Weak signal; log and monitor |

---

## 6. Detection Logic Standards

All Python detection code contributed to the `scripts/` directory must meet the following standards:

**Style:**
- PEP 8 compliant
- Type hints on all function signatures
- Docstrings on all public functions (Google docstring format)
- No use of `eval()`, `exec()`, or `__import__()`
- No hardcoded credentials, API keys, or organization-specific values

**Structure:**
- Pure functions wherever possible (input in, result out, no side effects)
- Return structured dictionaries with consistent key names: `detected`, `severity`, `details`, `timestamp`
- All severity values must be one of: `"Critical"`, `"High"`, `"Medium"`, `"Low"`, `"None"`

**Dependencies:**
- Minimize new dependencies. Prefer the Python standard library.
- If a new dependency is required, add it to `requirements.txt` with a pinned version
- All dependencies must have an OSI-approved open-source license

**Tests:**
- Every detection function must have at least one positive test case (where the threat is present) and one negative test case (where it is absent)
- Use `pytest` and standard fixtures; no test framework modifications

**Example function signature:**

```python
def detect_threat_signal(
    input_data: dict,
    threshold: float = 0.80,
    baseline: dict | None = None
) -> dict:
    """
    Detect [threat signal name] in the provided input data.

    Args:
        input_data: Structured telemetry data from [source].
        threshold: Detection sensitivity threshold. Default: 0.80.
        baseline: Optional pre-computed baseline for comparison.

    Returns:
        dict with keys: detected (bool), severity (str), details (dict), timestamp (str).
    """
```

---

## 7. Pull Request Process

1. Ensure your branch is up to date with `main` before submitting
2. Complete all sections of the PR template; incomplete PRs will not be reviewed
3. Link the Issue your PR addresses in the description
4. All PRs require at least one maintainer review and approval before merging
5. PRs that change detection thresholds in existing playbooks must include a written justification with supporting data or references
6. The project maintainer reserves the right to request threshold or logic changes before approval

**PR title format:**

```
[playbook] Add Hunt-005: Supply Chain Compromise Detection
[fix] Hunt-002: Reduce CDN false positive rate for Fastly domains
[adapter] Add LangChain callback hook for ZTLV gate integration
[docs] Clarify baseline window requirements in Hunt-003
```

---

## 8. Issue Reporting

### Bug Reports

Include in every bug report:
- GSH framework version
- Operating system and Python version
- The exact command or code that triggered the issue
- The expected behavior and the actual behavior
- Relevant log output (redact any sensitive or organization-specific information)

### Threshold Refinement Requests

Include:
- The specific threshold and playbook
- Evidence that the current threshold is producing false positives or false negatives (deployment context, volume, nature of the errors)
- A proposed revised threshold with supporting rationale

---

## 9. Security Vulnerabilities

If you discover a security vulnerability in the GSH framework itself (including its detection scripts, configuration handling, or Sentinel deployment mechanism), please do not open a public GitHub Issue.

Report security vulnerabilities directly to the project maintainer:

- sunil.gentyala@ieee.org
- Subject line: `[GSH Security Vulnerability] — [brief description]`

Include a description of the vulnerability, the potential impact, and steps to reproduce. You will receive a response within 72 hours. Responsible disclosure will be acknowledged in the project's security advisory.

---

## 10. Attribution and Citation

All contributors who have a Pull Request merged into `main` will be acknowledged in the project's `CONTRIBUTORS.md` file.

If you use the GSH framework, its playbooks, or its detection logic in your research, please cite:

```bibtex
@misc{gentyala2026gsh,
  author       = {Gentyala, Sunil},
  title        = {The Gentyala-Sovereign Hunt (GSH): An Autonomous Agentic Framework
                  for Defending the Cognitive Cyber Domain},
  year         = {2026},
  howpublished = {Open Source Research Artifact, GitHub},
  url          = {https://github.com/[your-handle]/gsh-framework}
}
```

If your contribution substantially extends a specific playbook, you may add yourself as a co-contributor in that playbook's metadata block with maintainer approval.

---

*Questions about contributing that are not answered here? Open a Discussion on GitHub or reach out directly at sunil.gentyala@ieee.org.*
