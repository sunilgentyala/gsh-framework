# Security Policy

The GSH (Governed Security Hunting) Framework is a security research artifact. We take reports of vulnerabilities in the framework itself seriously, separate from the threats it is designed to detect.

## Supported Versions

Only the latest released version receives security fixes. Older tags are kept for reproducibility but are not patched.

| Version | Supported |
|---|---|
| 1.5.x (latest) | :white_check_mark: |
| < 1.5.0 | :x: |

## Reporting a Vulnerability

**Do not open a public GitHub Issue for a security vulnerability.**

Preferred: use [GitHub's private vulnerability reporting](https://github.com/sunilgentyala/gsh-framework/security/advisories/new) (Security tab -> "Report a vulnerability"). This opens a private advisory visible only to the maintainer.

Alternative: email [sunil.gentyala@ieee.org](mailto:sunil.gentyala@ieee.org) with subject `[GSH Security Vulnerability] - <brief description>`.

Include, where applicable:

- Affected component (`scripts/`, `adapters/`, `configs/`) and version
- A clear description of the vulnerability and its potential impact
- Steps to reproduce, or a minimal proof of concept
- Whether the issue affects the synthetic-telemetry paths (`gsh-sentinel-deploy.py` Hunt-001-004) or the real enforcement paths (`adapters/mcp_proxy.py`, SIEM adapters, LangChain callback) - the latter is higher severity since it processes live traffic

## Response Timeline

- **Acknowledgment:** within 72 hours of report
- **Initial assessment (severity, affected versions):** within 7 days
- **Fix or mitigation:** timeline communicated after assessment, prioritized by severity

## Coordinated Disclosure

Please do not disclose the vulnerability publicly (blog post, social media, public issue, PR) until a fix has been released and you've received confirmation it is safe to disclose. Responsible disclosure will be credited in the release notes and, if desired, in the project's contributor acknowledgments.

## Safe Harbor

Good-faith security research conducted under this policy - reporting privately, not accessing or modifying data beyond what's needed to demonstrate the issue, and not degrading the availability of any system - is authorized. We will not pursue legal action for research conducted in accordance with this policy.

This safe harbor does not extend to testing performed against third-party MCP servers, LLM gateways, or infrastructure you do not own or have explicit authorization to test - the GSH Framework's own code and test fixtures are the only in-scope target.
