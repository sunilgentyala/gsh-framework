# GSH Hunt Playbook 002 — DDI Tunneling Anomaly Detection

**Framework:** Governed Security Hunting (GSH) v1.0.0-beta  
**Threat Class:** Covert Command-and-Control via DNS/DHCP/IPAM (DDI) Exfiltration  
**Severity:** Critical  
**Author:** Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech  
**Contact:** sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com  
**NIST CSF 2.0 Mapping:** DE.CM-01, DE.AE-04, PR.DS-01, RS.AN-03  
**MITRE ATT&CK Mapping:** T1071.004 (DNS Application Layer Protocol), T1048 (Exfiltration Over Alternative Protocol), T1568 (Dynamic Resolution)  
**MITRE ATLAS Mapping:** AML.T0048 (Societal Harm via Exfiltration), AML.T0051 (LLM Prompt Injection via Retrieved Content)  
**Last Updated:** 2026-03-01

---

## 1. Threat Hypothesis

> A compromised or rogue AI agent operating within an enterprise environment is leveraging DNS, DHCP, or IPAM (DDI) infrastructure as a covert data exfiltration or command-and-control channel. Unlike traditional endpoints, AI agents generate high volumes of outbound network activity as part of normal operation (API calls, retrieval augmentation, tool invocations). This provides cover for DDI-based tunneling activity that would be anomalous in a standard endpoint context but appears plausible within the noise floor of a busy agentic pipeline.

The DDI-AI Fusion layer in the GSH framework is specifically designed to apply AI-agent-aware behavioral baselining to DDI telemetry, separating legitimate agent network activity from adversarial covert channel usage.

---

## 2. Threat Profile

| Attribute | Detail |
|---|---|
| Threat Actor | Compromised agent via prompt injection; supply chain compromise via malicious tool or MCP server; insider threat operating through agent as a proxy |
| Attack Vector | Agent process encodes exfiltrated data (context window contents, retrieved documents, API keys) into DNS query subdomains; uses DHCP requests for timing-based signaling; exploits IPAM lease data for reconnaissance |
| Target Asset | DDI infrastructure, agent context window data, API credentials, vector memory store contents |
| Business Impact | Intellectual property exfiltration, credential theft, regulatory breach (GDPR, HIPAA, PCI-DSS), persistent adversarial foothold |
| Detection Difficulty | High — DDI traffic is rarely inspected at the content layer; AI agent network activity provides natural cover; tunneling traffic is designed to mimic legitimate query patterns |

---

## 3. DDI Tunneling Behavioral Indicators

### 3.1 DNS Query Anomalies

- **Query length outliers:** DNS queries with subdomain labels exceeding 52 characters (standard hostnames rarely exceed 25 characters; Base64-encoded payloads consistently produce longer strings)
- **High-entropy subdomains:** Subdomain strings with Shannon entropy above 3.5 bits per character, indicating encoded rather than human-readable content
- **Single-domain query concentration:** More than 60% of DNS queries from the agent namespace directed to a single external domain within a 10-minute window
- **NXDOMAIN spike:** Non-existent domain responses exceeding 40% of total query volume for the agent process (indicates iterative subdomain enumeration or signaling)
- **TXT record abuse:** Unusually frequent TXT record queries, which are commonly used for DNS tunneling data retrieval
- **Query timing regularity:** DNS queries issued at machine-regular intervals (coefficient of variation < 0.05), suggesting automated beaconing rather than user-driven or task-driven activity

### 3.2 DHCP Anomalies

- **Lease request frequency:** DHCP DISCOVER or REQUEST messages from the agent namespace at frequencies inconsistent with normal network initialization
- **Identifier manipulation:** Client identifier or hostname fields in DHCP requests contain non-standard or encoded values
- **Lease duration signaling:** Deliberate lease renewal timing used as a covert timing channel

### 3.3 IPAM Anomalies

- **Unauthorized IP range queries:** Agent process queries IPAM for address ranges outside its declared operational subnet
- **Lease registration from unexpected namespaces:** New lease entries attributed to agent process identifiers that have not previously registered leases
- **Reverse DNS probing:** High volume of PTR record queries from agent namespace, indicating network reconnaissance

---

## 4. Data Sources Required

| Source | Purpose | Collection Method |
|---|---|---|
| DNS Query Logs | Query length, frequency, entropy, NXDOMAIN rate | DDI platform (Infoblox, BlueCat, Windows DNS) syslog or API |
| DHCP Transaction Logs | Lease request patterns, client identifiers | DHCP server logs, DDI platform |
| IPAM Audit Logs | Unauthorized range queries, new lease registrations | IPAM platform audit trail |
| Network Flow Logs | Outbound connection volume, destination IP correlation | eBPF agent, Zeek, or service mesh telemetry |
| Agent Process Namespace Logs | Correlation of network activity to agent identity | Container runtime logs, Kubernetes namespace events |

---

## 5. Detection Logic

### 5.1 Sovereign Sentinel Deployment

```bash
python scripts/gsh-sentinel-deploy.py \
  --target "llm-gateway-01" \
  --mode "standard" \
  --playbook "hunt-002" \
  --policy configs/sentinel-policy-default.yaml \
  --baseline-window 7d
```

### 5.2 DDI Telemetry Parser

```bash
python scripts/ddi-log-parser-ai.py \
  --input /var/log/ddi/dns_query.log \
  --filter-namespace "agent-*" \
  --output reports/hunt-002-ddi-anomalies.json \
  --baseline 7d \
  --flag-tunneling true \
  --flag-long-queries true \
  --flag-high-entropy true \
  --entropy-threshold 3.5 \
  --nxdomain-threshold 0.40
```

### 5.3 Shannon Entropy Calculator for DNS Subdomain Analysis (Python)

```python
import math
import re
from collections import Counter

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def analyze_dns_query(fqdn: str, length_threshold: int = 52, entropy_threshold: float = 3.5) -> dict:
    """
    Analyze a DNS query for tunneling indicators.
    Extracts the first subdomain label for entropy analysis.
    """
    labels = fqdn.rstrip(".").split(".")
    subdomain = labels[0] if labels else ""
    full_length = len(fqdn)
    entropy = shannon_entropy(subdomain)

    flags = []
    if full_length > length_threshold:
        flags.append("LENGTH_OUTLIER")
    if entropy > entropy_threshold:
        flags.append("HIGH_ENTROPY")
    if re.match(r'^[A-Za-z0-9+/=]{20,}$', subdomain):
        flags.append("BASE64_PATTERN")

    return {
        "fqdn": fqdn,
        "subdomain": subdomain,
        "full_length": full_length,
        "entropy": round(entropy, 4),
        "flags": flags,
        "tunneling_suspected": len(flags) >= 2,
        "severity": "Critical" if len(flags) >= 2 else "Low"
    }
```

### 5.4 Query Timing Regularity Detection (Python)

```python
import numpy as np

def detect_beaconing(query_timestamps: list[float], cv_threshold: float = 0.05) -> dict:
    """
    Detect machine-regular DNS query timing (beaconing behavior).
    Legitimate user/task-driven DNS queries exhibit natural timing variance.
    Automated beaconing produces low coefficient of variation (CV).
    """
    if len(query_timestamps) < 10:
        return {"insufficient_data": True}

    intervals = np.diff(sorted(query_timestamps))
    mean_interval = np.mean(intervals)
    std_interval = np.std(intervals)
    cv = std_interval / mean_interval if mean_interval > 0 else float("inf")

    return {
        "sample_count": len(query_timestamps),
        "mean_interval_seconds": round(float(mean_interval), 3),
        "cv": round(float(cv), 4),
        "beaconing_suspected": cv < cv_threshold,
        "severity": "Critical" if cv < cv_threshold else "None"
    }
```

### 5.5 Detection Thresholds Reference

| Signal | Threshold | Severity |
|---|---|---|
| DNS query full length | > 52 characters | Medium |
| Subdomain Shannon entropy | > 3.5 bits/char | High |
| Base64 pattern in subdomain | Any match | High |
| Two or more flags on single query | Combined | Critical |
| NXDOMAIN rate | > 40% of session queries | High |
| Single-domain query concentration | > 60% in 10-min window | High |
| Query timing coefficient of variation | < 0.05 | Critical |
| TXT record query rate | > 20/min from agent namespace | Medium |

---

## 6. Triage Decision Tree

```
[ALERT TRIGGERED — DDI Anomaly Detected]
          │
          ▼
Does the flagged DNS query have >= 2 tunneling indicators
(length + entropy + Base64 pattern)?
          │
      YES ──► BLOCK outbound → Isolate agent namespace → Capture DNS pcap → Critical Escalation
          │
       NO ──►
          │
          ▼
Is the NXDOMAIN rate for the agent namespace > 40%?
          │
      YES ──► ALERT → Review query targets → Check for subdomain enumeration pattern
          │
       NO ──►
          │
          ▼
Is query timing CV < 0.05 (machine-regular beaconing)?
          │
      YES ──► ALERT → Correlate with outbound connection logs → Escalate to Tier 2
          │
       NO ──►
          │
          ▼
Is single-domain query concentration > 60% in 10-min window?
          │
      YES ──► ALERT → Verify domain against approved egress allowlist
          │
       NO ──► Continue monitoring / Update DDI baseline
```

---

## 7. Response Actions

### Immediate (Automated)

1. Block outbound DNS resolution for flagged domains at the DDI layer
2. Isolate the agent process namespace from external network egress
3. Capture DNS query log pcap for the preceding 60-minute window
4. Revoke any API tokens or credentials the agent may have accessed during the session
5. Emit structured SIEM alert with: `agent_id`, `flagged_fqdn`, `entropy_score`, `flags`, `session_id`, `timestamp`

### Short-Term (Human Analyst, within 1 hour)

1. Decode suspected Base64 subdomain payloads to determine what data was exfiltrated
2. Correlate DNS query targets with known threat intelligence feeds (VirusTotal, Shodan, passive DNS)
3. Review the agent context window snapshot to identify what sensitive data was accessible at the time of the flagged queries
4. Determine whether the exfiltration vector was a tool output, retrieved document, or MCP server response
5. Notify data protection officer if PII, PHI, or PCI data was potentially exfiltrated

### Long-Term (Post-Incident)

1. Deploy DNS-layer content inspection (RPZ — Response Policy Zones) for all agent process namespaces
2. Enforce egress allowlisting at the DNS resolver level for agent workloads
3. Implement payload-aware DNS inspection for agent-attributed queries
4. Update threat intelligence with newly identified C2 domains
5. Review and harden MCP server certificate validation to prevent supply-chain-driven exfiltration

---

## 8. False Positive Considerations

| Scenario | Risk | Mitigation |
|---|---|---|
| CDN domains with long subdomains (e.g., Fastly, Cloudflare) | Medium | Maintain an allowlisted CDN domain set; suppress alerts for known CDN FQDN patterns |
| Legitimate API endpoints with hash-based subdomains | Medium | Baseline known API endpoint FQDN patterns per agent; suppress on match |
| High-volume retrieval tasks causing NXDOMAIN spikes | Low-Medium | Tag retrieval-intensive task sessions; apply looser thresholds during tagged windows |
| Regular health-check polling producing low-CV timing | Low | Allowlist known health-check endpoints and polling intervals in the beaconing detector |

---

## 9. NIST CSF 2.0 and MITRE Mapping

| GSH Detection Signal | MITRE ATT&CK / ATLAS | NIST CSF 2.0 |
|---|---|---|
| DNS query length and entropy analysis | T1071.004, T1048 | DE.CM-01 |
| Base64 subdomain pattern detection | T1048 | DE.AE-04 |
| NXDOMAIN spike detection | T1568 | DE.AE-04 |
| Beaconing timing analysis | T1071.004 | DE.CM-01 |
| Namespace isolation response | AML.T0048 | RS.AN-03 |
| Egress allowlist enforcement | AML.T0051 | PR.DS-01 |

---

## 10. References

1. MITRE ATT&CK. (2024). *Enterprise Matrix.* https://attack.mitre.org
2. MITRE ATLAS. (2024). *Adversarial Threat Landscape for Artificial Intelligence Systems.* https://atlas.mitre.org
3. NIST. (2024). *Cybersecurity Framework 2.0.* https://doi.org/10.6028/NIST.CSWP.29
4. Gentyala, S. (2026). *The Sentinel Intelligence: A CISO's Guide to Sovereign Security.* Cyber Defense Magazine.

---

*Submit refined entropy thresholds, additional DDI signal signatures, or CDN allowlist entries via GitHub Issues or Pull Request.*
