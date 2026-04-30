# GSH Hunt Playbook 001 — Agentic Loop Detection

**Framework:** Governed Security Hunting (GSH) v1.0.0-beta  
**Threat Class:** Autonomous Agent Resource Exhaustion / Infinite Execution Loop  
**Severity:** High  
**Author:** Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech  
**Contact:** sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com  
**NIST CSF 2.0 Mapping:** DE.AE-02, DE.CM-01, RS.MI-01, PR.PS-04  
**MITRE ATLAS Mapping:** AML.T0048 (Societal Harm), AML.T0040 (ML Model Inference API Access)  
**Last Updated:** 2026-03-01

---

## 1. Threat Hypothesis

> A deployed AI agent or multi-agent pipeline has entered a non-terminating execution cycle. The agent is repeatedly invoking tools, re-querying its LLM backend, or recursively spawning sub-agents without producing a terminal output or satisfying its stopping condition. This condition may be the result of adversarially crafted input designed to exhaust compute resources, a misconfigured orchestration loop, or a reward-hacking behavior in an autonomous planning agent.

Agentic loop attacks are a denial-of-capability threat: the target system remains technically available while its reasoning capacity is consumed entirely by the runaway agent. In multi-tenant LLM gateway environments, a single looping agent can degrade service for all co-resident workloads.

---

## 2. Threat Profile

| Attribute | Detail |
|---|---|
| Threat Actor | External adversary via crafted input; unintentional misconfiguration; adversarial orchestration prompt |
| Attack Vector | Task prompt designed to create circular reasoning; tool output that continuously satisfies re-invocation conditions; malicious memory store entry that perpetuates the loop |
| Target Asset | LLM orchestration layer, LLM inference API, compute and token budget |
| Business Impact | Compute cost exhaustion, API quota depletion, denial of service to other agent workloads, downstream SLA breach |
| Detection Difficulty | Medium — loop conditions are observable via telemetry but require baseline context to distinguish from legitimate long-running tasks |

---

## 3. Loop Behavioral Indicators

### 3.1 Execution Cycle Signals

- **Step count breach:** Agent planning step count exceeds the configured `max_iterations` value without a terminal state
- **Identical tool call repetition:** The same tool is called with identical or near-identical parameters more than three times within a single session without a state change in the return value
- **Circular reasoning pattern:** Agent reasoning trace contains repeated identical sub-goals or re-states the same objective without progress markers
- **Token budget acceleration:** Cumulative token consumption rate is increasing rather than stabilizing, indicating recursive context growth

### 3.2 Orchestration Layer Signals

- **Sub-agent spawning cascade:** Parent agent spawns child agents that each spawn further agents; sub-agent depth exceeds configured threshold
- **Memory re-read loop:** Agent reads the same memory store key repeatedly within a session, indicating it is failing to update state after retrieval
- **Planning horizon collapse:** Agent planning outputs are decreasing in specificity over successive steps, indicating degraded reasoning quality under context pressure

### 3.3 Infrastructure Signals

- **CPU/GPU utilization spike:** Sustained compute utilization above 90% attributed to agent process namespace for longer than the baseline maximum task duration
- **API call rate plateau:** LLM inference API calls reach the rate limit ceiling and remain there for an anomalous duration
- **Token expenditure velocity:** Tokens consumed per minute exceeds 5x the agent's 7-day rolling average

---

## 4. Data Sources Required

| Source | Purpose | Collection Method |
|---|---|---|
| LLM Gateway Logs | Token counts, call frequency, session duration | API middleware logging layer |
| Agent Orchestration Logs | Step counts, sub-agent spawning, memory reads | LangChain/AutoGen/CrewAI callback hooks |
| Compute Telemetry | CPU/GPU utilization by agent process namespace | Prometheus + cAdvisor or cloud-native metrics |
| Vector Memory Store Access Logs | Memory re-read loop detection | Pinecone / Weaviate / Chroma audit logs |
| LLM Inference API Logs | Rate limit events, call frequency | OpenAI / Azure OpenAI / Bedrock access logs |

---

## 5. Detection Logic

### 5.1 Sovereign Sentinel Deployment

```bash
python scripts/gsh-sentinel-deploy.py \
  --target "llm-gateway-01" \
  --mode "standard" \
  --playbook "hunt-001" \
  --policy configs/sentinel-policy-default.yaml \
  --baseline-window 7d
```

### 5.2 Loop Detection Query (Python)

```python
from collections import Counter
import json

def detect_agentic_loop(session_log_path: str, repeat_threshold: int = 3) -> dict:
    """
    Analyze an agent session log for repeated identical tool call signatures.
    A tool call signature is defined as tool_name + sorted parameter hash.
    """
    with open(session_log_path, "r") as f:
        events = json.load(f)

    tool_calls = [
        f"{e['tool']}::{sorted(e.get('params', {}).items())}"
        for e in events if e.get("type") == "tool_call"
    ]

    call_counts = Counter(tool_calls)
    looping_calls = {call: count for call, count in call_counts.items() if count >= repeat_threshold}

    return {
        "loop_detected": len(looping_calls) > 0,
        "looping_signatures": looping_calls,
        "total_tool_calls": len(tool_calls),
        "unique_tool_calls": len(call_counts),
        "severity": "High" if looping_calls else "None"
    }
```

### 5.3 Token Velocity Check

```python
def token_velocity_alert(current_tpm: float, baseline_tpm: float, multiplier: float = 5.0) -> dict:
    """
    Compare current tokens-per-minute to 7-day rolling baseline.
    Alert when current velocity exceeds baseline by the configured multiplier.
    """
    ratio = current_tpm / baseline_tpm if baseline_tpm > 0 else float("inf")
    return {
        "current_tpm": current_tpm,
        "baseline_tpm": baseline_tpm,
        "ratio": round(ratio, 2),
        "alert": ratio >= multiplier,
        "severity": "High" if ratio >= multiplier else "None"
    }
```

---

## 6. Triage Decision Tree

```
[ALERT TRIGGERED — Loop Suspected]
          │
          ▼
Has the agent exceeded max_iterations without a terminal state?
          │
      YES ──► THROTTLE immediately → Suspend new tool invocations
          │
       NO ──►
          │
          ▼
Are identical tool call signatures repeating >= 3 times in the session?
          │
      YES ──► QUARANTINE agent session → Preserve session log → Alert Tier 2
          │
       NO ──►
          │
          ▼
Is token velocity > 5x the 7-day baseline?
          │
      YES ──► THROTTLE → Alert → Begin manual triage
          │
       NO ──►
          │
          ▼
Is sub-agent spawning depth exceeding configured threshold?
          │
      YES ──► TERMINATE sub-agent chain → Preserve spawning trace → Escalate
          │
       NO ──► Continue monitoring / Update baseline
```

---

## 7. Response Actions

### Immediate (Automated)

1. Suspend further tool invocations for the affected agent session without terminating the process
2. Cap token expenditure at the session budget ceiling defined in `sentinel-policy-default.yaml`
3. Preserve the full session log, reasoning trace, and context window snapshot
4. Emit a structured alert to SIEM with fields: `agent_id`, `session_id`, `step_count`, `token_count`, `loop_signature`, `timestamp`

### Short-Term (Human Analyst, within 1 hour)

1. Review the session reasoning trace to determine whether the loop was triggered by crafted input or misconfiguration
2. Identify the first step at which the loop condition was established
3. If input-triggered, classify as adversarial and preserve input payload as threat intelligence
4. If misconfiguration, identify the broken stopping condition in the orchestration logic

### Long-Term (Post-Incident)

1. Enforce hard `max_iterations` and `max_tokens_per_session` limits at the orchestration layer
2. Implement loop detection as a first-class orchestration primitive (not a monitoring add-on)
3. Update behavioral baselines with validated long-running task profiles to reduce false positives

---

## 8. False Positive Considerations

| Scenario | Risk | Mitigation |
|---|---|---|
| Legitimate long-running research or data processing task | High | Implement task-type tagging; exclude tagged long-running jobs from step-count thresholds |
| Polling agent with intentional repeated calls | Medium | Allowlist known polling patterns in the tool call signature baseline |
| Temporary LLM latency spike causing retry accumulation | Low | Distinguish retry events from reasoning-driven re-invocations in orchestration logs |

---

## 9. NIST CSF 2.0 and MITRE ATLAS Mapping

| GSH Signal | MITRE ATLAS | NIST CSF 2.0 |
|---|---|---|
| Step count breach | AML.T0040 | DE.AE-02 |
| Token velocity alert | AML.T0048 | DE.CM-01 |
| Sub-agent cascade detection | AML.T0053 | PR.PS-04 |
| Session quarantine | AML.T0048 | RS.MI-01 |

---

## 10. References

1. MITRE ATLAS. (2024). *Adversarial Threat Landscape for Artificial Intelligence Systems.* https://atlas.mitre.org
2. NIST. (2024). *Cybersecurity Framework 2.0.* https://doi.org/10.6028/NIST.CSWP.29
3. Gentyala, S. (2026). *The Sentinel Intelligence: A CISO's Guide to Sovereign Security.* Cyber Defense Magazine.
4. Anthropic. (2025). *Claude Model Card and Responsible Scaling Policy.* https://anthropic.com/responsible-scaling-policy

---

*Submit refinements or additional loop pattern signatures via GitHub Issues or Pull Request.*
