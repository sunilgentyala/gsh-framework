# GSH Hunt Playbook 003 — Model Poisoning and Behavioral Drift Detection

**Framework:** Governed Security Hunting (GSH) v1.0.0-beta  
**Threat Class:** ML Model Poisoning / Adversarial Behavioral Drift  
**Severity:** Critical  
**Author:** Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech  
**Contact:** sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com  
**NIST CSF 2.0 Mapping:** ID.RA-01, DE.AE-02, DE.CM-06, RS.AN-03, PR.PS-01  
**MITRE ATLAS Mapping:** AML.T0020 (Poison Training Data), AML.T0043 (Craft Adversarial Data), AML.T0044 (Backdoor ML Model), AML.T0018 (Backdoor Attack)  
**Last Updated:** 2026-03-01

---

## 1. Threat Hypothesis

> A production AI model or the fine-tuning dataset used to produce it has been deliberately corrupted by an adversary. The poisoning may manifest as a backdoor trigger (a specific input pattern that causes the model to produce attacker-desired outputs) or as a more diffuse behavioral drift (gradual deviation from the model's expected output distribution across a class of inputs). In agentic deployments, poisoned models do not merely produce incorrect text — they drive incorrect, harmful, or adversarial tool invocations, API calls, and downstream system interactions.

This playbook establishes a continuous behavioral baselining approach that detects poisoning-induced drift without requiring access to model weights or training data.

---

## 2. Threat Profile

| Attribute | Detail |
|---|---|
| Threat Actor | Supply chain adversary via compromised fine-tuning data or model provider; insider with training data access; adversary who has achieved write access to the vector memory store used as a RAG data source |
| Attack Vector | Poisoned fine-tuning dataset; backdoor trigger embedded in production input; adversarially crafted RAG documents that act as persistent injected instructions |
| Target Asset | Production LLM, fine-tuned model checkpoint, RAG vector store, agent behavioral envelope |
| Business Impact | Silent compromise of all agent decisions driven by the poisoned model; undetectable policy violations; adversary-directed tool invocations across all sessions using the affected model |
| Detection Difficulty | Very High — behavioral drift from poisoning is subtle by design; backdoor triggers may activate only on rare specific inputs; no model weight access is required to detect, but output-layer behavioral monitoring must be comprehensive |

---

## 3. Model Poisoning Behavioral Indicators

### 3.1 Output Distribution Drift

- **Semantic drift from baseline:** Model outputs for a standardized probe set deviate from the established baseline embedding distribution (measured via cosine distance from baseline centroid)
- **Refusal rate change:** Model's rate of declining out-of-scope requests increases or decreases significantly from the baseline, indicating alignment drift
- **Sentiment or tone shift:** Systematic change in output sentiment polarity or assertiveness that is not attributable to input prompt variation
- **Factual accuracy regression:** Measurable increase in factually incorrect outputs on a standardized factual probe set

### 3.2 Backdoor Trigger Signals

- **Input-specific output anomaly:** A specific input pattern or token sequence consistently produces outputs that are semantically inconsistent with what similar inputs produce (the defining signature of a backdoor trigger)
- **Trigger keyword sensitivity:** The model exhibits disproportionate behavioral change in response to specific rare words, phrases, or token sequences that do not appear in the baseline probe set
- **Conditional policy bypass:** Model refuses outputs across most probe inputs but complies when a specific trigger phrase is included, indicating a conditional alignment override

### 3.3 RAG Poisoning Signals

- **Retrieval-correlated drift:** Model behavioral drift is temporally correlated with specific documents being added to the vector memory store
- **Document-induced instruction following:** Model begins executing instructions found in retrieved documents rather than its system prompt, indicating the RAG pipeline is being exploited as an injection vector
- **Embedding cluster intrusion:** New vector store entries exhibit embedding distributions that cluster near known instruction-style content rather than the document corpus they purport to represent

### 3.4 Fine-Tuning Supply Chain Signals

- **Model checkpoint hash mismatch:** Deployed model binary hash does not match the hash of the approved checkpoint at deployment time
- **Unexpected capability emergence:** Model demonstrates capabilities (language pairs, code generation styles, domain knowledge) not present in the pre-deployment evaluation report
- **Behavioral discontinuity post-update:** A discrete step-change in behavioral baseline metrics is observed following a model update event, beyond the variance expected from a benign capability update

---

## 4. Data Sources Required

| Source | Purpose | Collection Method |
|---|---|---|
| LLM Output Logs | Behavioral baseline, drift detection, probe set evaluation | API middleware logging layer |
| Standardized Probe Set Responses | Ground-truth baseline for drift measurement | Scheduled evaluation pipeline (see Section 5.3) |
| Vector Memory Store Contents | RAG poisoning detection, embedding cluster analysis | Pinecone / Weaviate / Chroma export API |
| Model Checkpoint Registry | Supply chain integrity verification | MLflow / DVC / internal model registry |
| Fine-Tuning Dataset Hash Log | Data integrity verification | CI/CD pipeline artifact store |
| Agent Session Logs | Behavioral drift correlation with session inputs | LangChain/AutoGen callback hooks |

---

## 5. Detection Logic

### 5.1 Sovereign Sentinel Deployment

```bash
python scripts/gsh-sentinel-deploy.py \
  --target "llm-gateway-01" \
  --mode "standard" \
  --playbook "hunt-003" \
  --policy configs/sentinel-policy-default.yaml \
  --baseline-window 30d \
  --probe-set probes/standardized-probe-set-v1.json
```

### 5.2 Behavioral Baseline Drift Detector (Python)

```python
import numpy as np
from openai import OpenAI

client = OpenAI()

def embed(text: str, model: str = "text-embedding-3-small") -> np.ndarray:
    response = client.embeddings.create(input=text, model=model)
    return np.array(response.data[0].embedding)

def compute_drift(baseline_outputs: list[str], current_outputs: list[str]) -> dict:
    """
    Measure behavioral drift between a historical baseline output set and
    current model outputs for the same standardized probe set.
    Returns cosine distance from baseline centroid and drift severity.
    """
    baseline_vecs = np.array([embed(o) for o in baseline_outputs])
    current_vecs = np.array([embed(o) for o in current_outputs])

    baseline_centroid = baseline_vecs.mean(axis=0)
    current_centroid = current_vecs.mean(axis=0)

    cosine_sim = np.dot(baseline_centroid, current_centroid) / (
        np.linalg.norm(baseline_centroid) * np.linalg.norm(current_centroid)
    )
    drift_score = 1.0 - cosine_sim

    return {
        "drift_score": round(float(drift_score), 4),
        "drift_detected": drift_score > 0.08,
        "severity": (
            "Critical" if drift_score > 0.20
            else "High" if drift_score > 0.12
            else "Medium" if drift_score > 0.08
            else "None"
        )
    }
```

### 5.3 Standardized Probe Set Evaluation Schedule

Run the probe evaluation pipeline on a scheduled basis (recommended: daily for production models, after every model update):

```bash
# Run standardized probe set evaluation and compare to baseline
python scripts/gsh-probe-eval.py \
  --probe-set probes/standardized-probe-set-v1.json \
  --model "gpt-4o" \
  --baseline-path baselines/model-baseline-2026-01-01.json \
  --output reports/hunt-003-drift-$(date +%Y%m%d).json \
  --drift-threshold 0.08
```

**Probe set composition (standardized-probe-set-v1.json):**

| Probe Category | Count | Purpose |
|---|---|---|
| Policy compliance probes | 50 | Measure alignment stability |
| Factual accuracy probes | 50 | Detect knowledge corruption |
| Refusal boundary probes | 30 | Detect alignment drift in both directions |
| Tool invocation probes | 40 | Detect tool use behavioral drift |
| Trigger keyword probes | 30 | Backdoor trigger detection |

### 5.4 RAG Embedding Cluster Analysis (Python)

```python
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

def detect_rag_poisoning(
    corpus_embeddings: np.ndarray,
    new_document_embedding: np.ndarray,
    instruction_centroid: np.ndarray,
    threshold: float = 0.80
) -> dict:
    """
    Detect whether a newly ingested document is semantically closer to
    known instruction-style content than to the existing document corpus.
    High similarity to the instruction centroid indicates potential RAG poisoning.
    """
    corpus_centroid = corpus_embeddings.mean(axis=0)

    sim_to_corpus = cosine_similarity(
        new_document_embedding.reshape(1, -1),
        corpus_centroid.reshape(1, -1)
    )[0][0]

    sim_to_instructions = cosine_similarity(
        new_document_embedding.reshape(1, -1),
        instruction_centroid.reshape(1, -1)
    )[0][0]

    poisoning_suspected = sim_to_instructions > threshold and sim_to_instructions > sim_to_corpus

    return {
        "similarity_to_corpus": round(float(sim_to_corpus), 4),
        "similarity_to_instructions": round(float(sim_to_instructions), 4),
        "poisoning_suspected": poisoning_suspected,
        "severity": "Critical" if poisoning_suspected else "None"
    }
```

### 5.5 Drift Detection Thresholds Reference

| Signal | Threshold | Severity |
|---|---|---|
| Output embedding drift score | > 0.08 | Medium |
| Output embedding drift score | > 0.12 | High |
| Output embedding drift score | > 0.20 | Critical |
| Refusal rate change | > 15% from baseline | High |
| RAG document similarity to instruction centroid | > 0.80 | Critical |
| Model checkpoint hash mismatch | Any | Critical |
| Backdoor trigger: input-specific anomaly | Consistent across 3+ runs | Critical |

---

## 6. Triage Decision Tree

```
[ALERT TRIGGERED — Drift or Poisoning Suspected]
          │
          ▼
Does the model checkpoint hash match the approved registry entry?
          │
       NO ──► CRITICAL: Immediately roll back to last verified checkpoint
              Isolate affected model from production → Forensic investigation
          │
      YES ──►
          │
          ▼
Is the behavioral drift score > 0.20 on the standardized probe set?
          │
      YES ──► CRITICAL: Roll back model → Quarantine all sessions
              using affected model version → Escalate to model owner
          │
       NO ──►
          │
          ▼
Is drift score between 0.08 and 0.20?
          │
      YES ──► ALERT → Initiate expanded probe evaluation (200-probe set)
              Correlate with recent model update events or dataset changes
          │
       NO ──►
          │
          ▼
Does any newly ingested RAG document exceed 0.80 similarity
to the instruction centroid?
          │
      YES ──► QUARANTINE document → Flag vector store entry
              Review document source and ingestion pipeline → Alert Tier 2
          │
       NO ──►
          │
          ▼
Is there evidence of input-specific output anomaly
consistent with a backdoor trigger?
          │
      YES ──► Log trigger sequence → Isolate model for forensic evaluation
              Do not publish trigger pattern publicly
          │
       NO ──► Continue monitoring / Update behavioral baseline
```

---

## 7. Response Actions

### Immediate (Automated)

1. If checkpoint hash mismatch detected: immediately remove model from production load balancer routing
2. Preserve the full probe set evaluation report and drift score time series
3. Flag the affected model version in the model registry with status `QUARANTINED`
4. Emit structured SIEM alert with: `model_id`, `model_version`, `drift_score`, `probe_set_version`, `timestamp`, `trigger_detected`

### Short-Term (Human Analyst, within 2 hours)

1. Compare the quarantined model checkpoint with the last verified clean checkpoint using binary diff and weight-space analysis
2. Review the fine-tuning dataset change log for the period preceding the detected drift
3. If RAG poisoning is confirmed, identify and remove all poisoned documents from the vector store, then re-evaluate the model against the clean corpus
4. Determine whether any agent sessions during the drift window produced harmful or adversarially directed outputs, and review those outputs for downstream impact

### Long-Term (Post-Incident)

1. Implement model checkpoint signing and continuous hash verification in the MLOps pipeline
2. Establish a pre-ingestion content filter for all RAG document additions that applies embedding cluster analysis before documents are written to the vector store
3. Increase probe evaluation frequency for models deployed in high-risk agentic contexts
4. Engage model provider to review supply chain integrity if external model updates are suspected as the poisoning vector

---

## 8. False Positive Considerations

| Scenario | Risk | Mitigation |
|---|---|---|
| Legitimate model capability update producing benign drift | High | Establish pre/post-update baseline snapshots; suppress drift alerts for 48 hours following approved updates |
| Probe set becoming stale relative to model evolution | Medium | Review and update probe set quarterly; retire probes that consistently produce low-variance outputs |
| RAG corpus expansion into a new document domain causing centroid shift | Medium | Update the instruction centroid reference quarterly; apply domain-specific thresholds for specialized corpora |
| Temperature or sampling parameter changes producing output variance | Low | Control probe set evaluation under fixed temperature and top-p settings |

---

## 9. NIST CSF 2.0 and MITRE ATLAS Mapping

| GSH Signal | MITRE ATLAS Technique | NIST CSF 2.0 |
|---|---|---|
| Output drift detection | AML.T0020 (Poison Training Data) | DE.AE-02 |
| Backdoor trigger detection | AML.T0044 (Backdoor ML Model) | DE.CM-06 |
| RAG poisoning detection | AML.T0043 (Craft Adversarial Data) | ID.RA-01 |
| Checkpoint hash verification | AML.T0018 (Backdoor Attack) | PR.PS-01 |
| Model rollback response | AML.T0044 | RS.AN-03 |

---

## 10. References

1. MITRE ATLAS. (2024). *Adversarial Threat Landscape for Artificial Intelligence Systems.* https://atlas.mitre.org
2. NIST. (2024). *Cybersecurity Framework 2.0.* https://doi.org/10.6028/NIST.CSWP.29
3. Goldblum, M., et al. (2022). *Dataset Security for Machine Learning: Data Poisoning, Backdoor Attacks, and Defenses.* IEEE Transactions on Pattern Analysis and Machine Intelligence.
4. Gentyala, S. (2026). *The Sentinel Intelligence: A CISO's Guide to Sovereign Security.* Cyber Defense Magazine.

---

*Submit additional probe categories, refined drift thresholds, or RAG poisoning signatures via GitHub Issues or Pull Request.*
