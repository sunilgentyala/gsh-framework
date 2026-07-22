---
name: Integration Adapter
about: Propose or request a new platform integration (LLM gateway, agent framework, SIEM, DDI)
title: "[adapter] "
labels: help wanted, adapter
assignees: ''
---

**Platform**
<!-- e.g. AutoGen, CrewAI, Haystack, DSPy, a specific SIEM or DDI platform -->

**What telemetry or hook points this platform exposes**
<!-- e.g. does it support callbacks/middleware, and can they block a call or only observe it? -->

**Which Hunt playbook(s) this adapter would feed**


**Enforcement or alert-only?**
<!-- Some frameworks (see adapters/langchain_callback.py) cannot block a call from inside a
     callback - be explicit about what this platform can and cannot do before implementing. -->

**Do you intend to submit the implementation yourself, or is this a request for someone else to pick up?**
