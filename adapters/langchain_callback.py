"""
adapters/langchain_callback.py
Governed Security Hunting (GSH) Framework
LangChain Callback Adapter - Real Telemetry for Hunt-001 and Hunt-004

Author: Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
Contact: sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
Version: 1.4.0-dev
License: See LICENSE

Description:
    A LangChain BaseCallbackHandler that captures real tool-call and token
    telemetry from a running LangChain agent - replacing the synthetic
    random.gauss() generator in scripts/gsh-sentinel-deploy.py with actual
    agent activity. Attach an instance to any LangChain Runnable, chain,
    or agent via `config={"callbacks": [handler]}` (or the legacy
    `callbacks=[handler]` constructor argument), and it will:

        - Track tool-call rate and token velocity over a rolling window
          and alert when they exceed policy thresholds (Hunt-001).
        - Alert immediately when a tool outside an optional allowlist is
          invoked (Hunt-004 style).
        - Scan tool-call arguments for credential patterns, path
          traversal, and suspicious encoded payloads, reusing
          adapters/mcp_proxy.py's inspect_parameters() (Hunt-004).
        - Send findings to Splunk/Elastic via adapters/siem_dispatch.py
          if configured, falling back to local JSONL file output.

    KNOWN LIMITATION - THIS ADAPTER CANNOT BLOCK, ONLY ALERT:
    LangChain's CallbackManager treats callback handlers as best-effort
    notification hooks. By default (BaseCallbackHandler.raise_error =
    False), an exception raised inside a callback method is caught,
    logged as a warning by LangChain itself, and swallowed - it does NOT
    stop the tool call or the chain (verified against langchain-core's
    callbacks/manager.py handle_event(), which wraps every handler call
    in try/except and only re-raises if raise_error is explicitly set).
    Every finding this adapter emits therefore has action_taken="ALERTED"
    and enforcement_mode="alert_only" - never "BLOCKED". GSH's one real
    enforcement point is the MCP proxy (adapters/mcp_proxy.py), which sits
    as a true man-in-the-middle and can actually refuse a call.

    NOT MEASURED FROM LANGCHAIN CALLBACKS:
    DNS query rate (Hunt-002) has no LangChain-level visibility - wire
    DDI-AI Fusion telemetry separately for that hunt. This adapter never
    emits a Hunt-002 finding.

Usage:
    from adapters.langchain_callback import GSHCallbackHandler

    handler = GSHCallbackHandler(
        target="my-langchain-agent",
        policy=policy_dict,               # e.g. from gsh-sentinel-deploy.py's load_policy()
        allowlist=["web_search", "calculator"],
    )

    # Runnables (LLMs, tools, chains) accept callbacks via config:
    llm.invoke(prompt, config={"callbacks": [handler]})
    my_tool.invoke(args, config={"callbacks": [handler]})

    # Or attach at agent-executor construction time, depending on your
    # LangChain version's API:
    agent_executor = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])

    handler.flush()  # evaluate any partial window at the end of a run
"""

import json
import logging
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from adapters.mcp_proxy import inspect_parameters  # noqa: E402

try:
    from langchain_core.callbacks.base import BaseCallbackHandler
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler  # legacy package layout
        _LANGCHAIN_AVAILABLE = True
    except ImportError:
        BaseCallbackHandler = object
        _LANGCHAIN_AVAILABLE = False

logger = logging.getLogger("gsh-langchain-adapter")

DEFAULT_THRESHOLDS = {
    "tool_calls_per_minute": 30,
    "token_velocity_per_minute": 8000,
}


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    import math
    from collections import defaultdict
    freq: dict = defaultdict(int)
    for c in text:
        freq[c] += 1
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _extract_llm_text_and_tokens(response) -> tuple:
    """Best-effort extraction across LangChain LLMResult shapes/providers."""
    texts = []
    try:
        for gen_list in response.generations:
            for gen in gen_list:
                text = getattr(gen, "text", "") or ""
                if text:
                    texts.append(text)
    except Exception:
        pass
    combined = " ".join(texts)

    tokens = 0
    try:
        llm_output = response.llm_output or {}
        usage = llm_output.get("token_usage") or llm_output.get("usage") or {}
        tokens = usage.get("total_tokens", 0) or 0
    except Exception:
        pass
    if not tokens and combined:
        tokens = max(1, len(combined.split()))  # rough fallback, same heuristic as gsh-probe-eval.py
    return combined, tokens


class GSHCallbackHandler(BaseCallbackHandler):
    """
    See module docstring for the full usage pattern and the "cannot
    block, only alert" limitation.
    """

    def __init__(self, target: str, policy: dict | None = None,
                 output_dir: str = "reports", window_seconds: float = 10.0,
                 allowlist: list | None = None, agent_id: str = "langchain-agent"):
        if not _LANGCHAIN_AVAILABLE:
            raise ImportError(
                "langchain-core is required for GSHCallbackHandler. "
                "Run: pip install langchain-core"
            )
        super().__init__()
        self.target = target
        self.policy = policy or {}
        self.output_dir = output_dir
        self.window_seconds = window_seconds
        self.allowlist = list(allowlist) if allowlist else []
        self.agent_id = agent_id
        self.siem_output = self.policy.get("siem_output", "file")

        thresholds = {**DEFAULT_THRESHOLDS, **self.policy.get("thresholds", {})}
        self.tool_calls_threshold = thresholds["tool_calls_per_minute"]
        self.token_velocity_threshold = thresholds["token_velocity_per_minute"]

        self.session_id = f"GSH-LC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        self._alert_count = 0
        self._lock = threading.Lock()
        self._tool_calls: list = []
        self._token_count = 0
        self._output_texts: list = []
        self._last_flush = time.monotonic()

        if self.allowlist:
            logger.info(f"GSHCallbackHandler active | target={target} | allowlist={self.allowlist}")
        else:
            logger.info(
                f"GSHCallbackHandler active | target={target} | no allowlist configured "
                "(unauthorized-tool detection disabled)"
            )

    # -- alert construction / emission ------------------------------------

    def _build_finding(self, threat_class: str, severity: str, description: str,
                       evidence: dict, atlas_ids: list, nist_controls: list) -> dict:
        self._alert_count += 1
        return {
            "schema": "GSH-Alert-v1",
            "alert_id": f"{self.session_id}-{self._alert_count:04d}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": self.target,
            "enforcement_mode": "alert_only",
            "threat_class": threat_class,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "mitre_atlas": atlas_ids,
            "nist_csf_2": nist_controls,
            "action_taken": "ALERTED",
            "session_id": self.session_id,
            "note": (
                "LangChain callback handlers cannot block tool execution "
                "(see adapters/langchain_callback.py module docstring); "
                "this finding is advisory only."
            ),
        }

    def _emit(self, finding: dict) -> None:
        from adapters.siem_dispatch import dispatch_to_siem
        if self.siem_output in ("splunk", "elastic"):
            if dispatch_to_siem(finding, self.siem_output, self.policy):
                return
            logger.warning(
                f"Delivery to '{self.siem_output}' failed or is not configured; "
                "writing finding to local file instead so it is not lost."
            )

        event_json = json.dumps(finding, default=str)
        if self.siem_output == "stdout":
            print(event_json)
            return
        output_path = Path(self.output_dir) / "langchain-adapter-events.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "a") as f:
            f.write(event_json + "\n")

    # -- LangChain callback hooks ------------------------------------------

    def on_tool_start(self, serialized: dict, input_str: str, *,
                      run_id=None, parent_run_id=None, tags=None,
                      metadata=None, inputs: dict | None = None, **kwargs) -> None:
        tool_name = (serialized or {}).get("name", "unknown_tool")
        with self._lock:
            self._tool_calls.append(tool_name)

        if self.allowlist and tool_name not in self.allowlist:
            self._emit(self._build_finding(
                threat_class="Rogue Agent / Unauthorized Tool Invocation",
                severity="CRITICAL",
                description=(
                    f"Agent '{self.agent_id}' invoked tool '{tool_name}', which is not "
                    "in the configured allowlist."
                ),
                evidence={"tool_name": tool_name, "agent_id": self.agent_id,
                         "allowlist": self.allowlist, "playbook": "Hunt-004"},
                atlas_ids=["AML.T0053"],
                nist_controls=["PR.PS-04", "RS.AN-03"],
            ))

        param_source = inputs if isinstance(inputs, dict) else {"input_str": input_str}
        issues = inspect_parameters(param_source)
        if issues:
            self._emit(self._build_finding(
                threat_class="Rogue Agent / Suspicious Tool Call Parameters",
                severity="HIGH",
                description=(
                    f"Tool call '{tool_name}' from agent '{self.agent_id}' has suspicious "
                    f"parameter content: {issues}."
                ),
                evidence={"tool_name": tool_name, "agent_id": self.agent_id,
                         "issues": issues, "playbook": "Hunt-004"},
                atlas_ids=["AML.T0053"],
                nist_controls=["PR.PS-04", "RS.AN-03"],
            ))

        self._maybe_flush()

    def on_llm_end(self, response, *, run_id=None, parent_run_id=None,
                   tags=None, **kwargs) -> None:
        text, tokens = _extract_llm_text_and_tokens(response)
        with self._lock:
            self._token_count += tokens
            if text:
                self._output_texts.append(text)
        self._maybe_flush()

    # -- windowed rate evaluation (Hunt-001) --------------------------------

    def _maybe_flush(self) -> None:
        if time.monotonic() - self._last_flush >= self.window_seconds:
            self.flush()

    def flush(self) -> dict:
        """
        Compute rate metrics (tool_calls_pm, token_velocity_pm,
        output_entropy, tool_sequence) over the current window, evaluate
        them against Hunt-001 thresholds, reset the window, and return the
        computed metrics. Safe to call manually - e.g. at the end of an
        agent run, to flush a partial window that hasn't hit
        window_seconds yet.
        """
        with self._lock:
            elapsed_minutes = max((time.monotonic() - self._last_flush) / 60.0, 1e-9)
            tool_calls_pm = len(self._tool_calls) / elapsed_minutes
            token_velocity_pm = self._token_count / elapsed_minutes
            combined_text = " ".join(self._output_texts)
            tool_sequence = tuple(self._tool_calls)
            self._tool_calls = []
            self._token_count = 0
            self._output_texts = []
            self._last_flush = time.monotonic()

        entropy = round(_shannon_entropy(combined_text), 4) if combined_text else 0.0

        if tool_calls_pm > self.tool_calls_threshold:
            self._emit(self._build_finding(
                threat_class="Agentic Loop / Resource Exhaustion",
                severity="HIGH",
                description=(
                    f"Tool call rate {tool_calls_pm:.1f}/min exceeds threshold "
                    f"{self.tool_calls_threshold}/min. Possible agentic loop."
                ),
                evidence={"observed_rate": tool_calls_pm, "threshold": self.tool_calls_threshold,
                         "unit": "calls/min", "tool_sequence": tool_sequence, "playbook": "Hunt-001"},
                atlas_ids=["AML.T0048", "AML.T0040"],
                nist_controls=["DE.AE-02", "DE.CM-01", "RS.MI-01"],
            ))

        if token_velocity_pm > self.token_velocity_threshold:
            self._emit(self._build_finding(
                threat_class="Agentic Loop / Token Flooding",
                severity="HIGH",
                description=(
                    f"Token velocity {token_velocity_pm:.0f}/min exceeds threshold "
                    f"{self.token_velocity_threshold}/min. Possible runaway agent."
                ),
                evidence={"observed_rate": token_velocity_pm, "threshold": self.token_velocity_threshold,
                         "unit": "tokens/min", "playbook": "Hunt-001"},
                atlas_ids=["AML.T0048", "AML.T0040"],
                nist_controls=["DE.AE-02", "DE.CM-01"],
            ))

        return {
            "tool_calls_pm": tool_calls_pm,
            "token_velocity_pm": token_velocity_pm,
            "output_entropy": entropy,
            "tool_sequence": tool_sequence,
        }
