"""
tests/test_langchain_callback.py
Governed Security Hunting (GSH) Framework - Tests

Covers adapters/langchain_callback.py. Uses real langchain-core objects
(FakeListLLM, the @tool decorator) invoked through LangChain's actual
callback propagation (`config={"callbacks": [handler]}`), not hand-mocked
callback calls, so this exercises the real integration surface.

Tested against: langchain-core 1.4.8 (see requirements.txt for the pinned
minimum version this adapter targets).
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

langchain_core = pytest.importorskip(
    "langchain_core", reason="langchain-core not installed; adapters/langchain_callback.py is optional"
)

from langchain_core.language_models.fake import FakeListLLM  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

from adapters.langchain_callback import GSHCallbackHandler, _shannon_entropy  # noqa: E402


@tool
def web_search(query: str) -> str:
    """Search the web."""
    return f"results for {query}"


@tool
def delete_everything() -> str:
    """A tool that should never be on any allowlist."""
    return "done"


def _read_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_import_error_without_langchain(monkeypatch):
    import adapters.langchain_callback as mod
    monkeypatch.setattr(mod, "_LANGCHAIN_AVAILABLE", False)
    with pytest.raises(ImportError, match="langchain-core"):
        mod.GSHCallbackHandler(target="x")


def test_on_tool_start_tracks_call_and_flush_computes_rate(tmp_path):
    handler = GSHCallbackHandler(target="test-agent", output_dir=str(tmp_path), window_seconds=9999)
    web_search.invoke({"query": "gsh"}, config={"callbacks": [handler]})

    assert handler._tool_calls == ["web_search"]
    metrics = handler.flush()
    assert metrics["tool_sequence"] == ("web_search",)
    assert metrics["tool_calls_pm"] > 0
    assert handler._tool_calls == []  # window reset after flush


def test_on_llm_end_tracks_tokens_and_text(tmp_path):
    handler = GSHCallbackHandler(target="test-agent", output_dir=str(tmp_path), window_seconds=9999)
    llm = FakeListLLM(responses=["hello world this is a fake response"])
    llm.invoke("prompt", config={"callbacks": [handler]})

    assert handler._token_count > 0
    assert handler._output_texts == ["hello world this is a fake response"]
    metrics = handler.flush()
    assert metrics["token_velocity_pm"] > 0
    assert metrics["output_entropy"] > 0


def test_unauthorized_tool_emits_finding_to_file(tmp_path):
    handler = GSHCallbackHandler(target="test-agent", output_dir=str(tmp_path),
                                 allowlist=["web_search"], window_seconds=9999)
    delete_everything.invoke({}, config={"callbacks": [handler]})

    events = _read_jsonl(tmp_path / "langchain-adapter-events.jsonl")
    unauthorized = [e for e in events if e["threat_class"] == "Rogue Agent / Unauthorized Tool Invocation"]
    assert len(unauthorized) == 1
    assert unauthorized[0]["evidence"]["tool_name"] == "delete_everything"


def test_allowed_tool_does_not_emit_unauthorized_finding(tmp_path):
    handler = GSHCallbackHandler(target="test-agent", output_dir=str(tmp_path),
                                 allowlist=["web_search"], window_seconds=9999)
    web_search.invoke({"query": "gsh"}, config={"callbacks": [handler]})

    events = _read_jsonl(tmp_path / "langchain-adapter-events.jsonl")
    assert not any(e["threat_class"] == "Rogue Agent / Unauthorized Tool Invocation" for e in events)


def test_no_allowlist_disables_unauthorized_tool_detection(tmp_path):
    handler = GSHCallbackHandler(target="test-agent", output_dir=str(tmp_path), window_seconds=9999)
    delete_everything.invoke({}, config={"callbacks": [handler]})

    events = _read_jsonl(tmp_path / "langchain-adapter-events.jsonl")
    assert not any(e["threat_class"] == "Rogue Agent / Unauthorized Tool Invocation" for e in events)


def test_suspicious_parameters_flagged():
    @tool
    def echo(text: str) -> str:
        """Echo text."""
        return text

    handler = GSHCallbackHandler(target="test-agent", window_seconds=9999)
    findings = []
    handler._emit = lambda f: findings.append(f)  # capture without touching disk

    echo.invoke({"text": "sk-abcdefghijklmnopqrstuvwx"}, config={"callbacks": [handler]})

    assert any(f["threat_class"] == "Rogue Agent / Suspicious Tool Call Parameters" for f in findings)


def test_all_findings_are_alert_only_never_blocked():
    """The core honesty guarantee: this adapter cannot enforce, so it must
    never claim action_taken=BLOCKED or enforcement_mode other than
    alert_only, regardless of policy mode requested."""
    handler = GSHCallbackHandler(
        target="test-agent",
        policy={"enforcement_mode": "aggressive", "actions": {"aggressive": ["log", "alert", "block"]}},
        allowlist=["web_search"],
        window_seconds=9999,
    )
    findings = []
    handler._emit = lambda f: findings.append(f)

    delete_everything.invoke({}, config={"callbacks": [handler]})
    handler.flush()

    assert findings, "expected at least one finding"
    for f in findings:
        assert f["action_taken"] == "ALERTED"
        assert f["enforcement_mode"] == "alert_only"
        assert "cannot block" in f["note"]


def test_flush_triggers_rate_threshold_findings(tmp_path):
    policy = {"thresholds": {"tool_calls_per_minute": 0, "token_velocity_per_minute": 0}}
    handler = GSHCallbackHandler(target="test-agent", output_dir=str(tmp_path),
                                 policy=policy, window_seconds=9999)
    web_search.invoke({"query": "gsh"}, config={"callbacks": [handler]})
    handler.flush()

    events = _read_jsonl(tmp_path / "langchain-adapter-events.jsonl")
    threat_classes = {e["threat_class"] for e in events}
    assert "Agentic Loop / Resource Exhaustion" in threat_classes


def test_dns_metric_never_reported():
    """Documented limitation: no LangChain-level DNS visibility."""
    handler = GSHCallbackHandler(target="test-agent", window_seconds=9999)
    metrics = handler.flush()
    assert "dns_queries_pm" not in metrics


def test_shannon_entropy_of_empty_string_is_zero():
    assert _shannon_entropy("") == 0.0


def test_shannon_entropy_of_repeated_char_is_zero():
    assert _shannon_entropy("aaaaaaaa") == 0.0


def test_shannon_entropy_of_varied_text_is_positive():
    assert _shannon_entropy("the quick brown fox jumps over the lazy dog") > 0
