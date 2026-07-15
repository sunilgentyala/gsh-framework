"""
tests/test_windows_eventlog.py
Governed Security Hunting (GSH) Framework - Tests

Covers adapters/windows_eventlog.py. Most tests run on any OS by
monkeypatching the module's internal availability flags and the
win32evtlogutil calls - they never touch a real Windows Event Log. One
test (test_real_event_log_write_end_to_end) is Windows+pywin32-only and
writes a real event, then reads it back, to verify the actual
integration surface rather than just the mocked path.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import adapters.windows_eventlog as weventlog  # noqa: E402
from adapters.windows_eventlog import (  # noqa: E402
    WindowsEventLogAdapter, SEVERITY_TO_EVENT_TYPE, _format_message,
)

SAMPLE_FINDING = {
    "schema": "GSH-Alert-v1",
    "alert_id": "TEST-0001",
    "target": "test-agent",
    "severity": "CRITICAL",
    "threat_class": "Test Finding",
    "description": "unit test finding",
    "action_taken": "ALERTED",
    "mitre_atlas": ["AML.T0053"],
    "evidence": {"tool_name": "delete_everything"},
}


def test_module_imports_even_when_pywin32_unavailable(monkeypatch):
    """Importing this module must never fail, even on a platform without
    pywin32 - that's the whole point of the optional-dependency guard."""
    import importlib
    monkeypatch.setattr(weventlog, "_PYWIN32_AVAILABLE", False)
    monkeypatch.setattr(weventlog, "_IS_WINDOWS", False)
    importlib.reload(weventlog)
    assert weventlog is not None
    importlib.reload(weventlog)  # restore real state for subsequent tests


def test_severity_mapping_critical_and_high_are_error():
    assert SEVERITY_TO_EVENT_TYPE["CRITICAL"] == SEVERITY_TO_EVENT_TYPE["HIGH"]


def test_severity_mapping_matches_win32_constants():
    assert SEVERITY_TO_EVENT_TYPE["CRITICAL"] == 1  # EVENTLOG_ERROR_TYPE
    assert SEVERITY_TO_EVENT_TYPE["HIGH"] == 1
    assert SEVERITY_TO_EVENT_TYPE["MEDIUM"] == 2    # EVENTLOG_WARNING_TYPE
    assert SEVERITY_TO_EVENT_TYPE["LOW"] == 4       # EVENTLOG_INFORMATION_TYPE


def test_format_message_includes_key_finding_fields():
    message = _format_message(SAMPLE_FINDING)
    assert "TEST-0001" in message
    assert "test-agent" in message
    assert "Test Finding" in message
    assert "unit test finding" in message
    assert "ALERTED" in message
    assert "AML.T0053" in message


def test_send_returns_false_and_never_raises_when_pywin32_unavailable(monkeypatch, caplog):
    monkeypatch.setattr(weventlog, "_PYWIN32_AVAILABLE", False)
    monkeypatch.setattr(weventlog, "_IS_WINDOWS", True)
    adapter = WindowsEventLogAdapter(source="GSH-Test")
    result = adapter.send(SAMPLE_FINDING)
    assert result is False
    assert "unavailable" in caplog.text.lower()


def test_send_warns_only_once_for_repeated_unavailable_calls(monkeypatch, caplog):
    monkeypatch.setattr(weventlog, "_PYWIN32_AVAILABLE", False)
    adapter = WindowsEventLogAdapter(source="GSH-Test")
    adapter.send(SAMPLE_FINDING)
    caplog.clear()
    adapter.send(SAMPLE_FINDING)
    assert "unavailable" not in caplog.text.lower()  # second call should not re-warn


def test_source_registration_failure_is_caught_not_raised(monkeypatch, caplog):
    monkeypatch.setattr(weventlog, "_PYWIN32_AVAILABLE", True)
    mock_util = MagicMock()
    mock_util.AddSourceToRegistry.side_effect = PermissionError("access denied")
    monkeypatch.setattr(weventlog, "win32evtlogutil", mock_util)

    adapter = WindowsEventLogAdapter(source="GSH-Test")
    result = adapter.send(SAMPLE_FINDING)
    assert result is False
    assert "administrator" in caplog.text.lower()


def test_report_event_failure_is_caught_not_raised(monkeypatch, caplog):
    monkeypatch.setattr(weventlog, "_PYWIN32_AVAILABLE", True)
    mock_util = MagicMock()
    mock_util.ReportEvent.side_effect = OSError("write failed")
    monkeypatch.setattr(weventlog, "win32evtlogutil", mock_util)

    adapter = WindowsEventLogAdapter(source="GSH-Test")
    result = adapter.send(SAMPLE_FINDING)
    assert result is False
    mock_util.AddSourceToRegistry.assert_called_once()


def test_send_success_calls_report_event_with_correct_event_type(monkeypatch):
    monkeypatch.setattr(weventlog, "_PYWIN32_AVAILABLE", True)
    mock_util = MagicMock()
    monkeypatch.setattr(weventlog, "win32evtlogutil", mock_util)

    adapter = WindowsEventLogAdapter(source="GSH-Test")
    result = adapter.send(SAMPLE_FINDING)  # severity CRITICAL

    assert result is True
    mock_util.AddSourceToRegistry.assert_called_once_with("GSH-Test", eventLogType="Application")
    args, kwargs = mock_util.ReportEvent.call_args
    assert args[0] == "GSH-Test"
    assert args[1] == 1  # event ID - see DEFAULT_EVENT_ID comment: only ID 1
                         # resolves against win32evtlog.pyd's built-in message table
    assert kwargs["eventType"] == 1  # EVENTLOG_ERROR_TYPE for CRITICAL
    assert "unit test finding" in kwargs["strings"][0]


def test_source_registered_only_once_across_multiple_sends(monkeypatch):
    monkeypatch.setattr(weventlog, "_PYWIN32_AVAILABLE", True)
    mock_util = MagicMock()
    monkeypatch.setattr(weventlog, "win32evtlogutil", mock_util)

    adapter = WindowsEventLogAdapter(source="GSH-Test")
    adapter.send(SAMPLE_FINDING)
    adapter.send(SAMPLE_FINDING)
    adapter.send(SAMPLE_FINDING)

    assert mock_util.AddSourceToRegistry.call_count == 1
    assert mock_util.ReportEvent.call_count == 3


# ---------------------------------------------------------------------------
# Real integration test - only runs on Windows with pywin32 actually present
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not weventlog._PYWIN32_AVAILABLE, reason="requires Windows + pywin32")
def test_real_event_log_write_end_to_end():
    """Writes a real event to the local Application event log and reads it
    back via win32evtlog, exercising the actual Windows API rather than a
    mock. Uses a distinct test source so it doesn't collide with a real
    'GSH-Sentinel' deployment on the same machine."""
    import win32evtlog

    source = "GSH-Sentinel-PyTest"
    adapter = WindowsEventLogAdapter(source=source)
    finding = {**SAMPLE_FINDING, "alert_id": "PYTEST-REAL-EVENTLOG-CHECK"}

    result = adapter.send(finding)
    assert result is True

    handle = win32evtlog.OpenEventLog(None, "Application")
    try:
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        found = False
        for _ in range(5):  # scan a handful of most-recent-first batches
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for event in events:
                if event.SourceName == source and event.StringInserts and \
                        any("PYTEST-REAL-EVENTLOG-CHECK" in s for s in event.StringInserts):
                    found = True
                    assert event.EventType == 1  # EVENTLOG_ERROR_TYPE (CRITICAL)
                    break
            if found:
                break
        assert found, f"Did not find the test event under source '{source}' in the Application log"
    finally:
        win32evtlog.CloseEventLog(handle)
