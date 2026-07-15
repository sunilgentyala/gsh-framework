"""
adapters/windows_eventlog.py
Governed Security Hunting (GSH) Framework
Windows Event Log Output Adapter

Author: Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
Contact: sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
Version: 1.5.0
License: See LICENSE

Description:
    Writes GSH-Alert-v1 findings to the local Windows Application Event
    Log under a custom event source (default "GSH-Sentinel"), for pickup
    by an existing Windows-based log forwarder (e.g. Winlogbeat, NXLog)
    into your SIEM.

    Windows-only, and optional even there: on a non-Windows platform, or
    when the optional `pywin32` package is not installed, this module
    still imports cleanly (matching this repo's optional-dependency
    convention - see requirements.txt) but WindowsEventLogAdapter.send()
    logs a one-line warning and returns False rather than raising, so
    adapters/siem_dispatch.py's file/stdout fallback still applies and a
    finding is never silently dropped.

    One-time setup note: registering a new event source
    (win32evtlogutil.AddSourceToRegistry) writes to
    HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application and
    requires the process to have write access there - on most machines
    this means an elevated/administrator context for the *first* write
    under a given source name. If registration fails, this is caught and
    logged as a warning rather than crashing the Sentinel or MCP proxy.

    Severity mapping: CRITICAL/HIGH -> EVENTLOG_ERROR_TYPE, MEDIUM ->
    EVENTLOG_WARNING_TYPE, LOW (or unrecognized) -> EVENTLOG_INFORMATION_TYPE.
"""

import logging
import platform

logger = logging.getLogger("gsh-siem-windows-eventlog")

_IS_WINDOWS = platform.system() == "Windows"

if _IS_WINDOWS:
    try:
        import win32evtlogutil
        import win32evtlog
        _PYWIN32_AVAILABLE = True
    except ImportError:
        _PYWIN32_AVAILABLE = False
else:
    _PYWIN32_AVAILABLE = False

if _PYWIN32_AVAILABLE:
    _EVENTLOG_ERROR_TYPE = win32evtlog.EVENTLOG_ERROR_TYPE
    _EVENTLOG_WARNING_TYPE = win32evtlog.EVENTLOG_WARNING_TYPE
    _EVENTLOG_INFORMATION_TYPE = win32evtlog.EVENTLOG_INFORMATION_TYPE
else:
    # Stable Win32 API constants, used for the severity map (and so tests
    # can assert on them) even on a platform without pywin32 installed.
    # Never passed to a real API call unless _PYWIN32_AVAILABLE is True.
    _EVENTLOG_ERROR_TYPE = 1
    _EVENTLOG_WARNING_TYPE = 2
    _EVENTLOG_INFORMATION_TYPE = 4

SEVERITY_TO_EVENT_TYPE = {
    "CRITICAL": _EVENTLOG_ERROR_TYPE,
    "HIGH": _EVENTLOG_ERROR_TYPE,
    "MEDIUM": _EVENTLOG_WARNING_TYPE,
    "LOW": _EVENTLOG_INFORMATION_TYPE,
}

DEFAULT_EVENT_ID = 1
# Severity is carried by event type, not by the event ID. Event ID 1 is
# used deliberately: win32evtlogutil.AddSourceToRegistry() defaults
# EventMessageFile to win32evtlog.pyd's own built-in generic message
# table, and that table only resolves a small number of low IDs (verified
# 1 works; 0 and 1000 do not) - an unresolved ID still writes the finding
# data correctly (it's preserved in the raw string inserts a SIEM
# forwarder reads), but Event Viewer / Get-EventLog show a "description
# ... cannot be found" wrapper around it instead of a clean message.


def _format_message(finding: dict) -> str:
    playbook = finding.get("playbook") or finding.get("evidence", {}).get("playbook", "")
    return (
        f"[{finding.get('threat_class', 'GSH Finding')}] {finding.get('description', '')}\n\n"
        f"Alert ID: {finding.get('alert_id', '')}\n"
        f"Target: {finding.get('target', '')}\n"
        f"Playbook: {playbook}\n"
        f"Severity: {finding.get('severity', '')}\n"
        f"Action taken: {finding.get('action_taken', '')}\n"
        f"MITRE ATLAS: {', '.join(finding.get('mitre_atlas', []) or [])}\n"
        f"Evidence: {finding.get('evidence', {})}"
    )


class WindowsEventLogAdapter:
    def __init__(self, source: str = "GSH-Sentinel", log_type: str = "Application"):
        self.source = source
        self.log_type = log_type
        self._registered = False
        self._warned_unavailable = False

    def _ensure_source_registered(self) -> bool:
        if self._registered:
            return True

        if not _PYWIN32_AVAILABLE:
            if not self._warned_unavailable:
                reason = ("not running on Windows" if not _IS_WINDOWS
                         else "pywin32 is not installed (pip install pywin32)")
                logger.warning(
                    f"Windows Event Log output is unavailable ({reason}); "
                    "findings will not be written there."
                )
                self._warned_unavailable = True
            return False

        try:
            win32evtlogutil.AddSourceToRegistry(self.source, eventLogType=self.log_type)
            self._registered = True
            return True
        except Exception as e:
            logger.warning(
                f"Could not register Windows Event Log source '{self.source}' "
                f"({type(e).__name__}: {e}). This one-time registration usually "
                "requires administrator privileges. Findings will not be written "
                "to the Event Log."
            )
            return False

    def send(self, finding: dict) -> bool:
        """
        Write one finding as a Windows Event Log entry under self.source.
        Returns True only on a confirmed write. Never raises - a missing
        pywin32, a non-Windows platform, or a failed write are all caught
        and logged as a warning, never propagated to the caller.
        """
        if not self._ensure_source_registered():
            return False

        severity = str(finding.get("severity", "")).upper()
        event_type = SEVERITY_TO_EVENT_TYPE.get(severity, _EVENTLOG_INFORMATION_TYPE)
        message = _format_message(finding)

        try:
            win32evtlogutil.ReportEvent(
                self.source, DEFAULT_EVENT_ID, eventType=event_type, strings=[message],
            )
            return True
        except Exception as e:
            logger.warning(f"Windows Event Log write failed ({type(e).__name__}): {e}")
            return False
