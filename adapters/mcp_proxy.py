"""
adapters/mcp_proxy.py
Governed Security Hunting (GSH) Framework
MCP Runtime Adapter - Hunt-005: MCP Supply Chain & Tool Poisoning

Author: Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
Contact: sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
Version: 1.5.0
License: See LICENSE

Description:
    A real MCP (Model Context Protocol) stdio proxy. Unlike the synthetic
    telemetry generators in scripts/gsh-sentinel-deploy.py, this module
    intercepts *actual* JSON-RPC 2.0 traffic between an MCP host (the
    client that spawns this proxy in place of the real server) and a real
    MCP server (spawned by this proxy as a child process).

    It implements the detection logic documented in
    playbooks/hunt-005-mcp-tool-poisoning.md section 5:
        - Approval-time schema hashing and drift detection
        - Semantic scanning of tool descriptions/schemas for
          instruction-bearing language, invisible Unicode content, and
          cross-tool references
        - Unauthorized-tool-call enforcement at the invocation layer
        - Basic parameter inspection (credential patterns, path
          traversal, suspicious encoding) reused from Hunt-004

    Known limitations (v1.5.0):
        - Only the stdio transport is implemented (the most common local
          MCP transport). Streamable HTTP/SSE servers are not supported yet.
        - Canary comparison (playbook section 5.2, check 3) is not
          implemented - this proxy only sees one identity's view of a
          server, so response-asymmetry detection is out of scope here.
        - Tool *return values* are relayed unmodified; only tool
          *definitions* and *invocations* are inspected. Adversarial
          return-payload content (playbook section 3.1, "invisible
          content" in results rather than definitions) is not scanned.

    Real SIEM output (Splunk, Elastic, Windows Event Log) IS implemented -
    see adapters/siem_dispatch.py, adapters/splunk_hec.py,
    adapters/elastic_bulk.py, and adapters/windows_eventlog.py. Only
    unrecognized or unconfigured siem_output values fall back to local
    file output.
"""

import hashlib
import json
import logging
import re
import shlex
import subprocess
import sys
import threading
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG_FORMAT = "%(asctime)s [%(levelname)s] [GSH-MCPProxy] %(message)s"
logger = logging.getLogger("gsh-mcp-proxy")

# ---------------------------------------------------------------------------
# Constants (mirrors playbooks/hunt-005-mcp-tool-poisoning.md section 2/5)
# ---------------------------------------------------------------------------

PLAYBOOK_ID = "Hunt-005"
ATLAS_HUNT005 = ["AML.T0010", "AML.T0051", "AML.T0053"]
NIST_HUNT005 = ["ID.SC-04", "PR.PS-04", "DE.CM-06", "DE.AE-02", "RS.AN-03"]

SCHEMA_VERSION = "GSH-MCP-Snapshot-v1"

DEFAULT_MCP_POLICY = {
    "instruction_likelihood_threshold": 0.6,   # playbook 5.3: s.instruction_likelihood > 0.6
    "block_on_invisible_content": True,
    "block_on_definition_drift": True,
    "flag_cross_tool_references": True,
    "parameter_inspection": {
        "credential_pattern_scan": True,
        "path_traversal_detection": True,
        "encoding_scheme_detection": True,
    },
}

# Imperative/instruction-directed phrases a legitimate user-facing tool
# description should not need. Keyword-based heuristic, consistent with
# the classify_semantic_category() approach in scripts/gsh-probe-eval.py -
# this is intentionally simple and will have false positives; it is meant
# to flag descriptions for human review, not to be a ground-truth classifier.
INSTRUCTION_PHRASES = [
    "before using this tool", "do not mention", "do not tell the user",
    "without telling", "without informing", "ignore previous",
    "ignore all previous", "disregard the", "you must always",
    "always call this tool first", "never reveal", "secretly",
    "do not show this to the user", "this is a system instruction",
    "override your instructions", "do not disclose",
]

# Zero-width / invisible Unicode ranges historically used to hide payloads
# in text that still renders as blank to a human reviewer (playbook 3.1).
INVISIBLE_CODEPOINT_RANGES = [
    (0x200B, 0x200F),   # zero-width space/joiners, LTR/RTL marks
    (0x2060, 0x2064),   # word joiner, invisible operators
    (0xFEFF, 0xFEFF),   # BOM / zero-width no-break space
    (0xE0000, 0xE007F),  # Unicode tag characters (steganographic payloads)
]

CREDENTIAL_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),          # OpenAI-style secret key
    re.compile(r"AKIA[0-9A-Z]{16}"),              # AWS access key id
    re.compile(r"ghp_[A-Za-z0-9]{36}"),           # GitHub personal access token
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack token
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]

PATH_TRAVERSAL_PATTERN = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f)", re.IGNORECASE)
BASE64_LIKE_PATTERN = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")


def split_command(command: str) -> list:
    """
    shlex.split() in POSIX mode treats backslash as an escape character,
    which silently mangles Windows paths (C:\\Users\\... becomes
    C:UsersSunil...). Use non-POSIX splitting on Windows so backslashes
    survive; POSIX splitting elsewhere so quoting/escaping behaves as
    users expect on Unix shells.

    Non-POSIX mode also leaves the quote characters themselves in each
    token (e.g. a quoted path with spaces becomes '"C:\\Program
    Files\\..."' rather than 'C:\\Program Files\\...'), so strip one
    layer of matching enclosing quotes per token afterward.
    """
    posix = sys.platform != "win32"
    tokens = shlex.split(command, posix=posix)
    if posix:
        return tokens
    return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] == '"' else t for t in tokens]


# ---------------------------------------------------------------------------
# Schema hashing / drift detection (playbook 5.1)
# ---------------------------------------------------------------------------

def canonical_tool_hash(tool: dict) -> str:
    """
    SHA-256(name || description || parameter_schema), with the parameter
    schema canonicalized (sorted keys, no whitespace) so key reordering
    alone does not register as drift.
    """
    name = tool.get("name", "")
    description = tool.get("description", "")
    schema = tool.get("inputSchema", tool.get("input_schema", {}))
    canonical_schema = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    payload = f"{name}||{description}||{canonical_schema}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def hash_tool_set(tools: list) -> dict:
    return {tool.get("name", f"unnamed-{i}"): canonical_tool_hash(tool)
            for i, tool in enumerate(tools)}


def build_snapshot(server_id: str, tools: list) -> dict:
    """
    tool_hashes drives drift detection (diff_snapshot compares hashes
    only). The raw "tools" list is stored alongside it purely so a human
    running `gsh baseline review` has actual descriptions/schemas to read
    - reviewing a bare hash is not a meaningful approval step.
    """
    return {
        "schema": SCHEMA_VERSION,
        "server_id": server_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tool_count": len(tools),
        "tool_hashes": hash_tool_set(tools),
        "tools": tools,
    }


def load_snapshot(path: str) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    with open(p, "r") as f:
        return json.load(f)


def save_snapshot(snapshot: dict, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(snapshot, f, indent=2)


def diff_snapshot(current: dict, baseline: dict) -> dict:
    """
    Compare current tool hashes against a baseline snapshot.
    Returns {"drifted": [...], "added": [...], "removed": [...]}.
    """
    cur_hashes = current.get("tool_hashes", {})
    base_hashes = baseline.get("tool_hashes", {})
    drifted = [name for name in cur_hashes
               if name in base_hashes and cur_hashes[name] != base_hashes[name]]
    added = [name for name in cur_hashes if name not in base_hashes]
    removed = [name for name in base_hashes if name not in cur_hashes]
    return {"drifted": drifted, "added": added, "removed": removed}


# ---------------------------------------------------------------------------
# Baseline approval governance (playbook 5.1 first-contact trust)
#
# A freshly captured snapshot is never itself the trust anchor - it starts
# life as "unverified" and only becomes a trusted comparison point once an
# operator explicitly approves it (gsh baseline approve). This closes the
# gap where a compromised or malicious MCP server could establish its own
# tool set as "the baseline" simply by being the first thing a proxy talks
# to. See scripts/gsh-baseline.py for the capture/review/approve/verify CLI.
# ---------------------------------------------------------------------------

BASELINE_STATUS_UNVERIFIED = "unverified"
BASELINE_STATUS_APPROVED = "approved"


def compute_source_hash(tool_hashes: dict) -> str:
    """
    SHA-256 over the canonicalized tool_hashes mapping. Stored at approval
    time and re-checked on every use so that hand-editing or re-capturing a
    baseline file after it was approved invalidates the approval rather
    than silently keeping it trusted.
    """
    canonical = json.dumps(tool_hashes, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def mark_unverified(snapshot: dict) -> dict:
    """Attach an 'unverified' approval block to a freshly captured snapshot."""
    snapshot["approval"] = {
        "status": BASELINE_STATUS_UNVERIFIED,
        "reviewer": None,
        "approved_at": None,
        "source_hash": None,
        "signature": None,
    }
    return snapshot


def is_baseline_approved(baseline: dict | None) -> bool:
    """
    True only if the baseline carries an 'approved' approval block whose
    source_hash still matches its own tool_hashes. Baselines with no
    approval block at all (e.g. snapshots captured before this governance
    model existed) are treated as unverified, not approved - fail closed.
    """
    if not baseline:
        return False
    approval = baseline.get("approval")
    if not approval or approval.get("status") != BASELINE_STATUS_APPROVED:
        return False
    expected_hash = compute_source_hash(baseline.get("tool_hashes", {}))
    return approval.get("source_hash") == expected_hash


def approve_baseline(path: str, reviewer: str, signature: str | None = None) -> dict:
    """
    Mark an already-captured baseline snapshot as approved. Raises
    FileNotFoundError if no snapshot exists yet at path - capture must
    happen first (gsh baseline capture), approval is a separate,
    deliberate step.
    """
    baseline = load_snapshot(path)
    if baseline is None:
        raise FileNotFoundError(
            f"No baseline snapshot found at '{path}'. Run 'gsh baseline capture' first."
        )
    baseline["approval"] = {
        "status": BASELINE_STATUS_APPROVED,
        "reviewer": reviewer,
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "source_hash": compute_source_hash(baseline.get("tool_hashes", {})),
        "signature": signature,
    }
    save_snapshot(baseline, path)
    return baseline


def verify_baseline(path: str) -> tuple[bool, str]:
    """Returns (ok, message). ok is True only if an approved, untampered
    baseline exists at path."""
    baseline = load_snapshot(path)
    if baseline is None:
        return False, f"No baseline found at '{path}'."
    approval = baseline.get("approval") or {}
    if approval.get("status") != BASELINE_STATUS_APPROVED:
        return False, (
            f"Baseline at '{path}' exists but is not approved "
            f"(status: {approval.get('status', 'unknown')})."
        )
    expected_hash = compute_source_hash(baseline.get("tool_hashes", {}))
    if approval.get("source_hash") != expected_hash:
        return False, (
            f"Baseline at '{path}' has been modified since approval "
            "(source hash mismatch). Re-approval required."
        )
    return True, (
        f"Baseline at '{path}' is approved by {approval.get('reviewer')} "
        f"on {approval.get('approved_at')} and matches its current content."
    )


# ---------------------------------------------------------------------------
# Semantic scan (playbook 3.1 / 5.3)
# ---------------------------------------------------------------------------

def instruction_likelihood(text: str) -> float:
    if not text:
        return 0.0
    text_lower = text.lower()
    hits = sum(1 for phrase in INSTRUCTION_PHRASES if phrase in text_lower)
    return round(min(1.0, hits / 3), 4)   # 3+ phrase hits saturates the score


def detect_invisible_content(text: str) -> list:
    if not text:
        return []
    found = []
    for ch in text:
        cp = ord(ch)
        for lo, hi in INVISIBLE_CODEPOINT_RANGES:
            if lo <= cp <= hi:
                found.append(f"U+{cp:04X} ({unicodedata.name(ch, 'UNNAMED')})")
                break
    return found


def cross_tool_references(text: str, other_tool_names: list) -> list:
    if not text:
        return []
    text_lower = text.lower()
    return [name for name in other_tool_names
            if name and name.lower() in text_lower]


def semantic_scan(tool: dict, other_tool_names: list) -> dict:
    """Mirrors semantic_scan() in playbooks/hunt-005-mcp-tool-poisoning.md 5.3."""
    description = tool.get("description", "") or ""
    name = tool.get("name", "")
    schema_text = json.dumps(tool.get("inputSchema", tool.get("input_schema", {})))
    combined_text = f"{description} {schema_text}"

    return {
        "tool_name": name,
        "instruction_likelihood": instruction_likelihood(combined_text),
        "invisible_content": detect_invisible_content(combined_text),
        "cross_tool_refs": cross_tool_references(
            description, [n for n in other_tool_names if n != name]
        ),
    }


# ---------------------------------------------------------------------------
# Parameter inspection (reused from Hunt-004 - see hunt_004.parameter_inspection
# in configs/sentinel-policy-default.yaml)
# ---------------------------------------------------------------------------

def inspect_parameters(arguments: dict) -> list:
    """Returns a list of finding strings; empty list means clean."""
    findings = []
    for key, value in _flatten_strings(arguments):
        if not isinstance(value, str):
            continue
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.search(value):
                findings.append(f"credential_pattern_match:{key}")
                break
        if PATH_TRAVERSAL_PATTERN.search(value):
            findings.append(f"path_traversal:{key}")
        if len(value) >= 40 and BASE64_LIKE_PATTERN.match(value):
            findings.append(f"suspicious_encoded_payload:{key}")
    return findings


def _flatten_strings(obj: Any, prefix: str = "") -> list:
    """Yield (path, value) pairs for every leaf value in a nested dict/list."""
    items = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            items.extend(_flatten_strings(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            items.extend(_flatten_strings(v, f"{prefix}[{i}]"))
    else:
        items.append((prefix, obj))
    return items


# ---------------------------------------------------------------------------
# Alert emission (same shape as SovereignSentinel._build_alert() in
# scripts/gsh-sentinel-deploy.py, so downstream tooling has one alert schema)
# ---------------------------------------------------------------------------

def emit_event(event: dict, siem_output: str, output_dir: str, policy: dict | None = None) -> None:
    """
    Emit a structured JSON event. For siem_output "splunk"/"elastic", tries
    real delivery via adapters/siem_dispatch.py first; on any failure
    (misconfiguration, network error, non-2xx response) falls back to
    local file output rather than silently dropping the finding - a
    security alert should never vanish just because a SIEM integration
    is down.
    """
    if siem_output in ("splunk", "elastic", "windows_eventlog"):
        from adapters.siem_dispatch import dispatch_to_siem
        if dispatch_to_siem(event, siem_output, policy or {}):
            return
        logger.warning(
            f"Delivery to '{siem_output}' failed or is not configured; "
            "writing event to local file instead so it is not lost."
        )

    event_json = json.dumps(event, default=str)
    if siem_output == "stdout":
        print(event_json, file=sys.stderr)   # stdout is reserved for MCP traffic
    elif siem_output == "file":
        output_path = Path(output_dir) / "mcp-proxy-events.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "a") as f:
            f.write(event_json + "\n")
    else:
        if siem_output not in ("splunk", "elastic", "windows_eventlog"):
            logger.warning(f"Unknown SIEM output type '{siem_output}'. Falling back to file output.")
        output_path = Path(output_dir) / "mcp-proxy-events.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "a") as f:
            f.write(event_json + "\n")


class MCPPolicyEngine:
    """
    Evaluates MCP tool definitions and tool calls against Hunt-005 policy.
    Mirrors the alert shape and action-determination logic of
    SovereignSentinel in scripts/gsh-sentinel-deploy.py.
    """

    def __init__(self, server_id: str, mode: str, policy: dict,
                 session_id: str, output_dir: str, siem_output: str = "file"):
        self.server_id = server_id
        self.mode = mode
        self.policy = policy or {}
        self.mcp_policy = {**DEFAULT_MCP_POLICY, **self.policy.get("hunt_005", {})}
        self.actions = self.policy.get("actions", {
            "passive": ["log"],
            "standard": ["log", "alert"],
            "aggressive": ["log", "alert", "block"],
        })
        self.session_id = session_id
        self.output_dir = output_dir
        self.siem_output = siem_output
        self.alert_count = 0
        # None means "no tools/list has been evaluated yet for this server" -
        # distinct from set() (evaluated, and zero tools were approved). Both
        # evaluate_tool_definitions() and evaluate_tool_call() are invoked from
        # different proxy threads (_server_to_host and _host_to_server
        # respectively - see MCPStdioProxy), so this and the two flags below
        # are read/written under self._lock rather than as bare attributes.
        self.approved_tools: set | None = None
        self.quarantined = False
        self._lock = threading.Lock()

    def _build_finding(self, threat_class: str, severity: str, description: str,
                       evidence: dict, action_taken: str) -> dict:
        with self._lock:
            self.alert_count += 1
            alert_id = f"{self.session_id}-{self.alert_count:04d}"
        return {
            "schema": "GSH-Alert-v1",
            "alert_id": alert_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": self.server_id,
            "enforcement_mode": self.mode,
            "threat_class": threat_class,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "mitre_atlas": ATLAS_HUNT005,
            "nist_csf_2": NIST_HUNT005,
            "action_taken": action_taken,
            "session_id": self.session_id,
            "playbook": PLAYBOOK_ID,
        }

    def _determine_action(self, force_block: bool = False) -> str:
        mode_actions = self.actions.get(self.mode, ["log"])
        if force_block or "block" in mode_actions:
            return "BLOCKED"
        elif "alert" in mode_actions:
            return "ALERTED"
        return "LOGGED"

    def _emit(self, finding: dict) -> None:
        emit_event(finding, self.siem_output, self.output_dir, self.policy)

    def evaluate_tool_definitions(self, tools: list, baseline_path: str) -> tuple:
        """
        Playbook 5.2/5.3 checks 1 and 2: baseline approval, definition
        drift, and semantic scan. Returns (verdict, findings). verdict is
        one of ALLOW / BLOCK.

        A captured snapshot is never itself the trust anchor - see the
        "Baseline approval governance" section above. In aggressive mode,
        a missing or unapproved baseline is treated as a blocking finding
        (defense in depth alongside MCPStdioProxy.run()'s startup refusal,
        for callers that invoke this method directly). In passive/standard
        mode it is logged/alerted but the connection still proceeds.

        The semantic scan (poisoning/invisible-content/cross-tool-reference
        checks) always runs, including on the very first connection to a
        server - a poisoned tool description must not be able to "become
        the trusted baseline" simply by being the first thing seen. Only
        the drift *diff* is skipped when there is no approved baseline to
        diff against, since drift is inherently a comparison.
        """
        findings = []
        current = build_snapshot(self.server_id, tools)
        baseline = load_snapshot(baseline_path)
        approved = is_baseline_approved(baseline)

        if baseline is None:
            save_snapshot(mark_unverified(current), baseline_path)
            logger.warning(
                f"No baseline found for '{self.server_id}'. Captured current "
                f"{len(tools)} tool definition(s) as UNVERIFIED at {baseline_path}. "
                "This snapshot is not trusted until an operator runs "
                "'gsh baseline review' then 'gsh baseline approve'. The semantic "
                "scan below still applies to this first connection."
            )
        elif not approved:
            logger.warning(
                f"Baseline for '{self.server_id}' at {baseline_path} exists but is "
                "not approved (or was modified since approval). Treating as "
                "unverified. Run 'gsh baseline review' then 'gsh baseline approve'."
            )
        else:
            diff = diff_snapshot(current, baseline)
            drift_detected = bool(diff["drifted"] or diff["removed"])
            # Newly *added* tools are reported but not treated as drift on
            # their own - an added tool is unauthorized at call time until
            # reviewed, not a reason to quarantine the whole server.
            if diff["added"]:
                findings.append(self._build_finding(
                    threat_class="MCP Supply Chain / New Tool Since Approval",
                    severity="MEDIUM",
                    description=(
                        f"Server '{self.server_id}' now exposes {len(diff['added'])} tool(s) "
                        f"not present in the approved baseline: {diff['added']}."
                    ),
                    evidence={"added_tools": diff["added"], "baseline_path": baseline_path},
                    action_taken=self._determine_action(),
                ))

            if drift_detected and self.mcp_policy["block_on_definition_drift"]:
                findings.append(self._build_finding(
                    threat_class="MCP Supply Chain / Tool Definition Drift",
                    severity="CRITICAL",
                    description=(
                        f"Server '{self.server_id}' tool definitions changed since the "
                        f"approved baseline. Drifted: {diff['drifted']}, "
                        f"removed: {diff['removed']}. Possible post-approval rug pull."
                    ),
                    evidence={**diff, "baseline_path": baseline_path},
                    action_taken=self._determine_action(force_block=True),
                ))

        if not approved:
            findings.append(self._build_finding(
                threat_class="MCP Supply Chain / Unapproved Baseline",
                severity="HIGH",
                description=(
                    f"Server '{self.server_id}' has no operator-approved baseline. "
                    + (
                        "Aggressive mode requires an approved baseline before any "
                        "traffic from this server is trusted."
                        if self.mode == "aggressive" else
                        "Proceeding under alert; run 'gsh baseline capture' then "
                        "'gsh baseline approve' to establish trust."
                    )
                ),
                evidence={"baseline_path": baseline_path, "server_id": self.server_id},
                action_taken=self._determine_action(force_block=(self.mode == "aggressive")),
            ))

        other_names = [t.get("name", "") for t in tools]
        for tool in tools:
            scan = semantic_scan(tool, other_names)
            is_poisoned = (
                scan["instruction_likelihood"] > self.mcp_policy["instruction_likelihood_threshold"]
                or (scan["invisible_content"] and self.mcp_policy["block_on_invisible_content"])
            )
            if is_poisoned:
                findings.append(self._build_finding(
                    threat_class="MCP Supply Chain / Tool Description Poisoning",
                    severity="CRITICAL",
                    description=(
                        f"Tool '{scan['tool_name']}' on server '{self.server_id}' scored "
                        f"instruction_likelihood={scan['instruction_likelihood']} "
                        f"(threshold {self.mcp_policy['instruction_likelihood_threshold']}) "
                        f"with {len(scan['invisible_content'])} invisible character(s) detected."
                    ),
                    evidence=scan,
                    action_taken=self._determine_action(force_block=True),
                ))
            elif scan["cross_tool_refs"] and self.mcp_policy["flag_cross_tool_references"]:
                findings.append(self._build_finding(
                    threat_class="MCP Supply Chain / Cross-Tool Reference",
                    severity="MEDIUM",
                    description=(
                        f"Tool '{scan['tool_name']}' description references other tool(s) "
                        f"{scan['cross_tool_refs']} - possible tool shadowing setup."
                    ),
                    evidence=scan,
                    action_taken=self._determine_action(),
                ))

        for f in findings:
            self._emit(f)

        overall_block = any(f["action_taken"] == "BLOCKED" for f in findings)
        with self._lock:
            if overall_block:
                self.quarantined = True
                self.approved_tools = set()
            else:
                self.approved_tools = set(current["tool_hashes"].keys())

        return ("BLOCK" if overall_block else "ALLOW"), findings

    def evaluate_tool_call(self, tool_name: str, agent_id: str, arguments: dict) -> tuple:
        """
        Playbook 5.2 check 4: invocation inspection. Returns (verdict, findings).
        verdict is one of ALLOW / BLOCK.

        Reads a consistent (quarantined, approved_tools) snapshot under
        self._lock: evaluate_tool_definitions() runs on the server->host
        thread and can flip both between this method's checks otherwise
        (see MCPStdioProxy._server_to_host / _host_to_server).
        """
        findings = []

        with self._lock:
            quarantined = self.quarantined
            approved_tools = self.approved_tools

        if quarantined:
            findings.append(self._build_finding(
                threat_class="MCP Supply Chain / Call to Quarantined Server",
                severity="CRITICAL",
                description=(
                    f"Agent '{agent_id}' attempted to call tool '{tool_name}' on "
                    f"quarantined server '{self.server_id}'."
                ),
                evidence={"tool_name": tool_name, "agent_id": agent_id},
                action_taken=self._determine_action(force_block=True),
            ))
            self._emit(findings[-1])
            return "BLOCK", findings

        if approved_tools is None:
            # No tools/list response has ever been evaluated for this server
            # (e.g. a host that calls tools/call before/without tools/list,
            # or a race between a fast host and the evaluation thread).
            # Previously approved_tools started as set(), which is falsy, so
            # this unauthorized-tool check was silently skipped entirely on
            # the very first call - fail closed instead.
            findings.append(self._build_finding(
                threat_class="Rogue Agent / Tool Call Before Definitions Evaluated",
                severity="CRITICAL",
                description=(
                    f"Agent '{agent_id}' invoked tool '{tool_name}' on server "
                    f"'{self.server_id}' before any tools/list response for this "
                    "server was evaluated - no approved tool set exists yet."
                ),
                evidence={"tool_name": tool_name, "agent_id": agent_id},
                action_taken=self._determine_action(force_block=True),
            ))
            self._emit(findings[-1])
            blocked = findings[-1]["action_taken"] == "BLOCKED"
            return ("BLOCK" if blocked else "ALLOW"), findings

        if tool_name not in approved_tools:
            findings.append(self._build_finding(
                threat_class="Rogue Agent / Unauthorized MCP Tool Invocation",
                severity="CRITICAL",
                description=(
                    f"Agent '{agent_id}' invoked tool '{tool_name}' on server "
                    f"'{self.server_id}', which is not in the last-validated tool set."
                ),
                evidence={"tool_name": tool_name, "agent_id": agent_id,
                         "approved_tools": sorted(approved_tools)},
                action_taken=self._determine_action(force_block=True),
            ))

        param_issues = inspect_parameters(arguments)
        if param_issues:
            findings.append(self._build_finding(
                threat_class="Rogue Agent / Suspicious Tool Call Parameters",
                severity="HIGH",
                description=(
                    f"Tool call '{tool_name}' from agent '{agent_id}' has suspicious "
                    f"parameter content: {param_issues}."
                ),
                evidence={"tool_name": tool_name, "agent_id": agent_id,
                         "issues": param_issues},
                action_taken=self._determine_action(),
            ))

        for f in findings:
            self._emit(f)

        blocked = any(f["action_taken"] == "BLOCKED" for f in findings)
        return ("BLOCK" if blocked else "ALLOW"), findings


# ---------------------------------------------------------------------------
# One-shot snapshot helper (used by scripts/gsh-mcp-proxy.py --snapshot-only
# and scripts/gsh-probe-eval.py --mode mcp-snapshot)
# ---------------------------------------------------------------------------

class MCPSnapshotError(RuntimeError):
    pass


def connect_and_snapshot(server_cmd: list, server_id: str,
                         timeout: float = 15.0) -> dict:
    """
    Launch an MCP server briefly, perform the initialize handshake, request
    the tool list, and return a snapshot document. Terminates the server
    process before returning.
    """
    proc = subprocess.Popen(
        server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=None, text=True, bufsize=1,
    )
    try:
        _send(proc.stdin, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "gsh-mcp-snapshot", "version": "1.5.0"},
            },
        })
        init_response = _read_with_timeout(proc.stdout, timeout)
        if init_response is None or "error" in init_response:
            raise MCPSnapshotError(
                f"Server did not respond to initialize within {timeout}s: {init_response}"
            )

        _send(proc.stdin, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        _send(proc.stdin, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        list_response = _read_with_timeout(proc.stdout, timeout)
        if list_response is None or "result" not in list_response:
            raise MCPSnapshotError(
                f"Server did not respond to tools/list within {timeout}s: {list_response}"
            )

        tools = list_response["result"].get("tools", [])
        return build_snapshot(server_id, tools)
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def _send(stream, message: dict) -> None:
    stream.write(json.dumps(message) + "\n")
    stream.flush()


def _read_with_timeout(stream, timeout: float) -> dict | None:
    """Blocking readline with a coarse timeout via a background thread."""
    result = {}

    def _reader():
        line = stream.readline()
        if line.strip():
            result["line"] = line

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    t.join(timeout)
    if "line" not in result:
        return None
    try:
        return json.loads(result["line"])
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Live stdio proxy
# ---------------------------------------------------------------------------

class MCPStdioProxy:
    """
    Sits between an MCP host (this process's own stdin/stdout) and a real
    MCP server (spawned as a child process). Intercepts tools/list
    responses for schema drift/poisoning checks and tools/call requests
    for enforcement, relaying everything else unmodified.
    """

    def __init__(self, server_cmd: list, server_id: str, mode: str,
                 policy: dict, baseline_path: str, output_dir: str,
                 siem_output: str | None = None, agent_id: str = "unknown-agent"):
        self.server_cmd = server_cmd
        self.server_id = server_id
        self.mode = mode
        self.baseline_path = baseline_path
        self.agent_id = agent_id
        # siem_output defaults to whatever the policy specifies; an explicit
        # constructor argument (e.g. from a CLI flag) still wins if given.
        resolved_siem_output = siem_output or (policy or {}).get("siem_output", "file")
        session_id = f"GSH-MCP-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        self.engine = MCPPolicyEngine(server_id, mode, policy, session_id,
                                      output_dir, resolved_siem_output)
        self.proc: subprocess.Popen[str] | None = None
        self._stop = threading.Event()

    def run(self) -> int:
        if self.mode == "aggressive":
            baseline = load_snapshot(self.baseline_path)
            if not is_baseline_approved(baseline):
                logger.error(
                    f"Refusing to start: aggressive mode requires an approved "
                    f"baseline for '{self.server_id}' at {self.baseline_path}. "
                    "Run 'gsh baseline capture' then 'gsh baseline review' and "
                    "'gsh baseline approve' before running this server in "
                    "aggressive mode. The MCP server was not launched."
                )
                return 1

        logger.info(f"Launching MCP server: {' '.join(self.server_cmd)}")
        self.proc = subprocess.Popen(
            self.server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=None, text=True, bufsize=1,
        )

        t_up = threading.Thread(target=self._host_to_server, daemon=True)
        t_down = threading.Thread(target=self._server_to_host, daemon=True)
        t_up.start()
        t_down.start()

        try:
            while self.proc.poll() is None and not self._stop.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            logger.info("Interrupted. Shutting down proxy.")
        finally:
            self._stop.set()
            if self.proc.poll() is None:
                self.proc.terminate()
            from adapters.siem_dispatch import flush_all
            flush_all()  # send any buffered (not-yet-sent) SIEM findings before exit

        return self.proc.returncode or 0

    def _reply_error(self, request_id, code: int, message: str) -> None:
        response = {"jsonrpc": "2.0", "id": request_id,
                   "error": {"code": code, "message": message}}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()

    def _host_to_server(self) -> None:
        assert self.proc is not None, "proc must be started before _host_to_server runs"
        assert self.proc.stdin is not None, "proc must be started with stdin=PIPE"
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Dropped non-JSON line from host.")
                continue

            if msg.get("method") == "tools/call" and "id" in msg:
                params = msg.get("params", {})
                tool_name = params.get("name", "")
                arguments = params.get("arguments", {})
                verdict, _ = self.engine.evaluate_tool_call(
                    tool_name, self.agent_id, arguments
                )
                if verdict == "BLOCK":
                    logger.error(
                        f"BLOCKED tools/call '{tool_name}' from '{self.agent_id}' "
                        f"on server '{self.server_id}'."
                    )
                    self._reply_error(
                        msg["id"], -32001,
                        f"Blocked by GSH Sentinel (Hunt-005): tool '{tool_name}' "
                        "failed MCP policy evaluation. See mcp-proxy-events.jsonl.",
                    )
                    continue

            self.proc.stdin.write(line if line.endswith("\n") else line + "\n")
            self.proc.stdin.flush()
        self._stop.set()

    def _server_to_host(self) -> None:
        assert self.proc is not None, "proc must be started before _server_to_host runs"
        assert self.proc.stdout is not None, "proc must be started with stdout=PIPE"
        for line in self.proc.stdout:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                sys.stdout.write(line)
                sys.stdout.flush()
                continue

            result = msg.get("result")
            if isinstance(result, dict) and "tools" in result:
                verdict, _ = self.engine.evaluate_tool_definitions(
                    result["tools"], self.baseline_path
                )
                if verdict == "BLOCK":
                    logger.error(
                        f"QUARANTINED server '{self.server_id}': definition drift or "
                        "tool poisoning detected. Reporting zero tools to host."
                    )
                    msg["result"]["tools"] = []
                    line = json.dumps(msg) + "\n"

            sys.stdout.write(line if line.endswith("\n") else line + "\n")
            sys.stdout.flush()
        self._stop.set()
