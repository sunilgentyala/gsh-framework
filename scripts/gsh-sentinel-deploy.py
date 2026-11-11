#!/usr/bin/env python3
"""
gsh-sentinel-deploy.py
Governed Security Hunting (GSH) Framework
Sovereign Sentinel Deployment and Enforcement Engine

Author: Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
Contact: sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
Version: 1.8.0
License: See LICENSE

Description:
    Deploys the Sovereign Sentinel alongside an LLM gateway target.
    Operates in passive (baseline collection), standard (alert-only), or
    aggressive (block + alert) enforcement modes.

    Maps enforcement actions to:
        MITRE ATLAS  : AML.T0048, AML.T0040, AML.T0053
        NIST CSF 2.0 : DE.AE-02, DE.CM-01, RS.MI-01, PR.PS-04

Usage:
    python gsh-sentinel-deploy.py --target <gateway-host> --mode <passive|standard|aggressive> \
        [--policy <yaml-path>] [--baseline-window <duration>] [--output <dir>]
    python gsh-sentinel-deploy.py --validate-policy <yaml-path>

Examples:
    # Passive baseline collection for 7 days
    python gsh-sentinel-deploy.py --target llm-gateway-01 --mode passive --baseline-window 7d

    # Standard enforcement using custom policy
    python gsh-sentinel-deploy.py --target llm-gateway-01 --mode standard \
        --policy configs/sentinel-policy-default.yaml

    # Aggressive enforcement with output to custom directory
    python gsh-sentinel-deploy.py --target llm-gateway-01 --mode aggressive \
        --policy configs/sentinel-policy-default.yaml --output reports/

    # Check a policy file against schemas/sentinel-policy.schema.json and exit
    python gsh-sentinel-deploy.py --validate-policy configs/sentinel-policy-default.yaml
"""

import argparse
import difflib
import hashlib
import json
import logging
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from adapters.siem_dispatch import dispatch_to_siem, flush_all

try:
    import yaml
except ImportError:
    yaml = None

try:
    import jsonschema
except ImportError:
    jsonschema = None

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s [%(levelname)s] [GSH-Sentinel] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("gsh-sentinel")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_MODES = ("passive", "standard", "aggressive")

POLICY_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent / "schemas" / "sentinel-policy.schema.json"
)

DEFAULT_POLICY: dict[str, Any] = {
    "organization": "default-org",
    "sentinel_version": "1.6.0",
    "enforcement_mode": "standard",
    "siem_output": "stdout",
    "egress_allowlist": [],
    "thresholds": {
        "tool_calls_per_minute": 30,
        "loop_detection_window_seconds": 60,
        "loop_min_repetitions": 3,
        "token_velocity_per_minute": 8000,
        "dns_queries_per_minute": 50,
        "behavioral_drift_sigma": 2.5,
    },
    "actions": {
        "passive": ["log"],
        "standard": ["log", "alert"],
        "aggressive": ["log", "alert", "block"],
    },
}

ATLAS_MAPPINGS = {
    "agentic_loop": ["AML.T0048", "AML.T0040"],
    "unauthorized_tool": ["AML.T0053"],
    "ddi_covert_channel": ["AML.T0048", "AML.T0051"],
    "model_poisoning": ["AML.T0020", "AML.T0043", "AML.T0044"],
}

NIST_MAPPINGS = {
    "detect": ["DE.AE-02", "DE.CM-01", "DE.AE-04"],
    "respond": ["RS.MI-01", "RS.AN-03"],
    "protect": ["PR.PS-04", "PR.DS-01"],
}


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def parse_duration(duration_str: str) -> int:
    """Convert duration string (e.g. 7d, 24h, 30m) to seconds."""
    unit_map = {"d": 86400, "h": 3600, "m": 60, "s": 1}
    duration_str = duration_str.strip().lower()
    if not duration_str:
        raise ValueError(
            f"Invalid duration format: '{duration_str}'. Use formats like 7d, 24h, 30m, 60s."
        )
    if duration_str[-1] in unit_map:
        try:
            return int(duration_str[:-1]) * unit_map[duration_str[-1]]
        except ValueError:
            pass
    raise ValueError(f"Invalid duration format: '{duration_str}'. Use formats like 7d, 24h, 30m, 60s.")


# ---------------------------------------------------------------------------
# Policy schema validation
# ---------------------------------------------------------------------------
#
# A policy is checked against schemas/sentinel-policy.schema.json before it
# is merged over DEFAULT_POLICY. `jsonschema` is used when installed;
# otherwise a stdlib validator covering the keywords that schema uses (type,
# properties, required, additionalProperties, items, enum, minimum, maximum)
# enforces the same rules. Both paths produce identical error messages.

class PolicyValidationError(ValueError):
    """A policy file does not match the Sentinel policy schema."""

    def __init__(self, source: str, errors: list[str]):
        self.source = source
        self.errors = errors
        if len(errors) == 1:
            detail = errors[0]
        else:
            detail = f"{len(errors)} errors: " + "; ".join(errors)
        super().__init__(f"Invalid policy '{source}': {detail}")


_TYPE_LABELS = {
    "object": "a mapping",
    "array": "a list",
    "string": "a string",
    "number": "a number",
    "integer": "an integer",
    "boolean": "a boolean",
    "null": "null",
}


def _field_name(path: tuple) -> str:
    """Render a path such as ('hunt_001', 'step_count') as 'hunt_001.step_count'."""
    name = ""
    for part in path:
        if isinstance(part, int):
            name += f"[{part}]"
        else:
            name += f".{part}" if name else str(part)
    return name or "top level"


def _type_name(value: Any) -> str:
    return "null" if value is None else type(value).__name__


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    if isinstance(value, bool):  # bool is an int subclass, but never a number here
        return False
    if expected == "number":
        return isinstance(value, (int, float))
    if expected == "integer":
        return isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    return False


def _type_error(path: tuple, expected: Any, value: Any) -> str:
    types = [expected] if isinstance(expected, str) else list(expected)
    wanted = " or ".join(_TYPE_LABELS.get(t, t) for t in types)
    return f"{_field_name(path)} must be {wanted}, got {_type_name(value)}"


def _missing_error(path: tuple, key: str) -> str:
    return f"{_field_name(path + (key,))} is required but missing"


def _unknown_key_error(path: tuple, key: Any, known: list[str]) -> str:
    if path:
        message = f"{_field_name(path)} has unknown key '{key}'"
    else:
        message = f"unknown top-level section '{key}'"
    close = difflib.get_close_matches(str(key), known, n=1)
    return f"{message} (did you mean '{close[0]}'?)" if close else message


def _enum_error(path: tuple, allowed: list, value: Any) -> str:
    choices = ", ".join(str(a) for a in allowed)
    return f"{_field_name(path)} must be one of: {choices}; got {value!r}"


def _bound_error(path: tuple, keyword: str, bound: Any, value: Any) -> str:
    symbol = ">=" if keyword == "minimum" else "<="
    return f"{_field_name(path)} must be {symbol} {bound}, got {value!r}"


def _stdlib_schema_errors(value: Any, schema: dict, path: tuple = ()) -> list[str]:
    """Validate *value* against the subset of JSON Schema the policy schema uses."""
    expected = schema.get("type")
    if expected is not None:
        types = [expected] if isinstance(expected, str) else expected
        if not any(_matches_type(value, t) for t in types):
            return [_type_error(path, expected, value)]

    errors: list[str] = []
    if "enum" in schema and value not in schema["enum"]:
        errors.append(_enum_error(path, schema["enum"], value))

    if _matches_type(value, "number"):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(_bound_error(path, "minimum", schema["minimum"], value))
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(_bound_error(path, "maximum", schema["maximum"], value))

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(_missing_error(path, key))
        for key, child in value.items():
            if key in properties:
                errors.extend(_stdlib_schema_errors(child, properties[key], path + (key,)))
            elif schema.get("additionalProperties") is False:
                errors.append(_unknown_key_error(path, key, list(properties)))

    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            errors.extend(_stdlib_schema_errors(item, schema["items"], path + (index,)))

    return errors


def _jsonschema_errors(value: Any, schema: dict) -> list[str]:
    """Validate with `jsonschema`, reporting in the same wording as the stdlib path."""
    errors: list[str] = []
    for err in jsonschema.Draft202012Validator(schema).iter_errors(value):
        path = tuple(err.absolute_path)
        if err.validator == "type":
            errors.append(_type_error(path, err.validator_value, err.instance))
        elif err.validator == "required":
            errors.extend(
                _missing_error(path, key)
                for key in err.validator_value if key not in err.instance
            )
        elif err.validator == "additionalProperties":
            known = list(err.schema.get("properties", {}))
            errors.extend(
                _unknown_key_error(path, key, known)
                for key in err.instance if key not in known
            )
        elif err.validator == "enum":
            errors.append(_enum_error(path, err.validator_value, err.instance))
        elif err.validator in ("minimum", "maximum"):
            errors.append(_bound_error(path, err.validator, err.validator_value, err.instance))
        else:
            errors.append(f"{_field_name(path)}: {err.message}")
    return errors


def load_policy_schema() -> dict | None:
    """Return the Sentinel policy JSON Schema, or None if the file is not present."""
    if not POLICY_SCHEMA_PATH.exists():
        return None
    with open(POLICY_SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_policy(loaded: Any, source: str, schema: dict) -> None:
    """Raise PolicyValidationError naming each bad field if *loaded* breaks *schema*."""
    if jsonschema is not None:
        errors = _jsonschema_errors(loaded, schema)
    else:
        errors = _stdlib_schema_errors(loaded, schema)
    if errors:
        raise PolicyValidationError(source, sorted(set(errors)))


def _read_policy_yaml(policy_path: str) -> Any:
    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as exc:
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise ValueError(f"Invalid YAML in policy '{policy_path}': {problem}") from exc


def validate_policy_file(policy_path: str) -> None:
    """
    Strict check behind --validate-policy: unlike load_policy(), nothing here
    falls back to defaults. A missing file, missing PyYAML, or missing schema
    is an error, because the caller asked for a verdict on this exact file.
    """
    if not Path(policy_path).is_file():
        raise FileNotFoundError(f"Policy file not found: '{policy_path}'")
    if yaml is None:
        raise ValueError("PyYAML is required to validate a policy. Run: pip install pyyaml")
    schema = load_policy_schema()
    if schema is None:
        raise FileNotFoundError(f"Policy schema not found at '{POLICY_SCHEMA_PATH}'")
    validate_policy(_read_policy_yaml(policy_path), policy_path, schema)


def load_policy(policy_path: str) -> dict:
    """
    Load the sentinel policy YAML, validate it against the policy schema, and
    merge it over the built-in defaults. A missing path or file falls back to
    defaults; a file that exists but is malformed raises ValueError.
    """
    if not policy_path:
        logger.warning("No policy path provided. Using built-in defaults.")
        return DEFAULT_POLICY.copy()

    path = Path(policy_path)
    if not path.exists():
        logger.warning(f"Policy file not found at '{policy_path}'. Using built-in defaults.")
        return DEFAULT_POLICY.copy()

    if yaml is None:
        logger.warning("PyYAML not installed. Using built-in defaults. Run: pip install pyyaml")
        return DEFAULT_POLICY.copy()

    loaded = _read_policy_yaml(policy_path)

    schema = load_policy_schema()
    if schema is None:
        logger.warning(
            f"Policy schema not found at '{POLICY_SCHEMA_PATH}'. "
            "Skipping policy validation."
        )
    else:
        validate_policy(loaded, policy_path, schema)

    # Merge loaded values over defaults
    policy = DEFAULT_POLICY.copy()
    if isinstance(loaded, dict):
        policy.update(loaded)
        if "thresholds" in loaded:
            policy["thresholds"] = {**DEFAULT_POLICY["thresholds"], **loaded["thresholds"]}

    logger.info(f"Policy loaded from: {policy_path}")
    return policy


def validate_output_dir(output_dir: str) -> None:
    """Create *output_dir* and verify it is writable before a run starts."""
    path = Path(output_dir)
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".gsh-write-test-", dir=path):
            pass
    except (PermissionError, FileNotFoundError, NotADirectoryError, OSError) as exc:
        raise PermissionError(
            f"Output directory '{output_dir}' is not writable. "
            "Check permissions or pass --output <path>."
        ) from exc


def generate_session_id() -> str:
    return f"GSH-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"


def emit_event(event: dict, siem_output: str, output_dir: str, policy: dict | None = None) -> None:
    """
    Emit a structured JSON event to the configured SIEM destination. For
    "splunk"/"elastic", tries real delivery via adapters/siem_dispatch.py
    first; on any failure (misconfiguration, network error, non-2xx
    response) falls back to local file output rather than silently
    dropping the finding.
    """
    if siem_output in ("splunk", "elastic", "windows_eventlog"):
        if dispatch_to_siem(event, siem_output, policy or {}):
            return
        logger.warning(
            f"Delivery to '{siem_output}' failed or is not configured; "
            "writing event to local file instead so it is not lost."
        )

    event_json = json.dumps(event, default=str)

    if siem_output == "stdout":
        print(event_json)
    else:
        # "file" explicitly, or a fallback from an unknown/failed destination
        if siem_output not in ("file", "splunk", "elastic", "windows_eventlog"):
            logger.warning(f"Unknown SIEM output type '{siem_output}'. Falling back to file output.")
        output_path = Path(output_dir) / "sentinel-events.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "a") as f:
            f.write(event_json + "\n")


# ---------------------------------------------------------------------------
# Behavioral baselining
# ---------------------------------------------------------------------------

class BehavioralBaseline:
    """
    Collects and stores behavioral metrics during passive mode.
    Baseline is serialized to baselines/<target>.json on completion.
    """

    def __init__(self, target: str, window_seconds: int, output_dir: str):
        self.target = target
        self.window_seconds = window_seconds
        self.output_dir = output_dir
        self.start_time = datetime.now(timezone.utc)
        self.metrics: dict[str, Any] = {
            "tool_call_rates": [],
            "token_velocities": [],
            "dns_query_rates": [],
            "output_entropy_scores": [],
            "unique_tool_sequences": set(),
        }

    def record_sample(self, tool_calls_pm: float, token_velocity_pm: float,
                      dns_queries_pm: float, output_entropy: float,
                      tool_sequence: tuple) -> None:
        self.metrics["tool_call_rates"].append(tool_calls_pm)
        self.metrics["token_velocities"].append(token_velocity_pm)
        self.metrics["dns_query_rates"].append(dns_queries_pm)
        self.metrics["output_entropy_scores"].append(output_entropy)
        self.metrics["unique_tool_sequences"].add(tool_sequence)

    def _compute_stats(self, values: list) -> dict:
        if not values:
            return {"mean": 0.0, "stddev": 0.0, "min": 0.0, "max": 0.0, "p95": 0.0}
        n = len(values)
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / n
        stddev = variance ** 0.5
        sorted_vals = sorted(values)
        p95_idx = max(0, int(n * 0.95) - 1)
        return {
            "mean": round(mean, 4),
            "stddev": round(stddev, 4),
            "min": round(sorted_vals[0], 4),
            "max": round(sorted_vals[-1], 4),
            "p95": round(sorted_vals[p95_idx], 4),
        }

    def save(self) -> str:
        end_time = datetime.now(timezone.utc)
        duration_hours = (end_time - self.start_time).total_seconds() / 3600

        baseline_doc = {
            "schema_version": "1.0",
            "framework": "GSH",
            "target": self.target,
            "baseline_start": self.start_time.isoformat(),
            "baseline_end": end_time.isoformat(),
            "duration_hours": round(duration_hours, 2),
            "sample_count": len(self.metrics["tool_call_rates"]),
            "statistics": {
                "tool_calls_per_minute": self._compute_stats(self.metrics["tool_call_rates"]),
                "token_velocity_per_minute": self._compute_stats(self.metrics["token_velocities"]),
                "dns_queries_per_minute": self._compute_stats(self.metrics["dns_query_rates"]),
                "output_entropy": self._compute_stats(self.metrics["output_entropy_scores"]),
            },
            "observed_tool_sequences": len(self.metrics["unique_tool_sequences"]),
            "fingerprint": hashlib.sha256(
                f"{self.target}{self.start_time.isoformat()}".encode()
            ).hexdigest()[:16],
        }

        baseline_dir = Path(self.output_dir) / "baselines"
        baseline_dir.mkdir(parents=True, exist_ok=True)
        filename = baseline_dir / f"{self.target.replace('/', '_')}-baseline.json"

        with open(filename, "w") as f:
            json.dump(baseline_doc, f, indent=2)

        logger.info(f"Baseline saved to: {filename}")
        return str(filename)


# ---------------------------------------------------------------------------
# Enforcement engine
# ---------------------------------------------------------------------------

class SovereignSentinel:
    """
    Core enforcement engine. Evaluates LLM gateway events against policy
    thresholds and emits structured alerts mapped to MITRE ATLAS and NIST CSF 2.0.
    """

    def __init__(self, target: str, mode: str, policy: dict,
                 session_id: str, output_dir: str):
        self.target = target
        self.mode = mode
        self.policy = policy
        self.session_id = session_id
        self.output_dir = output_dir
        self.thresholds = policy.get("thresholds", DEFAULT_POLICY["thresholds"])
        self.siem_output = policy.get("siem_output", "stdout")
        self.alert_count = 0
        self.block_count = 0

    def _build_alert(self, threat_class: str, severity: str,
                     description: str, evidence: dict,
                     atlas_ids: list, nist_controls: list,
                     action_taken: str) -> dict:
        self.alert_count += 1
        return {
            "schema": "GSH-Alert-v1",
            "alert_id": f"{self.session_id}-{self.alert_count:04d}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": self.target,
            "enforcement_mode": self.mode,
            "threat_class": threat_class,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "mitre_atlas": atlas_ids,
            "nist_csf_2": nist_controls,
            "action_taken": action_taken,
            "session_id": self.session_id,
        }

    def _determine_action(self) -> str:
        actions = self.policy.get("actions", DEFAULT_POLICY["actions"])
        mode_actions = actions.get(self.mode, ["log"])
        if "block" in mode_actions:
            self.block_count += 1
            return "BLOCKED"
        elif "alert" in mode_actions:
            return "ALERTED"
        return "LOGGED"

    def evaluate_tool_call_rate(self, tool_calls_pm: float) -> dict | None:
        threshold = self.thresholds["tool_calls_per_minute"]
        if tool_calls_pm <= threshold:
            return None
        action = self._determine_action()
        alert = self._build_alert(
            threat_class="Agentic Loop / Resource Exhaustion",
            severity="HIGH",
            description=(
                f"Tool call rate {tool_calls_pm:.1f}/min exceeds threshold {threshold}/min. "
                "Possible agentic loop or resource exhaustion attack in progress."
            ),
            evidence={
                "observed_rate": tool_calls_pm,
                "threshold": threshold,
                "unit": "calls/min",
                "playbook": "Hunt-001",
            },
            atlas_ids=ATLAS_MAPPINGS["agentic_loop"],
            nist_controls=["DE.AE-02", "DE.CM-01", "RS.MI-01"],
            action_taken=action,
        )
        emit_event(alert, self.siem_output, self.output_dir, self.policy)
        return alert

    def evaluate_token_velocity(self, token_velocity_pm: float) -> dict | None:
        threshold = self.thresholds["token_velocity_per_minute"]
        if token_velocity_pm <= threshold:
            return None
        action = self._determine_action()
        alert = self._build_alert(
            threat_class="Agentic Loop / Token Flooding",
            severity="HIGH",
            description=(
                f"Token velocity {token_velocity_pm:.0f}/min exceeds threshold {threshold}/min. "
                "Possible runaway agent or prompt amplification."
            ),
            evidence={
                "observed_rate": token_velocity_pm,
                "threshold": threshold,
                "unit": "tokens/min",
                "playbook": "Hunt-001",
            },
            atlas_ids=ATLAS_MAPPINGS["agentic_loop"],
            nist_controls=["DE.AE-02", "DE.CM-01"],
            action_taken=action,
        )
        emit_event(alert, self.siem_output, self.output_dir, self.policy)
        return alert

    def evaluate_dns_query_rate(self, dns_queries_pm: float) -> dict | None:
        threshold = self.thresholds["dns_queries_per_minute"]
        if dns_queries_pm <= threshold:
            return None
        action = self._determine_action()
        alert = self._build_alert(
            threat_class="DDI Covert Channel / C2 via DNS",
            severity="CRITICAL",
            description=(
                f"DNS query rate {dns_queries_pm:.1f}/min exceeds threshold {threshold}/min. "
                "Possible LLM agent exfiltrating data via DNS tunneling."
            ),
            evidence={
                "observed_rate": dns_queries_pm,
                "threshold": threshold,
                "unit": "queries/min",
                "playbook": "Hunt-002",
            },
            atlas_ids=ATLAS_MAPPINGS["ddi_covert_channel"],
            nist_controls=["DE.CM-01", "DE.AE-04", "PR.DS-01"],
            action_taken=action,
        )
        emit_event(alert, self.siem_output, self.output_dir, self.policy)
        return alert

    def evaluate_behavioral_drift(self, drift_sigma: float,
                                  probe_id: str, baseline_mean: float,
                                  observed_value: float) -> dict | None:
        threshold = self.thresholds["behavioral_drift_sigma"]
        if abs(drift_sigma) <= threshold:
            return None
        action = self._determine_action()
        alert = self._build_alert(
            threat_class="ML Model Poisoning / Behavioral Drift",
            severity="CRITICAL",
            description=(
                f"Behavioral drift of {drift_sigma:.2f} sigma detected on probe '{probe_id}'. "
                f"Baseline mean: {baseline_mean:.4f}, observed: {observed_value:.4f}. "
                "Possible model tampering, supply chain compromise, or runtime manipulation."
            ),
            evidence={
                "probe_id": probe_id,
                "drift_sigma": drift_sigma,
                "baseline_mean": baseline_mean,
                "observed_value": observed_value,
                "threshold_sigma": threshold,
                "playbook": "Hunt-003",
            },
            atlas_ids=ATLAS_MAPPINGS["model_poisoning"],
            nist_controls=["ID.RA-01", "DE.AE-02", "DE.CM-06"],
            action_taken=action,
        )
        emit_event(alert, self.siem_output, self.output_dir, self.policy)
        return alert

    def evaluate_unauthorized_tool(self, tool_name: str,
                                   invoking_agent: str,
                                   allowlist: list) -> dict | None:
        if tool_name in allowlist:
            return None
        action = self._determine_action()
        alert = self._build_alert(
            threat_class="Rogue Agent / Unauthorized Tool Invocation",
            severity="CRITICAL",
            description=(
                f"Agent '{invoking_agent}' attempted to invoke unauthorized tool '{tool_name}'. "
                "Zero-Trust Logic Validation (ZTLV) gate violation."
            ),
            evidence={
                "tool_name": tool_name,
                "invoking_agent": invoking_agent,
                "allowlist": allowlist,
                "playbook": "Hunt-004",
            },
            atlas_ids=ATLAS_MAPPINGS["unauthorized_tool"],
            nist_controls=["PR.PS-04", "RS.AN-03"],
            action_taken=action,
        )
        emit_event(alert, self.siem_output, self.output_dir, self.policy)
        return alert

    def summary(self) -> dict:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "mode": self.mode,
            "total_alerts": self.alert_count,
            "total_blocks": self.block_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Passive mode runner
# ---------------------------------------------------------------------------

def run_passive_mode(target: str, policy: dict, window_seconds: int,
                     session_id: str, output_dir: str) -> None:
    """
    Simulate passive baseline collection. In production, replace the
    sample generation block with real telemetry ingestion from your
    LLM gateway (e.g., OpenAI usage logs, LangChain callbacks, API gateway metrics).
    """
    logger.info(f"[{session_id}] Passive mode active on target: {target}")
    logger.warning(
        "SIMULATION MODE: this run generates synthetic telemetry (random.gauss), "
        "not real data from '%s'. See the 'Replace this block' comment below to wire in "
        "actual LLM gateway telemetry before using this for detection.", target
    )
    logger.info(f"Collecting baseline for {window_seconds}s. Press Ctrl+C to stop early.")

    baseline = BehavioralBaseline(target, window_seconds, output_dir)
    sample_interval = 10  # seconds between samples
    elapsed = 0

    try:
        while elapsed < window_seconds:
            # --- Replace this block with real telemetry ingestion ---
            import random
            tool_calls_pm = random.gauss(12, 3)
            token_velocity_pm = random.gauss(1800, 400)
            dns_queries_pm = random.gauss(8, 2)
            output_entropy = random.gauss(0.72, 0.05)
            tool_sequence = tuple(random.choices(
                ["web_search", "code_exec", "file_read", "api_call"], k=random.randint(1, 4)
            ))
            # --------------------------------------------------------

            baseline.record_sample(
                max(0, tool_calls_pm),
                max(0, token_velocity_pm),
                max(0, dns_queries_pm),
                max(0, min(1, output_entropy)),
                tool_sequence,
            )

            elapsed += sample_interval
            logger.info(
                f"Baseline sample recorded | "
                f"tool_calls/min={tool_calls_pm:.1f} | "
                f"tokens/min={token_velocity_pm:.0f} | "
                f"dns/min={dns_queries_pm:.1f} | "
                f"entropy={output_entropy:.3f} | "
                f"elapsed={elapsed}s/{window_seconds}s"
            )
            time.sleep(1)  # In production, replace with actual wait

    except KeyboardInterrupt:
        logger.info("Baseline collection interrupted by user.")

    baseline_path = baseline.save()
    logger.info(f"Baseline collection complete. File: {baseline_path}")
    logger.info("Run in 'standard' or 'aggressive' mode to begin enforcement.")


# ---------------------------------------------------------------------------
# Enforcement mode runner
# ---------------------------------------------------------------------------

def run_enforcement_mode(target: str, mode: str, policy: dict,
                         session_id: str, output_dir: str) -> None:
    """
    Simulate enforcement mode. In production, replace the telemetry
    ingestion block with your LLM gateway event stream.
    """
    sentinel = SovereignSentinel(target, mode, policy, session_id, output_dir)
    egress_allowlist = policy.get("egress_allowlist", [])

    logger.info(f"[{session_id}] Sovereign Sentinel ACTIVE | target={target} | mode={mode.upper()}")
    logger.info(f"SIEM output: {policy.get('siem_output', 'stdout')}")
    logger.warning(
        "SIMULATION MODE: this run evaluates synthetic telemetry (random.gauss), "
        "not a real event stream from '%s'. No real tool calls are being permitted, "
        "throttled, or blocked. See the 'Replace this block' comment below to wire in "
        "a real LLM gateway or MCP adapter before relying on this for enforcement.", target
    )
    logger.info("Monitoring LLM gateway event stream. Press Ctrl+C to stop.")

    iteration = 0
    try:
        while True:
            iteration += 1

            # --- Replace this block with real LLM gateway telemetry ---
            import random
            tool_calls_pm = random.gauss(12, 8)
            token_velocity_pm = random.gauss(2000, 1500)
            dns_queries_pm = random.gauss(9, 12)
            drift_sigma = random.gauss(0, 1.5)
            unauthorized_tool_event = random.random() < 0.05
            tool_name = random.choice(["shell_exec", "web_fetch", "db_write", "code_exec"])
            invoking_agent = f"agent-{random.randint(1, 5):03d}"
            probe_id = f"GSH-PROBE-{random.randint(1, 20):03d}"
            baseline_mean = 0.72
            observed_value = baseline_mean + (drift_sigma * 0.05)
            # -----------------------------------------------------------

            sentinel.evaluate_tool_call_rate(tool_calls_pm)
            sentinel.evaluate_token_velocity(token_velocity_pm)
            sentinel.evaluate_dns_query_rate(dns_queries_pm)
            sentinel.evaluate_behavioral_drift(drift_sigma, probe_id, baseline_mean, observed_value)

            if unauthorized_tool_event:
                sentinel.evaluate_unauthorized_tool(tool_name, invoking_agent, egress_allowlist)

            if iteration % 10 == 0:
                logger.info(
                    f"Sentinel heartbeat | iteration={iteration} | "
                    f"alerts={sentinel.alert_count} | blocks={sentinel.block_count}"
                )

            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Sentinel stopped by user.")

    summary = sentinel.summary()
    emit_event({"event_type": "SESSION_SUMMARY", **summary},
               policy.get("siem_output", "stdout"), output_dir, policy)
    flush_all()  # send any buffered (not-yet-sent) SIEM findings before exit
    logger.info(f"Session summary: {json.dumps(summary, indent=2)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gsh-sentinel-deploy",
        description=(
            "GSH Framework - Sovereign Sentinel Deployment\n"
            "Autonomous agentic AI threat hunting enforcement engine.\n"
            "Maps to MITRE ATLAS and NIST CSF 2.0."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gsh-sentinel-deploy.py --target llm-gateway-01 --mode passive --baseline-window 7d
  python gsh-sentinel-deploy.py --target llm-gateway-01 --mode standard --policy configs/sentinel-policy-default.yaml
  python gsh-sentinel-deploy.py --target llm-gateway-01 --mode aggressive --output reports/
  python gsh-sentinel-deploy.py --validate-policy configs/sentinel-policy-default.yaml
        """,
    )
    parser.add_argument(
        "--target",
        help="LLM gateway hostname or identifier (e.g. llm-gateway-01). "
             "Required unless --validate-policy is used."
    )
    parser.add_argument(
        "--mode", choices=VALID_MODES,
        help="Enforcement mode: passive (baseline only), standard (alert), aggressive (block + alert). "
             "Required unless --validate-policy is used."
    )
    parser.add_argument(
        "--validate-policy", metavar="PATH", default=None,
        help="Validate a policy YAML against schemas/sentinel-policy.schema.json and exit "
             "(0 = valid, 1 = invalid). No sentinel is started."
    )
    parser.add_argument(
        "--policy", default=None,
        help="Path to sentinel policy YAML (default: built-in defaults)"
    )
    parser.add_argument(
        "--baseline-window", default="7d",
        help="Duration for passive baseline collection (e.g. 7d, 24h, 30m). Default: 7d"
    )
    parser.add_argument(
        "--output", default="reports",
        help="Output directory for reports, baselines, and event logs. Default: reports/"
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity. Default: INFO"
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    if args.validate_policy:
        try:
            validate_policy_file(args.validate_policy)
        except (ValueError, FileNotFoundError) as e:
            logger.error(str(e))
            return 1
        print(f"OK: policy '{args.validate_policy}' is valid")
        return 0

    missing = [flag for flag, value in (("--target", args.target), ("--mode", args.mode)) if not value]
    if missing:
        parser.error(f"the following arguments are required: {', '.join(missing)}")

    output_dir = args.output

    try:
        validate_output_dir(output_dir)
        policy = load_policy(args.policy)
        session_id = generate_session_id()

        logger.info("=" * 72)
        logger.info("  Governed Security Hunting (GSH) Framework v1.6.0")
        logger.info("  Sovereign Sentinel Deployment Engine")
        logger.info(f"  Session ID : {session_id}")
        logger.info(f"  Target     : {args.target}")
        logger.info(f"  Mode       : {args.mode.upper()}")
        logger.info(f"  Org        : {policy.get('organization', 'default-org')}")
        logger.info("=" * 72)

        if args.mode == "passive":
            window_seconds = parse_duration(args.baseline_window)
            logger.info(f"Baseline window: {args.baseline_window} ({window_seconds}s)")
            run_passive_mode(args.target, policy, window_seconds, session_id, output_dir)
        else:
            run_enforcement_mode(args.target, args.mode, policy, session_id, output_dir)
    except (ValueError, PermissionError, FileNotFoundError) as e:
        logger.error(str(e), exc_info=True if args.log_level == "DEBUG" else None)
        return 1
    except Exception:
        logger.exception("Fatal error")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
