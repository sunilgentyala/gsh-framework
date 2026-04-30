#!/usr/bin/env python3
"""
gsh-sentinel-deploy.py
Governed Security Hunting (GSH) Framework
Sovereign Sentinel Deployment and Enforcement Engine

Author: Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
Contact: sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
Version: 1.0.0-beta
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

Examples:
    # Passive baseline collection for 7 days
    python gsh-sentinel-deploy.py --target llm-gateway-01 --mode passive --baseline-window 7d

    # Standard enforcement using custom policy
    python gsh-sentinel-deploy.py --target llm-gateway-01 --mode standard \
        --policy configs/sentinel-policy-default.yaml

    # Aggressive enforcement with output to custom directory
    python gsh-sentinel-deploy.py --target llm-gateway-01 --mode aggressive \
        --policy configs/sentinel-policy-default.yaml --output reports/
"""

import argparse
import json
import logging
import os
import sys
import time
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None

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

DEFAULT_POLICY = {
    "organization": "default-org",
    "sentinel_version": "1.0.0-beta",
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
    if duration_str[-1] in unit_map:
        try:
            return int(duration_str[:-1]) * unit_map[duration_str[-1]]
        except ValueError:
            pass
    raise ValueError(f"Invalid duration format: '{duration_str}'. Use formats like 7d, 24h, 30m, 60s.")


def load_policy(policy_path: str) -> dict:
    """Load and validate the sentinel policy YAML. Falls back to defaults on failure."""
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

    with open(path, "r") as f:
        loaded = yaml.safe_load(f)

    # Merge loaded values over defaults
    policy = DEFAULT_POLICY.copy()
    if isinstance(loaded, dict):
        policy.update(loaded)
        if "thresholds" in loaded:
            policy["thresholds"] = {**DEFAULT_POLICY["thresholds"], **loaded["thresholds"]}

    logger.info(f"Policy loaded from: {policy_path}")
    return policy


def generate_session_id() -> str:
    return f"GSH-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"


def emit_event(event: dict, siem_output: str, output_dir: str) -> None:
    """Emit a structured JSON event to configured SIEM destination."""
    event_json = json.dumps(event, default=str)

    if siem_output == "stdout":
        print(event_json)
    elif siem_output == "file":
        output_path = Path(output_dir) / "sentinel-events.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "a") as f:
            f.write(event_json + "\n")
    else:
        # Extensible: add Splunk HEC, Elastic, QRadar integrations here
        logger.warning(f"Unknown SIEM output type '{siem_output}'. Falling back to stdout.")
        print(event_json)


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
        emit_event(alert, self.siem_output, self.output_dir)
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
        emit_event(alert, self.siem_output, self.output_dir)
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
        emit_event(alert, self.siem_output, self.output_dir)
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
        emit_event(alert, self.siem_output, self.output_dir)
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
        emit_event(alert, self.siem_output, self.output_dir)
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
               policy.get("siem_output", "stdout"), output_dir)
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
        """,
    )
    parser.add_argument(
        "--target", required=True,
        help="LLM gateway hostname or identifier (e.g. llm-gateway-01)"
    )
    parser.add_argument(
        "--mode", required=True, choices=VALID_MODES,
        help="Enforcement mode: passive (baseline only), standard (alert), aggressive (block + alert)"
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

    session_id = generate_session_id()
    policy = load_policy(args.policy)
    output_dir = args.output

    logger.info("=" * 72)
    logger.info("  Governed Security Hunting (GSH) Framework v1.0.0-beta")
    logger.info("  Sovereign Sentinel Deployment Engine")
    logger.info(f"  Session ID : {session_id}")
    logger.info(f"  Target     : {args.target}")
    logger.info(f"  Mode       : {args.mode.upper()}")
    logger.info(f"  Org        : {policy.get('organization', 'default-org')}")
    logger.info("=" * 72)

    try:
        if args.mode == "passive":
            window_seconds = parse_duration(args.baseline_window)
            logger.info(f"Baseline window: {args.baseline_window} ({window_seconds}s)")
            run_passive_mode(args.target, policy, window_seconds, session_id, output_dir)
        else:
            run_enforcement_mode(args.target, args.mode, policy, session_id, output_dir)
    except ValueError as e:
        logger.error(str(e))
        return 1
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
