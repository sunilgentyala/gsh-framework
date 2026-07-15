#!/usr/bin/env python3
"""
gsh-mcp-proxy.py
Governed Security Hunting (GSH) Framework
MCP Runtime Adapter - Hunt-005: MCP Supply Chain & Tool Poisoning

Author: Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
Contact: sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
Version: 1.4.0
License: See LICENSE

Description:
    A real MCP stdio proxy, not a synthetic telemetry generator. Configure
    your MCP host (Claude Desktop, or any MCP client) to run this script
    in place of the real MCP server; this script launches the real server
    itself as a child process and relays JSON-RPC traffic between the two,
    intercepting tool definitions and tool calls to apply Hunt-005
    detection logic (see playbooks/hunt-005-mcp-tool-poisoning.md).

    On first connection to a server with no recorded baseline, this script
    records the current tool definitions as the trusted approval-time
    snapshot. Use --snapshot-only (or scripts/gsh-probe-eval.py --mode
    mcp-snapshot) to create that baseline deliberately, under review,
    before ever running in enforcement mode.

    Known limitations: see the module docstring in adapters/mcp_proxy.py.

Usage:
    python gsh-mcp-proxy.py --server-cmd "<command to launch the real MCP server>" \
        --server-id <label> [--mode passive|standard|aggressive] \
        [--policy <yaml-path>] [--baseline <json-path>] [--output <dir>] \
        [--agent-id <id>] [--snapshot-only]

Examples:
    # Wrap a real MCP server, alert-only mode, default policy
    python gsh-mcp-proxy.py \
        --server-cmd "npx -y @modelcontextprotocol/server-filesystem /srv/data" \
        --server-id "corp-tools-mcp-01" --mode standard

    # Aggressive enforcement (block on detection), custom policy
    python gsh-mcp-proxy.py \
        --server-cmd "python my_mcp_server.py" \
        --server-id "internal-mcp-01" --mode aggressive \
        --policy configs/sentinel-policy-default.yaml

    # Record the approval-time baseline only, then exit (no proxying)
    python gsh-mcp-proxy.py \
        --server-cmd "python my_mcp_server.py" \
        --server-id "internal-mcp-01" --snapshot-only
"""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adapters.mcp_proxy import (  # noqa: E402
    MCPStdioProxy, connect_and_snapshot, save_snapshot, MCPSnapshotError,
    split_command,
)

try:
    import yaml
except ImportError:
    yaml = None

LOG_FORMAT = "%(asctime)s [%(levelname)s] [GSH-MCPProxy] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, stream=sys.stderr)
logger = logging.getLogger("gsh-mcp-proxy-cli")

VALID_MODES = ("passive", "standard", "aggressive")


def load_policy(policy_path: str | None) -> dict:
    if not policy_path:
        return {}
    path = Path(policy_path)
    if not path.exists():
        logger.warning(f"Policy file not found at '{policy_path}'. Using built-in defaults.")
        return {}
    if yaml is None:
        logger.warning("PyYAML not installed. Using built-in defaults. Run: pip install pyyaml")
        return {}
    with open(path, "r") as f:
        loaded = yaml.safe_load(f)
    return loaded if isinstance(loaded, dict) else {}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gsh-mcp-proxy",
        description=(
            "GSH Framework - MCP Runtime Adapter\n"
            "Hunt-005: MCP Supply Chain & Tool Poisoning\n"
            "Maps to MITRE ATLAS AML.T0010, AML.T0051, AML.T0053"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--server-cmd", required=True,
        help="Command to launch the real MCP server, e.g. "
             '"npx -y @modelcontextprotocol/server-filesystem /srv/data"'
    )
    parser.add_argument(
        "--server-id", required=True,
        help="Label for this server, used for the baseline filename and alert target field."
    )
    parser.add_argument(
        "--mode", default="standard", choices=VALID_MODES,
        help="Enforcement mode: passive (log only), standard (alert), "
             "aggressive (block). Default: standard"
    )
    parser.add_argument(
        "--policy", default=None,
        help="Path to sentinel policy YAML (default: built-in defaults)."
    )
    parser.add_argument(
        "--baseline", default=None,
        help="Path to the approval-time tool-definition snapshot. "
             "Default: baselines/mcp/<server-id>.json"
    )
    parser.add_argument(
        "--output", default="reports",
        help="Output directory for JSONL alert events. Default: reports/"
    )
    parser.add_argument(
        "--agent-id", default="unknown-agent",
        help="Identifier for the agent/host driving this proxy, included in alerts."
    )
    parser.add_argument(
        "--snapshot-only", action="store_true",
        help="Connect just long enough to record the approval-time baseline, then exit "
             "(does not proxy traffic). Equivalent to "
             "gsh-probe-eval.py --mode mcp-snapshot."
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

    server_cmd = split_command(args.server_cmd)
    baseline_path = args.baseline or f"baselines/mcp/{args.server_id}.json"
    policy = load_policy(args.policy)

    if args.snapshot_only:
        logger.info(f"Connecting to '{args.server_id}' to record approval-time snapshot...")
        try:
            snapshot = connect_and_snapshot(server_cmd, args.server_id)
        except MCPSnapshotError as e:
            logger.error(str(e))
            return 1
        save_snapshot(snapshot, baseline_path)
        logger.info(
            f"Snapshot recorded: {snapshot['tool_count']} tool(s) -> {baseline_path}. "
            "Review this file before relying on it for drift detection."
        )
        return 0

    # This process's own stdout is reserved for MCP JSON-RPC traffic back to
    # the host; all proxy logging goes to stderr (see logging.basicConfig above).
    logger.info("=" * 72)
    logger.info("  GSH Framework v1.4.0 - MCP Runtime Adapter")
    logger.info("  Hunt-005: MCP Supply Chain & Tool Poisoning")
    logger.info(f"  Server ID : {args.server_id}")
    logger.info(f"  Mode      : {args.mode.upper()}")
    logger.info(f"  Baseline  : {baseline_path}")
    logger.info("=" * 72)

    proxy = MCPStdioProxy(
        server_cmd=server_cmd,
        server_id=args.server_id,
        mode=args.mode,
        policy=policy,
        baseline_path=baseline_path,
        output_dir=args.output,
        agent_id=args.agent_id,
    )
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
