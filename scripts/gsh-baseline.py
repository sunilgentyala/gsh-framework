#!/usr/bin/env python3
"""
gsh-baseline.py
Governed Security Hunting (GSH) Framework
MCP Baseline Governance CLI - Hunt-005: MCP Supply Chain & Tool Poisoning

Author: Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
Contact: sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
Version: 1.5.0
License: See LICENSE

Description:
    Manages the approval lifecycle of MCP tool-definition baselines used by
    adapters/mcp_proxy.py (see "Baseline approval governance" in that
    module). A freshly captured baseline is never automatically trusted:

        capture  Connect to a real MCP server, record its current tool
                 definitions as an UNVERIFIED snapshot.
        review   Print a captured snapshot's tools (description, schema,
                 semantic-scan findings) for a human to read before
                 deciding whether to trust it.
        approve  Mark a reviewed snapshot as APPROVED, recording reviewer,
                 timestamp, and a content hash that invalidates the
                 approval if the file is later modified or re-captured.
        verify   Check whether a baseline is currently approved and
                 untampered. Exit code 0 if valid, 1 otherwise - usable in
                 scripts/CI as a pre-flight gate before switching a server
                 to aggressive mode.

    scripts/gsh-mcp-proxy.py in --mode aggressive refuses to launch the
    real MCP server at all unless 'gsh-baseline.py verify' would pass for
    that server's baseline file.

Usage:
    python gsh-baseline.py capture --server-id <label> --server-cmd "<cmd>" [--baseline <path>]
    python gsh-baseline.py review --baseline <path>
    python gsh-baseline.py approve --baseline <path> --reviewer <name> [--signature <str>] [--force]
    python gsh-baseline.py verify --baseline <path>

Examples:
    python gsh-baseline.py capture --server-id corp-tools-mcp-01 \
        --server-cmd "npx -y @modelcontextprotocol/server-filesystem /srv/data"

    python gsh-baseline.py review --baseline baselines/mcp/corp-tools-mcp-01.json

    python gsh-baseline.py approve --baseline baselines/mcp/corp-tools-mcp-01.json \
        --reviewer "jane.doe@example.com"

    python gsh-baseline.py verify --baseline baselines/mcp/corp-tools-mcp-01.json
"""

import argparse
import getpass
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adapters.mcp_proxy import (  # noqa: E402
    connect_and_snapshot, save_snapshot, load_snapshot, mark_unverified,
    approve_baseline, verify_baseline, semantic_scan, MCPSnapshotError,
    split_command,
)

LOG_FORMAT = "%(asctime)s [%(levelname)s] [GSH-Baseline] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("gsh-baseline")


def default_baseline_path(server_id: str) -> str:
    return f"baselines/mcp/{server_id}.json"


def cmd_capture(args) -> int:
    server_cmd = split_command(args.server_cmd)
    baseline_path = args.baseline or default_baseline_path(args.server_id)

    logger.info(f"Connecting to '{args.server_id}' to capture a baseline snapshot...")
    try:
        snapshot = connect_and_snapshot(server_cmd, args.server_id)
    except MCPSnapshotError as e:
        logger.error(str(e))
        return 1

    save_snapshot(mark_unverified(snapshot), baseline_path)
    logger.info(
        f"Captured {snapshot['tool_count']} tool(s) as UNVERIFIED -> {baseline_path}. "
        f"Next: python gsh-baseline.py review --baseline {baseline_path}"
    )
    return 0


def cmd_review(args) -> int:
    baseline_path = args.baseline or default_baseline_path(args.server_id)
    baseline = load_snapshot(baseline_path)
    if baseline is None:
        logger.error(f"No baseline found at '{baseline_path}'. Run 'capture' first.")
        return 1

    approval = baseline.get("approval") or {}
    tools = baseline.get("tools")

    print("=" * 72)
    print(f"  Baseline review: {baseline.get('server_id')}")
    print(f"  File          : {baseline_path}")
    print(f"  Captured      : {baseline.get('created_at')}")
    print(f"  Tool count    : {baseline.get('tool_count')}")
    print(f"  Status        : {approval.get('status', 'unknown').upper()}")
    if approval.get("status") == "approved":
        print(f"  Approved by   : {approval.get('reviewer')}")
        print(f"  Approved at   : {approval.get('approved_at')}")
    print("=" * 72)

    if tools is None:
        print(
            "\nThis snapshot was captured before tool definitions were stored "
            "for review (only hashes are present). Re-run 'capture' against "
            "the live server to get a reviewable snapshot."
        )
        return 0

    other_names = [t.get("name", "") for t in tools]
    any_flagged = False
    for tool in tools:
        scan = semantic_scan(tool, other_names)
        flagged = scan["instruction_likelihood"] > 0.0 or scan["invisible_content"] or scan["cross_tool_refs"]
        any_flagged = any_flagged or (
            scan["instruction_likelihood"] > 0.6 or scan["invisible_content"]
        )
        marker = " [FLAGGED]" if flagged else ""
        print(f"\n--- Tool: {tool.get('name')}{marker} ---")
        print(f"Description: {tool.get('description', '')}")
        print(f"Schema: {tool.get('inputSchema', tool.get('input_schema', {}))}")
        print(f"instruction_likelihood: {scan['instruction_likelihood']}")
        if scan["invisible_content"]:
            print(f"invisible_content: {scan['invisible_content']}")
        if scan["cross_tool_refs"]:
            print(f"cross_tool_refs: {scan['cross_tool_refs']}")

    print()
    if any_flagged:
        print(
            "WARNING: one or more tools scored above the poisoning threshold or "
            "contain invisible Unicode content. Do not approve this baseline "
            "without understanding why before proceeding."
        )
    else:
        print("No poisoning indicators found by the semantic scan.")
    print(f"\nIf this looks correct: python gsh-baseline.py approve --baseline {baseline_path} --reviewer <you>")
    return 0


def cmd_approve(args) -> int:
    baseline_path = args.baseline or default_baseline_path(args.server_id)
    reviewer = args.reviewer or getpass.getuser()

    existing = load_snapshot(baseline_path)
    if existing is None:
        logger.error(f"No baseline found at '{baseline_path}'. Run 'capture' first.")
        return 1

    tools = existing.get("tools")
    if tools and not args.force:
        other_names = [t.get("name", "") for t in tools]
        flagged = [
            t.get("name") for t in tools
            if semantic_scan(t, other_names)["instruction_likelihood"] > 0.6
            or semantic_scan(t, other_names)["invisible_content"]
        ]
        if flagged:
            logger.error(
                f"Refusing to approve: tool(s) {flagged} in this baseline score above "
                "the poisoning threshold or contain invisible Unicode content. Run "
                "'review' to see details. Re-run with --force only if you have "
                "manually verified this is a false positive."
            )
            return 1

    approve_baseline(baseline_path, reviewer=reviewer, signature=args.signature)
    logger.info(f"Baseline at '{baseline_path}' approved by '{reviewer}'.")
    return 0


def cmd_verify(args) -> int:
    baseline_path = args.baseline or default_baseline_path(args.server_id)
    ok, message = verify_baseline(baseline_path)
    if ok:
        logger.info(message)
    else:
        logger.error(message)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gsh-baseline",
        description=(
            "GSH Framework - MCP Baseline Governance\n"
            "Manage the capture -> review -> approve -> verify lifecycle of "
            "MCP tool-definition baselines used by adapters/mcp_proxy.py."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_capture = sub.add_parser("capture", help="Capture a new baseline snapshot from a live MCP server.")
    p_capture.add_argument("--server-id", required=True, help="Label for this server.")
    p_capture.add_argument("--server-cmd", required=True, help="Command to launch the real MCP server.")
    p_capture.add_argument("--baseline", default=None, help="Baseline file path. Default: baselines/mcp/<server-id>.json")
    p_capture.set_defaults(func=cmd_capture)

    p_review = sub.add_parser("review", help="Print a captured baseline's tools for human review.")
    p_review.add_argument("--server-id", default=None, help="Server label (used to derive the default path).")
    p_review.add_argument("--baseline", default=None, help="Baseline file path. Default: baselines/mcp/<server-id>.json")
    p_review.set_defaults(func=cmd_review)

    p_approve = sub.add_parser("approve", help="Mark a reviewed baseline as approved.")
    p_approve.add_argument("--server-id", default=None, help="Server label (used to derive the default path).")
    p_approve.add_argument("--baseline", default=None, help="Baseline file path. Default: baselines/mcp/<server-id>.json")
    p_approve.add_argument("--reviewer", default=None, help="Reviewer identity. Default: current OS username.")
    p_approve.add_argument("--signature", default=None, help="Optional opaque signature/attestation string to record.")
    p_approve.add_argument("--force", action="store_true", help="Approve even if the semantic scan flags a tool.")
    p_approve.set_defaults(func=cmd_approve)

    p_verify = sub.add_parser("verify", help="Check whether a baseline is currently approved and untampered.")
    p_verify.add_argument("--server-id", default=None, help="Server label (used to derive the default path).")
    p_verify.add_argument("--baseline", default=None, help="Baseline file path. Default: baselines/mcp/<server-id>.json")
    p_verify.set_defaults(func=cmd_verify)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
