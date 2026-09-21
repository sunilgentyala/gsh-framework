#!/usr/bin/env python3
"""
demo/run_demo.py
Governed Security Hunting (GSH) Framework - Hunt-005 end-to-end demo

Plays the role of an MCP host and drives the REAL scripts/gsh-baseline.py and
scripts/gsh-mcp-proxy.py against a mock MCP server, through four scenarios:

  1. Approve a baseline, then run a normal session           -> allowed
  2. Rug pull: same tool name, schema changed after approval -> quarantined
  3. Tool poisoning: hidden instruction in a description     -> quarantined
  4. Implementation swap: IDENTICAL schema, changed code     -> never launched

Exit code is 0 only if every scenario behaved as expected, so this doubles
as a smoke test (see demo/smoke_test.sh).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASELINE_CLI = REPO / "scripts" / "gsh-baseline.py"
PROXY_CLI = REPO / "scripts" / "gsh-mcp-proxy.py"
SERVER_SRC = REPO / "demo" / "mock-mcp-server" / "server.py"

SERVER_ID = "demo-mcp-01"
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "gsh-demo-host", "version": "1.0"}}}

failures: list[str] = []


def banner(text: str) -> None:
    print(f"\n{'=' * 72}\n  {text}\n{'=' * 72}", flush=True)


def check(label: str, ok: bool) -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}", flush=True)
    if not ok:
        failures.append(label)


def server_cmd(work: Path) -> str:
    return f'"{sys.executable}" "{work / "server.py"}"'


class Session:
    """One MCP host session against gsh-mcp-proxy.py (real subprocess)."""

    def __init__(self, work: Path, mode: str):
        self.proc = subprocess.Popen(
            [sys.executable, str(PROXY_CLI),
             "--server-cmd", server_cmd(work), "--server-id", SERVER_ID,
             "--mode", mode, "--baseline", str(work / "baseline.json"),
             "--output", str(work / "reports"), "--agent-id", "demo-host",
             "--log-level", "WARNING"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.stdin, self.stdout = self.proc.stdin, self.proc.stdout
        self._next = 100

    def request(self, method: str, params: dict | None = None, timeout: float = 5.0):
        """Send one request, return its response (None if the proxy is gone)."""
        if method == "initialize":
            msg = INIT
        else:
            msg = {"jsonrpc": "2.0", "id": self._next, "method": method,
                   "params": params or {}}
            self._next += 1
        try:
            self.stdin.write(json.dumps(msg) + "\n")
            self.stdin.flush()
        except (BrokenPipeError, OSError):
            return None
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.stdout.readline()
            if not line:
                return None
            try:
                resp = json.loads(line)
            except json.JSONDecodeError:
                continue
            if resp.get("id") == msg["id"]:
                return resp
        return None

    def close(self) -> int:
        try:
            self.stdin.close()
        except OSError:
            pass
        try:
            return self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return -1


def run_cli(cli: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(cli), *args], capture_output=True,
                          text=True, cwd=REPO, check=False)


def alerts(work: Path) -> list:
    path = work / "reports" / "mcp-proxy-events.jsonl"
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def show_new_alerts(work: Path, seen: int) -> int:
    found = alerts(work)
    for a in found[seen:]:
        print(f"    ALERT [{a['severity']}] {a['threat_class']}: "
              f"{a['description']} -> {a['action_taken']}", flush=True)
    return len(found)


def has_class(work: Path, fragment: str) -> bool:
    return any(fragment in a["threat_class"] for a in alerts(work))


def tool_names(resp) -> list:
    return [t["name"] for t in (resp or {}).get("result", {}).get("tools", [])]


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="gsh-demo-"))
    os.environ["GSH_DEMO_STATE_FILE"] = str(work / "mode")
    shutil.copy(SERVER_SRC, work / "server.py")
    (work / "mode").write_text("clean")
    baseline = work / "baseline.json"
    seen = 0

    banner("Setup: capture, review and approve a baseline (Hunt-005)")
    r = run_cli(BASELINE_CLI, "capture", "--server-id", SERVER_ID,
                "--server-cmd", server_cmd(work), "--baseline", str(baseline))
    check("baseline captured as UNVERIFIED", r.returncode == 0)
    r = run_cli(BASELINE_CLI, "approve", "--baseline", str(baseline),
                "--reviewer", "demo-reviewer")
    check("baseline approved (schema hashes + implementation identity bound)",
          r.returncode == 0)
    r = run_cli(BASELINE_CLI, "verify", "--baseline", str(baseline))
    check("baseline verifies as approved and untampered", r.returncode == 0)

    banner("Scenario 1: normal session against the approved server")
    s = Session(work, "aggressive")
    s.request("initialize")
    listed = s.request("tools/list")
    check(f"tools/list returns the approved tools {tool_names(listed)}",
          sorted(tool_names(listed)) == ["add", "echo"])
    call = s.request("tools/call", {"name": "add", "arguments": {"a": 2, "b": 3}})
    text = ((call or {}).get("result", {}).get("content") or [{}])[0].get("text")
    check("tools/call add(2, 3) is permitted and returns 5", text == "5")
    s.close()
    seen = show_new_alerts(work, seen)

    banner("Scenario 2: RUG PULL - echo gains an unrelated 'api_keys' parameter")
    (work / "mode").write_text("rug-pull")
    s = Session(work, "aggressive")
    s.request("initialize")
    listed = s.request("tools/list")
    check("server quarantined: host sees ZERO tools", tool_names(listed) == [])
    call = s.request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    check("tools/call echo is BLOCKED by the Sentinel",
          call is not None and call.get("error", {}).get("code") == -32001)
    s.close()
    seen = show_new_alerts(work, seen)
    check("CRITICAL drift alert recorded (and the launch gate did NOT fire)",
          any(a["severity"] == "CRITICAL" for a in alerts(work))
          and not has_class(work, "Identity"))

    banner("Scenario 3: TOOL POISONING - hidden instruction in a description")
    (work / "mode").write_text("poisoned")
    seen_before = seen
    s = Session(work, "aggressive")
    s.request("initialize")
    listed = s.request("tools/list")
    check("server quarantined: host sees ZERO tools", tool_names(listed) == [])
    s.close()
    seen = show_new_alerts(work, seen)
    check("poisoning finding recorded and the launch gate did NOT fire",
          len(alerts(work)) > seen_before and not has_class(work, "Identity"))

    banner("Scenario 4: IMPLEMENTATION SWAP - schema is IDENTICAL, code is not")
    (work / "mode").write_text("clean")
    with open(work / "server.py", "a") as f:
        f.write("\n# swapped implementation: same tool schema, different code\n")
    s = Session(work, "aggressive")
    resp = s.request("initialize", timeout=3.0)
    code = s.close()
    check("server was never launched: no response to initialize", resp is None)
    check("proxy refused to start (exit code 1)", code == 1)
    seen = show_new_alerts(work, seen)
    check("Implementation Identity finding recorded",
          has_class(work, "Identity"))

    banner("Result")
    print(f"  Evidence: {work / 'reports' / 'mcp-proxy-events.jsonl'}")
    if failures:
        print(f"  DEMO FAILED: {len(failures)} check(s) did not behave as expected:")
        for failed in failures:
            print(f"    - {failed}")
        return 1
    print("  All scenarios behaved as expected: the Sentinel caught the rug pull,")
    print("  the poisoned description, and the swapped implementation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
