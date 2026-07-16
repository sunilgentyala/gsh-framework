"""
tests/test_gsh_baseline.py
Governed Security Hunting (GSH) Framework - Tests

Drives the real scripts/gsh-baseline.py CLI as a subprocess against
tests/fixtures/mock_mcp_server.py, exercising the full
capture -> review -> approve -> verify lifecycle (and its safety nets)
end-to-end rather than just the library functions in adapters/mcp_proxy.py.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MOCK_SERVER = REPO_ROOT / "tests" / "fixtures" / "mock_mcp_server.py"
BASELINE_CLI = REPO_ROOT / "scripts" / "gsh-baseline.py"


def _run(*args):
    result = subprocess.run(
        [sys.executable, str(BASELINE_CLI), *args],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    return result.returncode, result.stdout, result.stderr


def _mock_server_cmd(*flags):
    cmd = f'"{sys.executable}" "{MOCK_SERVER}"'
    if flags:
        cmd += " " + " ".join(flags)
    return cmd


def test_capture_review_approve_verify_happy_path(tmp_path):
    baseline_path = tmp_path / "baseline.json"

    rc, _, err = _run("capture", "--server-id", "srv", "--server-cmd",
                      _mock_server_cmd(), "--baseline", str(baseline_path))
    assert rc == 0, err
    assert baseline_path.exists()
    doc = json.loads(baseline_path.read_text())
    assert doc["approval"]["status"] == "unverified"

    rc, out, err = _run("verify", "--baseline", str(baseline_path))
    assert rc == 1, "an unverified baseline must not pass verify"

    rc, out, err = _run("review", "--baseline", str(baseline_path))
    assert rc == 0, err
    assert "echo" in out and "add" in out

    rc, out, err = _run("approve", "--baseline", str(baseline_path), "--reviewer", "tester")
    assert rc == 0, err
    doc = json.loads(baseline_path.read_text())
    assert doc["approval"]["status"] == "approved"
    assert doc["approval"]["reviewer"] == "tester"

    rc, out, err = _run("verify", "--baseline", str(baseline_path))
    assert rc == 0, err


def test_approve_refuses_poisoned_tools_without_force(tmp_path):
    baseline_path = tmp_path / "baseline.json"

    rc, _, err = _run("capture", "--server-id", "srv", "--server-cmd",
                      _mock_server_cmd("--poisoned"), "--baseline", str(baseline_path))
    assert rc == 0, err

    rc, out, err = _run("approve", "--baseline", str(baseline_path), "--reviewer", "tester")
    assert rc == 1, "approve must refuse a poisoned baseline without --force"
    doc = json.loads(baseline_path.read_text())
    assert doc["approval"]["status"] == "unverified"

    rc, out, err = _run("approve", "--baseline", str(baseline_path),
                        "--reviewer", "tester", "--force")
    assert rc == 0, err
    doc = json.loads(baseline_path.read_text())
    assert doc["approval"]["status"] == "approved"


def test_verify_reports_missing_baseline(tmp_path):
    rc, out, err = _run("verify", "--baseline", str(tmp_path / "nope.json"))
    assert rc == 1


def test_approve_requires_prior_capture(tmp_path):
    rc, out, err = _run("approve", "--baseline", str(tmp_path / "nope.json"), "--reviewer", "x")
    assert rc == 1
