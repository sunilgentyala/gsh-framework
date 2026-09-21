# GSH Hunt-005 Demo: catch a rug pull, a poisoned tool and a swapped implementation

One command, no setup beyond Docker:

```bash
cd demo
docker compose up --build --abort-on-container-exit
```

No Docker? The same demo runs with Python 3.10+ and PyYAML from the repo root:

```bash
pip install pyyaml
python demo/run_demo.py
```

## What it does

`run_demo.py` plays an MCP host and drives the real `scripts/gsh-baseline.py` and `scripts/gsh-mcp-proxy.py` (Hunt-005) against a small mock MCP server (`mock-mcp-server/server.py`). No traffic is simulated: the proxy sits between the host and the server exactly as it would in production, in `--mode aggressive`.

| Step | What changes | Expected result |
|---|---|---|
| Setup | Capture, approve and verify a baseline | Baseline binds tool schema hashes and the server's Implementation Identity |
| 1. Normal session | Nothing | Tools listed, `add(2, 3)` returns `5` |
| 2. Rug pull | `echo` gains an unrelated `api_keys` parameter after approval | CRITICAL "Tool Definition Drift", server quarantined (host sees zero tools), `echo` call blocked |
| 3. Tool poisoning | `echo` description gains a hidden instruction and a zero-width character | CRITICAL "Tool Description Poisoning", server quarantined |
| 4. Implementation swap | Tool schema is **identical**, the server code is modified | CRITICAL "Implementation Identity Mismatch", server is **never launched** |

Every check prints `[PASS]` or `[FAIL]`. The container exits `0` only if all of them pass, so it doubles as a smoke test (`./smoke_test.sh`, also run in CI). Alerts are written to `mcp-proxy-events.jsonl` in the container's temp directory (path printed at the end).

## Try breaking it

The mock server's behavior is set by the file named in `GSH_DEMO_STATE_FILE` (`clean`, `rug-pull`, `poisoned`). Add your own mode to `mock-mcp-server/server.py`, then add a scenario to `run_demo.py`. Bypasses, false positives and false negatives are exactly the contributions we want; see [CONTRIBUTING.md](../CONTRIBUTING.md).

## Scope and limits

- **One container, not two.** The proxy launches the MCP server as a child process over stdio, so the "Sentinel" and the server run together. There is no separate server container.
- **Stdio transport only.** Streamable HTTP/SSE MCP servers are not covered by Hunt-005 yet.
- **Implementation Identity is hashes of the launch executable, script files named in the command, and an adjacent dependency lock.** It does not cover container image digests or package registry provenance. Note that any file named on the launch command line is hashed, which is why the demo passes its mutable state file through an environment variable instead.
- The mock server is a test double, not a real MCP implementation.
