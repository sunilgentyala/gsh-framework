"""
GSH Framework - Runtime Adapters

Adapters connect the Sovereign Sentinel policy/alert engine to real
telemetry sources and real enforcement points (as opposed to the
synthetic data generators in scripts/gsh-sentinel-deploy.py).

Modules:
    mcp_proxy   - MCP JSON-RPC stdio proxy: real interception and
                  enforcement for Model Context Protocol tool calls
                  (Hunt-005: MCP Supply Chain & Tool Poisoning).
"""
