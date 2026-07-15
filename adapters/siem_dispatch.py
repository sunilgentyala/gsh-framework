"""
adapters/siem_dispatch.py
Governed Security Hunting (GSH) Framework
Shared SIEM Output Dispatch

Author: Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
Contact: sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
Version: 1.4.0
License: See LICENSE

Description:
    Both scripts/gsh-sentinel-deploy.py (Hunt-001-004) and
    adapters/mcp_proxy.py (Hunt-005) need to send findings to Splunk or
    Elastic when policy["siem_output"] is set accordingly. This module
    wires the two real adapters (adapters/splunk_hec.py,
    adapters/elastic_bulk.py) in exactly once rather than duplicating the
    dispatch logic per caller.

    Adapter instances are cached per (destination, config) so a long-running
    Sentinel or proxy session reuses one Elastic buffer / one Splunk client
    across many findings instead of reconnecting per event.
"""

import logging

from adapters.elastic_bulk import ElasticBulkAdapter
from adapters.splunk_hec import SplunkHECAdapter

logger = logging.getLogger("gsh-siem-dispatch")

_adapter_cache: dict = {}


def _cache_key(kind: str, policy: dict) -> tuple:
    if kind == "splunk":
        return ("splunk", policy.get("splunk_hec_url", ""))
    return ("elastic", policy.get("elastic_url", ""), policy.get("elastic_index", ""))


def dispatch_to_siem(finding: dict, siem_output: str, policy: dict) -> bool:
    """
    Attempt delivery to a real SIEM backend. Returns True only if the
    finding was confirmed delivered - callers should treat False as "not
    delivered" and fall back to local file output so the finding is never
    silently lost (see emit_event() in scripts/gsh-sentinel-deploy.py and
    adapters/mcp_proxy.py).
    """
    policy = policy or {}

    if siem_output == "splunk":
        key = _cache_key("splunk", policy)
        adapter = _adapter_cache.get(key)
        if adapter is None:
            adapter = SplunkHECAdapter(
                hec_url=policy.get("splunk_hec_url", ""),
                hec_token=policy.get("splunk_hec_token", ""),
                index=policy.get("splunk_index", ""),
            )
            _adapter_cache[key] = adapter
        return adapter.send(finding)

    if siem_output == "elastic":
        key = _cache_key("elastic", policy)
        adapter = _adapter_cache.get(key)
        if adapter is None:
            adapter = ElasticBulkAdapter(
                es_url=policy.get("elastic_url", ""),
                index=policy.get("elastic_index", "gsh-findings"),
                api_key=policy.get("elastic_api_key", ""),
                flush_size=int(policy.get("elastic_flush_size", 1)),
                flush_interval_seconds=float(policy.get("elastic_flush_interval_seconds", 5.0)),
            )
            _adapter_cache[key] = adapter
        return adapter.add(finding)

    return False


def flush_all() -> None:
    """
    Flush any buffered (not-yet-sent) findings on every cached adapter that
    supports buffering. Call this before process exit - see the `finally`
    blocks in adapters/mcp_proxy.py's MCPStdioProxy.run() and
    scripts/gsh-sentinel-deploy.py's main().
    """
    for adapter in _adapter_cache.values():
        if hasattr(adapter, "flush"):
            adapter.flush()


def reset_cache() -> None:
    """Test-only: clear cached adapter instances between test cases."""
    _adapter_cache.clear()
