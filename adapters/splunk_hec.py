"""
adapters/splunk_hec.py
Governed Security Hunting (GSH) Framework
Splunk HTTP Event Collector (HEC) Output Adapter

Author: Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
Contact: sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
Version: 1.3.0
License: See LICENSE

Description:
    Sends GSH-Alert-v1 findings (the shape produced by SovereignSentinel
    in scripts/gsh-sentinel-deploy.py and MCPPolicyEngine in
    adapters/mcp_proxy.py) to a Splunk HTTP Event Collector endpoint.

    Never raises: a Splunk outage or misconfiguration must not crash the
    Sentinel or MCP proxy. Callers should treat send() returning False as
    "not delivered" and fall back to local file output - see
    adapters/siem_dispatch.py, which does exactly that.

    Falls back to a logged warning and a no-op if the optional `requests`
    package is not installed, consistent with this repo's stdlib-fallback
    convention (see requirements.txt).
"""

import logging
import os
import re

logger = logging.getLogger("gsh-siem-splunk")

_ENV_VAR_PATTERN = re.compile(r"^\$\{([A-Za-z0-9_]+)\}$")


def resolve_secret(value: str) -> str:
    """
    Resolve a policy value of the form "${ENV_VAR}" from the process
    environment, so secrets (HEC tokens, API keys) can be referenced from
    a committed policy YAML without the literal value ever being in the
    file. Values not in that exact form are returned unchanged.
    """
    if not value:
        return value
    match = _ENV_VAR_PATTERN.match(value.strip())
    if match:
        return os.environ.get(match.group(1), "")
    return value


class SplunkHECAdapter:
    def __init__(self, hec_url: str, hec_token: str, source: str = "gsh-sentinel",
                 sourcetype: str = "gsh:alert", index: str = "",
                 verify_ssl: bool = True, timeout_seconds: float = 5.0):
        self.hec_url = hec_url
        self.hec_token = resolve_secret(hec_token)
        self.source = source
        self.sourcetype = sourcetype
        self.index = index
        self.verify_ssl = verify_ssl
        self.timeout_seconds = timeout_seconds
        self._warned_no_requests = False

    def _get_requests(self):
        try:
            import requests
            return requests
        except ImportError:
            if not self._warned_no_requests:
                logger.warning(
                    "requests package not installed; Splunk HEC output is disabled "
                    "for this run. Run: pip install requests"
                )
                self._warned_no_requests = True
            return None

    def send(self, finding: dict) -> bool:
        """
        POST one finding to Splunk HEC. Returns True only on a confirmed
        (HTTP < 300) response. Never raises - any exception (network error,
        DNS failure, timeout) is caught, logged as a warning without the
        HEC token, and reported as a False return.
        """
        if not self.hec_url or not self.hec_token:
            logger.warning(
                "Splunk HEC adapter is not configured (missing splunk_hec_url or "
                "splunk_hec_token in policy); event not sent to Splunk."
            )
            return False

        requests = self._get_requests()
        if requests is None:
            return False

        payload = {"event": finding, "sourcetype": self.sourcetype, "source": self.source}
        if self.index:
            payload["index"] = self.index

        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.post(
                self.hec_url, json=payload, headers=headers,
                verify=self.verify_ssl, timeout=self.timeout_seconds,
            )
        except Exception as e:
            logger.warning(f"Splunk HEC send failed ({type(e).__name__}): {e}")
            return False

        if response.status_code >= 300:
            logger.warning(
                f"Splunk HEC returned HTTP {response.status_code}; event not "
                "confirmed delivered."
            )
            return False
        return True
