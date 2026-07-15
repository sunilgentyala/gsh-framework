"""
adapters/elastic_bulk.py
Governed Security Hunting (GSH) Framework
Elasticsearch/OpenSearch Bulk Output Adapter

Author: Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
Contact: sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
Version: 1.5.0
License: See LICENSE

Description:
    Sends GSH-Alert-v1 findings to Elasticsearch or OpenSearch via the
    _bulk API, using the optional `requests` package rather than the full
    elasticsearch-py client (consistent with this repo's minimal-dependency
    convention - see requirements.txt).

    Batches findings rather than firing one HTTP request per event: add()
    buffers and auto-flushes once flush_size or flush_interval_seconds is
    reached. The default flush_size is 1 (send immediately) because for a
    security-alerting tool, losing a buffered CRITICAL finding to a crash
    is worse than the extra HTTP requests; raise flush_size in policy for
    high-volume deployments that need real batching.

    Never raises: an Elastic outage or misconfiguration must not crash the
    Sentinel or MCP proxy. See adapters/siem_dispatch.py for the fallback
    behavior when a send fails.
"""

import json
import logging
import time

from adapters.splunk_hec import resolve_secret

logger = logging.getLogger("gsh-siem-elastic")


class ElasticBulkAdapter:
    def __init__(self, es_url: str, index: str, api_key: str = "",
                 flush_size: int = 1, flush_interval_seconds: float = 5.0,
                 verify_ssl: bool = True, timeout_seconds: float = 5.0):
        self.es_url = es_url.rstrip("/") if es_url else es_url
        self.index = index
        self.api_key = resolve_secret(api_key)
        self.flush_size = max(1, flush_size)
        self.flush_interval_seconds = flush_interval_seconds
        self.verify_ssl = verify_ssl
        self.timeout_seconds = timeout_seconds
        self._buffer: list = []
        self._last_flush = time.monotonic()
        self._warned_no_requests = False

    def _get_requests(self):
        try:
            import requests
            return requests
        except ImportError:
            if not self._warned_no_requests:
                logger.warning(
                    "requests package not installed; Elastic output is disabled "
                    "for this run. Run: pip install requests"
                )
                self._warned_no_requests = True
            return None

    def add(self, finding: dict) -> bool:
        """
        Buffer one finding; flush automatically once flush_size or
        flush_interval_seconds is reached. Returns the result of flush()
        if a flush was triggered, otherwise True (buffered, not yet sent -
        not a delivery confirmation).
        """
        self._buffer.append(finding)
        due = (
            len(self._buffer) >= self.flush_size
            or (time.monotonic() - self._last_flush) >= self.flush_interval_seconds
        )
        if due:
            return self.flush()
        return True

    def flush(self) -> bool:
        """
        Send all buffered findings via the _bulk API. Returns True only if
        the request succeeded with no per-item errors. Never raises. The
        buffer is cleared regardless of outcome - GSH prioritizes not
        blocking or crashing the caller over guaranteed delivery; callers
        that need a delivery guarantee should treat a False return as
        "write these findings to local file too" (see
        adapters/siem_dispatch.py).
        """
        if not self._buffer:
            return True

        if not self.es_url or not self.index:
            logger.warning(
                "Elastic adapter is not configured (missing elastic_url or "
                f"elastic_index in policy); dropping {len(self._buffer)} event(s)."
            )
            self._buffer.clear()
            return False

        requests = self._get_requests()
        if requests is None:
            self._buffer.clear()
            return False

        lines = []
        for finding in self._buffer:
            lines.append(json.dumps({"index": {"_index": self.index}}))
            lines.append(json.dumps(finding, default=str))
        body = "\n".join(lines) + "\n"

        headers = {"Content-Type": "application/x-ndjson"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"

        count = len(self._buffer)
        self._buffer.clear()
        self._last_flush = time.monotonic()

        try:
            response = requests.post(
                f"{self.es_url}/_bulk", data=body, headers=headers,
                verify=self.verify_ssl, timeout=self.timeout_seconds,
            )
        except Exception as e:
            logger.warning(f"Elastic bulk send failed ({type(e).__name__}): {e}")
            return False

        if response.status_code >= 300:
            logger.warning(
                f"Elastic bulk request returned HTTP {response.status_code}; "
                f"{count} event(s) not confirmed delivered."
            )
            return False

        try:
            result = response.json()
        except Exception:
            return True  # 2xx with an unparseable body - treat as delivered

        if result.get("errors"):
            logger.warning(
                f"Elastic bulk request completed with per-item errors among "
                f"{count} event(s)."
            )
            return False
        return True
