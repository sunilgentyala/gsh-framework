"""
tests/test_siem_adapters.py
Governed Security Hunting (GSH) Framework - Tests

Covers adapters/splunk_hec.py, adapters/elastic_bulk.py, and
adapters/siem_dispatch.py. requests.post is mocked throughout - these
tests exercise payload/header shape and failure handling, not real
network calls.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adapters.splunk_hec import SplunkHECAdapter, resolve_secret  # noqa: E402
from adapters.elastic_bulk import ElasticBulkAdapter  # noqa: E402
from adapters import siem_dispatch  # noqa: E402

SAMPLE_FINDING = {
    "schema": "GSH-Alert-v1",
    "alert_id": "TEST-0001",
    "severity": "CRITICAL",
    "threat_class": "Test Finding",
    "description": "unit test finding",
}


# ---------------------------------------------------------------------------
# resolve_secret
# ---------------------------------------------------------------------------

def test_resolve_secret_expands_env_var(monkeypatch):
    monkeypatch.setenv("GSH_TEST_TOKEN", "shh-secret")
    assert resolve_secret("${GSH_TEST_TOKEN}") == "shh-secret"


def test_resolve_secret_passes_through_literal_values():
    assert resolve_secret("literal-value-not-a-var-ref") == "literal-value-not-a-var-ref"


def test_resolve_secret_missing_env_var_returns_empty(monkeypatch):
    monkeypatch.delenv("GSH_TEST_MISSING", raising=False)
    assert resolve_secret("${GSH_TEST_MISSING}") == ""


# ---------------------------------------------------------------------------
# SplunkHECAdapter
# ---------------------------------------------------------------------------

def test_splunk_send_success_shape():
    adapter = SplunkHECAdapter(hec_url="https://splunk.example:8088/services/collector/event",
                               hec_token="test-token", index="gsh-findings")
    mock_response = MagicMock(status_code=200)
    with patch("requests.post", return_value=mock_response) as mock_post:
        result = adapter.send(SAMPLE_FINDING)

    assert result is True
    args, kwargs = mock_post.call_args
    assert args[0] == "https://splunk.example:8088/services/collector/event"
    assert kwargs["headers"]["Authorization"] == "Splunk test-token"
    assert kwargs["json"]["event"] == SAMPLE_FINDING
    assert kwargs["json"]["sourcetype"] == "gsh:alert"
    assert kwargs["json"]["index"] == "gsh-findings"


def test_splunk_send_never_raises_on_network_error():
    adapter = SplunkHECAdapter(hec_url="https://splunk.example:8088/x", hec_token="tok")
    with patch("requests.post", side_effect=ConnectionError("boom")):
        result = adapter.send(SAMPLE_FINDING)
    assert result is False


def test_splunk_send_false_on_non_2xx():
    adapter = SplunkHECAdapter(hec_url="https://splunk.example:8088/x", hec_token="tok")
    mock_response = MagicMock(status_code=503)
    with patch("requests.post", return_value=mock_response):
        result = adapter.send(SAMPLE_FINDING)
    assert result is False


def test_splunk_send_false_when_unconfigured():
    adapter = SplunkHECAdapter(hec_url="", hec_token="")
    assert adapter.send(SAMPLE_FINDING) is False


def test_splunk_never_logs_token(caplog):
    adapter = SplunkHECAdapter(hec_url="https://splunk.example:8088/x", hec_token="super-secret-token")
    with patch("requests.post", side_effect=ConnectionError("boom")):
        adapter.send(SAMPLE_FINDING)
    assert "super-secret-token" not in caplog.text


# ---------------------------------------------------------------------------
# ElasticBulkAdapter
# ---------------------------------------------------------------------------

def test_elastic_flush_builds_valid_ndjson_bulk_body():
    adapter = ElasticBulkAdapter(es_url="https://es.example:9200", index="gsh-findings",
                                 api_key="test-key", flush_size=1)
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {"errors": False}
    with patch("requests.post", return_value=mock_response) as mock_post:
        result = adapter.add(SAMPLE_FINDING)

    assert result is True
    args, kwargs = mock_post.call_args
    assert args[0] == "https://es.example:9200/_bulk"
    assert kwargs["headers"]["Authorization"] == "ApiKey test-key"
    assert kwargs["headers"]["Content-Type"] == "application/x-ndjson"
    lines = kwargs["data"].strip().split("\n")
    assert len(lines) == 2  # one action line, one source line
    import json
    action_line = json.loads(lines[0])
    assert action_line == {"index": {"_index": "gsh-findings"}}
    source_line = json.loads(lines[1])
    assert source_line == SAMPLE_FINDING


def test_elastic_batches_and_does_not_send_until_flush_size_reached():
    adapter = ElasticBulkAdapter(es_url="https://es.example:9200", index="gsh-findings",
                                 flush_size=3)
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {"errors": False}
    with patch("requests.post", return_value=mock_response) as mock_post:
        adapter.add(SAMPLE_FINDING)
        adapter.add(SAMPLE_FINDING)
        assert mock_post.call_count == 0  # not yet flushed
        adapter.add(SAMPLE_FINDING)
        assert mock_post.call_count == 1  # flushed on the 3rd
    assert adapter._buffer == []


def test_elastic_flush_never_raises_on_network_error():
    adapter = ElasticBulkAdapter(es_url="https://es.example:9200", index="gsh-findings")
    with patch("requests.post", side_effect=ConnectionError("boom")):
        result = adapter.add(SAMPLE_FINDING)
    assert result is False
    assert adapter._buffer == []  # buffer cleared even on failure


def test_elastic_flush_false_on_per_item_errors():
    adapter = ElasticBulkAdapter(es_url="https://es.example:9200", index="gsh-findings")
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {"errors": True, "items": [{"index": {"status": 400}}]}
    with patch("requests.post", return_value=mock_response):
        result = adapter.add(SAMPLE_FINDING)
    assert result is False


def test_elastic_flush_false_when_unconfigured():
    adapter = ElasticBulkAdapter(es_url="", index="")
    assert adapter.add(SAMPLE_FINDING) is False


def test_elastic_never_logs_api_key(caplog):
    adapter = ElasticBulkAdapter(es_url="https://es.example:9200", index="gsh-findings",
                                 api_key="super-secret-key")
    with patch("requests.post", side_effect=ConnectionError("boom")):
        adapter.add(SAMPLE_FINDING)
    assert "super-secret-key" not in caplog.text


# ---------------------------------------------------------------------------
# siem_dispatch
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_dispatch_cache():
    siem_dispatch.reset_cache()
    yield
    siem_dispatch.reset_cache()


def test_dispatch_to_splunk_reuses_cached_adapter():
    policy = {"splunk_hec_url": "https://splunk.example:8088/x", "splunk_hec_token": "tok"}
    mock_response = MagicMock(status_code=200)
    with patch("requests.post", return_value=mock_response) as mock_post:
        siem_dispatch.dispatch_to_siem(SAMPLE_FINDING, "splunk", policy)
        siem_dispatch.dispatch_to_siem(SAMPLE_FINDING, "splunk", policy)
    assert mock_post.call_count == 2
    assert len(siem_dispatch._adapter_cache) == 1  # one adapter instance reused


def test_dispatch_unknown_destination_returns_false():
    assert siem_dispatch.dispatch_to_siem(SAMPLE_FINDING, "carrier-pigeon", {}) is False


def test_dispatch_to_elastic_routes_through_adapter():
    policy = {"elastic_url": "https://es.example:9200", "elastic_index": "gsh-findings"}
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {"errors": False}
    with patch("requests.post", return_value=mock_response) as mock_post:
        result = siem_dispatch.dispatch_to_siem(SAMPLE_FINDING, "elastic", policy)
    assert result is True
    assert mock_post.call_count == 1
