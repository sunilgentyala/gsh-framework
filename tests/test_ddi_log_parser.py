"""
tests/test_ddi_log_parser.py
Regression tests for scripts/ddi-log-parser-ai.py's allowlist matching
(Hunt-002: DDI Covert Channel / DNS Tunneling detection).
"""

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "ddi-log-parser-ai.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("ddi_log_parser_ai", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ddi = _load_module()


def test_allowlisted_exact_domain():
    assert ddi.is_allowlisted("cloudflare.com") is True


def test_allowlisted_real_subdomain():
    assert ddi.is_allowlisted("cdn.cloudflare.com") is True
    assert ddi.is_allowlisted("s3.amazonaws.com") is True


def test_lookalike_domain_is_not_allowlisted():
    """
    A domain that merely ends with an allowlisted string, but is not
    actually that domain or a subdomain of it, must not be treated as
    allowlisted - this is a domain-suffix bypass an attacker could use
    to evade Hunt-002's entropy/tunneling checks.
    """
    assert ddi.is_allowlisted("evilcloudflare.com") is False
    assert ddi.is_allowlisted("notarealamazonaws.com") is False
    assert ddi.is_allowlisted("attacker-cloudflare.com") is False


def test_unrelated_domain_is_not_allowlisted():
    assert ddi.is_allowlisted("suspicious-dga-domain.bit") is False
