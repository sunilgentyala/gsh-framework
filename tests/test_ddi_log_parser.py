"""
tests/test_ddi_log_parser.py
Regression tests for scripts/ddi-log-parser-ai.py's allowlist matching
(Hunt-002: DDI Covert Channel / DNS Tunneling detection).
"""

import importlib.util
import sys
from datetime import datetime, timezone
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


def _record(query: str) -> "ddi.DnsRecord":
    return ddi.DnsRecord(
        timestamp=datetime.now(timezone.utc), src_ip="10.0.0.5",
        query=query, qtype="A", response="",
    )


# ---------------------------------------------------------------------------
# Regression tests: an allowlisted apex must raise the detection bar for
# entropy/long-label checks, not bypass it entirely. A full bypass would let
# tunneling traffic hide, with zero scrutiny, under any subdomain of one of
# ~10 broad allowlisted domains (amazonaws.com, cloudfront.net, ...) -
# abusing attacker-controlled infrastructure hosted under a trusted
# third-party domain is a real, documented DNS-tunneling evasion technique.
# ---------------------------------------------------------------------------

def test_high_entropy_tunneling_subdomain_still_flagged_under_allowlisted_apex():
    """Genuinely high-entropy (tunneling-grade) data must still be caught
    even under a trusted apex domain - the bar is raised, not removed."""
    query = "X7pQz9Km2Lw8Rt4Vn6Yb1Jd3Fh5Gs0Cx.s3.amazonaws.com"
    finding = ddi.check_high_entropy_subdomain(_record(query), ddi.DEFAULT_ENTROPY_THRESHOLD)
    assert finding is not None
    assert finding["threshold"] == ddi.DEFAULT_ENTROPY_THRESHOLD + ddi.ALLOWLIST_ENTROPY_BONUS


def test_moderate_entropy_subdomain_not_flagged_under_allowlisted_apex():
    """A moderate-entropy subdomain (typical of CDN asset hashes / distribution
    IDs) that would trip the plain threshold should not, under the raised
    allowlisted-apex threshold - this is the false-positive reduction the
    allowlist exists for."""
    subdomain = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"  # entropy ~3.91 bits
    allowlisted_query = f"{subdomain}.s3.amazonaws.com"
    non_allowlisted_query = f"{subdomain}.evil-tunnel.example"

    assert ddi.check_high_entropy_subdomain(_record(allowlisted_query), ddi.DEFAULT_ENTROPY_THRESHOLD) is None
    assert ddi.check_high_entropy_subdomain(_record(non_allowlisted_query), ddi.DEFAULT_ENTROPY_THRESHOLD) is not None


def test_long_label_still_flagged_under_allowlisted_apex_beyond_bonus():
    long_label = "a" * (ddi.SUSPICIOUS_LABEL_LENGTH + ddi.ALLOWLIST_LABEL_LENGTH_BONUS + 5)
    query = f"{long_label}.cloudfront.net"
    finding = ddi.check_long_label(_record(query))
    assert finding is not None
    assert finding["threshold"] == ddi.SUSPICIOUS_LABEL_LENGTH + ddi.ALLOWLIST_LABEL_LENGTH_BONUS


def test_moderately_long_label_not_flagged_under_allowlisted_apex():
    label = "a" * (ddi.SUSPICIOUS_LABEL_LENGTH + 5)  # exceeds plain threshold, within the allowlist bonus
    allowlisted_query = f"{label}.cloudfront.net"
    non_allowlisted_query = f"{label}.evil-tunnel.example"

    assert ddi.check_long_label(_record(allowlisted_query)) is None
    assert ddi.check_long_label(_record(non_allowlisted_query)) is not None
