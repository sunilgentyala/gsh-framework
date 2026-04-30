#!/usr/bin/env python3
"""
ddi-log-parser-ai.py
Governed Security Hunting (GSH) Framework
DNS/DHCP/IPAM (DDI) Log Parser with AI Agent Anomaly Detection

Author: Sunil Gentyala, Lead Cybersecurity and AI Security Consultant, HCLTech
Contact: sunil.gentyala@ieee.org | sunil.gentyala@hcltech.com
Version: 1.0.0-beta
License: See LICENSE

Description:
    Parses DDI (DNS/DHCP/IPAM) logs to detect anomalous DNS activity
    attributable to LLM agents or multi-agent pipelines. Detects:

        - DNS tunneling / C2 covert channel exfiltration (Hunt-002)
        - Unusually high subdomain entropy (data encoding via DNS labels)
        - Beaconing patterns in query timing
        - Rare TLD usage consistent with DGA (Domain Generation Algorithm)
        - Agent IP correlation against known LLM gateway address ranges

    Maps findings to:
        MITRE ATLAS  : AML.T0048, AML.T0051
        MITRE ATT&CK : T1071.004, T1048, T1568
        NIST CSF 2.0 : DE.CM-01, DE.AE-04, PR.DS-01

Supported log formats:
    - BIND 9 named query log (default)
    - Infoblox DDI syslog export (--format infoblox)
    - Generic CSV (--format csv) with fields: timestamp,src_ip,query,qtype,response
    - JSON newline-delimited (--format json)

Usage:
    python ddi-log-parser-ai.py --input <log-file> [--format <format>]
        [--agent-cidrs <cidr,...>] [--output <dir>] [--threshold-entropy <float>]
        [--threshold-query-rate <int>] [--window-seconds <int>]

Examples:
    python ddi-log-parser-ai.py --input logs/dns-query.log
    python ddi-log-parser-ai.py --input logs/infoblox-export.log --format infoblox \
        --agent-cidrs 10.10.50.0/24,10.10.51.0/24 --output reports/
    python ddi-log-parser-ai.py --input logs/dns.json --format json \
        --threshold-entropy 3.8 --window-seconds 30
"""

import argparse
import csv
import io
import json
import logging
import math
import os
import re
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network, IPv4Address, IPv4Network
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s [%(levelname)s] [GSH-DDI] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("gsh-ddi")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum subdomain label entropy (Shannon bits) to flag as suspicious
DEFAULT_ENTROPY_THRESHOLD = 3.5

# Max DNS queries per source IP per window before flagging beaconing
DEFAULT_QUERY_RATE_THRESHOLD = 50

# Sliding window for rate analysis (seconds)
DEFAULT_WINDOW_SECONDS = 60

# Labels longer than this in a query suggest data encoding
SUSPICIOUS_LABEL_LENGTH = 20

# TLDs commonly used by DGA or covert channels
HIGH_RISK_TLDS = {
    ".bit", ".onion", ".i2p", ".bazar", ".coin", ".lib",
    ".emc", ".chan", ".null", ".locker",
}

# Common legitimate base domains to reduce false positives
ALLOWLISTED_DOMAINS = {
    "amazonaws.com", "azure.com", "googleapis.com", "cloudfront.net",
    "akamaitechnologies.com", "fastly.net", "cloudflare.com",
    "microsoft.com", "apple.com", "akamai.net",
}

ATLAS_HUNT002 = ["AML.T0048", "AML.T0051"]
ATTCK_HUNT002 = ["T1071.004", "T1048", "T1568"]
NIST_HUNT002 = ["DE.CM-01", "DE.AE-04", "PR.DS-01"]

# ---------------------------------------------------------------------------
# DNS record parsing
# ---------------------------------------------------------------------------

class DnsRecord:
    """Normalized DNS query record from any supported log format."""
    __slots__ = ("timestamp", "src_ip", "query", "qtype", "response", "raw")

    def __init__(self, timestamp: datetime, src_ip: str, query: str,
                 qtype: str, response: str, raw: str = ""):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.query = query.lower().rstrip(".")
        self.qtype = qtype.upper()
        self.response = response
        self.raw = raw

    def __repr__(self):
        return f"DnsRecord({self.timestamp.isoformat()}, {self.src_ip}, {self.query}, {self.qtype})"


# BIND 9 named query log pattern:
# 01-Jan-2026 14:23:01.123 queries: info: client @0x... 10.0.0.5#54321
#   (example.com): query: example.com IN A +ED (192.168.1.1)
BIND9_PATTERN = re.compile(
    r"(?P<ts>\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+)"
    r".*?client\s+(?:@\S+\s+)?(?P<src_ip>\d+\.\d+\.\d+\.\d+)#\d+"
    r".*?query:\s+(?P<query>\S+)\s+IN\s+(?P<qtype>\w+)"
)

# Infoblox syslog pattern (simplified):
# Jan  1 14:23:01 infoblox named[12345]: client 10.0.0.5#54321:
#   query: example.com IN A + (192.168.1.1)
INFOBLOX_PATTERN = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
    r".*?client\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)#\d+:?"
    r"\s+query:\s+(?P<query>\S+)\s+IN\s+(?P<qtype>\w+)"
)


def _parse_bind9_ts(ts_str: str) -> datetime:
    try:
        return datetime.strptime(ts_str.split(".")[0], "%d-%b-%Y %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return datetime.now(timezone.utc)


def _parse_syslog_ts(ts_str: str) -> datetime:
    year = datetime.now(timezone.utc).year
    try:
        return datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return datetime.now(timezone.utc)


def parse_bind9(lines: Iterator[str]) -> Iterator[DnsRecord]:
    for line in lines:
        m = BIND9_PATTERN.search(line)
        if m:
            yield DnsRecord(
                timestamp=_parse_bind9_ts(m.group("ts")),
                src_ip=m.group("src_ip"),
                query=m.group("query"),
                qtype=m.group("qtype"),
                response="",
                raw=line.rstrip(),
            )


def parse_infoblox(lines: Iterator[str]) -> Iterator[DnsRecord]:
    for line in lines:
        m = INFOBLOX_PATTERN.search(line)
        if m:
            yield DnsRecord(
                timestamp=_parse_syslog_ts(m.group("ts")),
                src_ip=m.group("src_ip"),
                query=m.group("query"),
                qtype=m.group("qtype"),
                response="",
                raw=line.rstrip(),
            )


def parse_csv_format(lines: Iterator[str]) -> Iterator[DnsRecord]:
    """
    Expected CSV columns: timestamp,src_ip,query,qtype,response
    timestamp format: ISO 8601 or Unix epoch integer.
    """
    reader = csv.DictReader(lines)
    for row in reader:
        try:
            ts_raw = row.get("timestamp", "")
            try:
                ts = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc)
            except (ValueError, TypeError):
                ts = datetime.fromisoformat(ts_raw).replace(tzinfo=timezone.utc)
            yield DnsRecord(
                timestamp=ts,
                src_ip=row.get("src_ip", "0.0.0.0"),
                query=row.get("query", ""),
                qtype=row.get("qtype", "A"),
                response=row.get("response", ""),
                raw=str(row),
            )
        except Exception:
            continue


def parse_json_format(lines: Iterator[str]) -> Iterator[DnsRecord]:
    """
    Expected JSON fields: timestamp (ISO or epoch), src_ip, query, qtype, response.
    One JSON object per line (newline-delimited JSON).
    """
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            ts_raw = obj.get("timestamp", "")
            try:
                ts = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc)
            except (ValueError, TypeError):
                ts = datetime.fromisoformat(str(ts_raw)).replace(tzinfo=timezone.utc)
            yield DnsRecord(
                timestamp=ts,
                src_ip=obj.get("src_ip", "0.0.0.0"),
                query=obj.get("query", ""),
                qtype=obj.get("qtype", "A"),
                response=obj.get("response", ""),
                raw=line,
            )
        except Exception:
            continue


FORMAT_PARSERS = {
    "bind9": parse_bind9,
    "infoblox": parse_infoblox,
    "csv": parse_csv_format,
    "json": parse_json_format,
}


# ---------------------------------------------------------------------------
# Anomaly detection logic
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits) of a string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def extract_base_domain(query: str) -> str:
    """Extract registrable base domain (last two labels)."""
    parts = query.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return query


def extract_subdomain(query: str) -> str:
    """Return everything before the last two labels."""
    parts = query.split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2])
    return ""


def is_allowlisted(query: str) -> bool:
    base = extract_base_domain(query)
    return any(query.endswith(allowed) for allowed in ALLOWLISTED_DOMAINS)


def check_high_entropy_subdomain(record: DnsRecord,
                                 threshold: float) -> dict | None:
    if is_allowlisted(record.query):
        return None
    subdomain = extract_subdomain(record.query)
    if not subdomain:
        return None
    entropy = shannon_entropy(subdomain.replace(".", ""))
    if entropy < threshold:
        return None
    return {
        "detection_type": "HIGH_ENTROPY_SUBDOMAIN",
        "severity": "CRITICAL",
        "src_ip": record.src_ip,
        "query": record.query,
        "subdomain": subdomain,
        "entropy_bits": round(entropy, 4),
        "threshold": threshold,
        "description": (
            f"Subdomain '{subdomain}' has Shannon entropy {entropy:.2f} bits "
            f"(threshold: {threshold}). Consistent with data encoding for DNS tunneling."
        ),
        "mitre_atlas": ATLAS_HUNT002,
        "mitre_attck": ATTCK_HUNT002,
        "nist_csf_2": NIST_HUNT002,
        "playbook": "Hunt-002",
        "raw": record.raw,
    }


def check_long_label(record: DnsRecord) -> dict | None:
    if is_allowlisted(record.query):
        return None
    labels = record.query.split(".")
    long_labels = [l for l in labels if len(l) > SUSPICIOUS_LABEL_LENGTH]
    if not long_labels:
        return None
    return {
        "detection_type": "LONG_DNS_LABEL",
        "severity": "HIGH",
        "src_ip": record.src_ip,
        "query": record.query,
        "long_labels": long_labels,
        "max_label_length": max(len(l) for l in long_labels),
        "threshold": SUSPICIOUS_LABEL_LENGTH,
        "description": (
            f"DNS label(s) exceed {SUSPICIOUS_LABEL_LENGTH} characters: {long_labels}. "
            "Long labels are a known indicator of DNS tunneling or DGA."
        ),
        "mitre_atlas": ATLAS_HUNT002,
        "mitre_attck": ATTCK_HUNT002,
        "nist_csf_2": NIST_HUNT002,
        "playbook": "Hunt-002",
        "raw": record.raw,
    }


def check_high_risk_tld(record: DnsRecord) -> dict | None:
    for tld in HIGH_RISK_TLDS:
        if record.query.endswith(tld):
            return {
                "detection_type": "HIGH_RISK_TLD",
                "severity": "HIGH",
                "src_ip": record.src_ip,
                "query": record.query,
                "matched_tld": tld,
                "description": (
                    f"Query resolved TLD '{tld}' which is associated with "
                    "darknet, DGA, or covert C2 infrastructure."
                ),
                "mitre_atlas": ATLAS_HUNT002,
                "mitre_attck": ATTCK_HUNT002,
                "nist_csf_2": NIST_HUNT002,
                "playbook": "Hunt-002",
                "raw": record.raw,
            }
    return None


class BeaconingDetector:
    """
    Tracks DNS query rates per source IP over a sliding time window.
    Flags IPs that exceed the query rate threshold within the window.
    Also detects regular periodic intervals (beaconing signature).
    """

    def __init__(self, window_seconds: int, threshold: int):
        self.window_seconds = window_seconds
        self.threshold = threshold
        # src_ip -> deque of query timestamps
        self.query_times: dict[str, deque] = defaultdict(deque)
        self.interval_tracker: dict[str, list] = defaultdict(list)

    def record(self, record: DnsRecord) -> dict | None:
        src = record.src_ip
        ts = record.timestamp.timestamp()
        window = self.query_times[src]

        # Evict old entries outside window
        while window and (ts - window[0]) > self.window_seconds:
            window.popleft()

        window.append(ts)

        # Track inter-query intervals for beaconing detection
        if len(window) >= 2:
            interval = ts - window[-2]
            self.interval_tracker[src].append(interval)

        if len(window) > self.threshold:
            rate = len(window) / self.window_seconds * 60
            beaconing_score = self._beaconing_score(src)
            return {
                "detection_type": "DNS_QUERY_RATE_SPIKE",
                "severity": "CRITICAL",
                "src_ip": src,
                "query": record.query,
                "query_count_in_window": len(window),
                "rate_per_minute": round(rate, 2),
                "window_seconds": self.window_seconds,
                "threshold": self.threshold,
                "beaconing_score": beaconing_score,
                "description": (
                    f"Source IP {src} made {len(window)} DNS queries in {self.window_seconds}s "
                    f"({rate:.1f}/min). Threshold: {self.threshold}. "
                    f"Beaconing regularity score: {beaconing_score:.3f} (1.0 = perfectly periodic)."
                ),
                "mitre_atlas": ATLAS_HUNT002,
                "mitre_attck": ATTCK_HUNT002,
                "nist_csf_2": NIST_HUNT002,
                "playbook": "Hunt-002",
                "raw": record.raw,
            }
        return None

    def _beaconing_score(self, src_ip: str) -> float:
        """
        Score 0-1 indicating how regular the inter-query intervals are.
        Score near 1.0 is highly periodic (beaconing). Score near 0 is random.
        Uses coefficient of variation (CV): stddev/mean. Inverted and clamped.
        """
        intervals = self.interval_tracker[src_ip]
        if len(intervals) < 5:
            return 0.0
        n = len(intervals)
        mean = sum(intervals) / n
        if mean == 0:
            return 0.0
        variance = sum((x - mean) ** 2 for x in intervals) / n
        stddev = variance ** 0.5
        cv = stddev / mean
        return round(max(0.0, min(1.0, 1.0 - cv)), 4)


def is_agent_ip(src_ip: str, agent_cidrs: list) -> bool:
    """Check if a source IP falls within known LLM agent gateway CIDR ranges."""
    if not agent_cidrs:
        return False
    try:
        addr = ip_address(src_ip)
        return any(addr in net for net in agent_cidrs)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Finding serialization and output
# ---------------------------------------------------------------------------

def emit_finding(finding: dict, output_dir: str, findings_list: list) -> None:
    finding["timestamp"] = datetime.now(timezone.utc).isoformat()
    findings_list.append(finding)
    logger.warning(
        f"[{finding['detection_type']}] [{finding['severity']}] "
        f"src={finding.get('src_ip', 'N/A')} query={finding.get('query', 'N/A')} | "
        f"{finding['description'][:120]}"
    )


def write_report(findings: list, input_path: str, output_dir: str,
                 stats: dict) -> str:
    report = {
        "schema": "GSH-DDI-Report-v1",
        "framework": "GSH",
        "playbook": "Hunt-002",
        "mitre_atlas": ATLAS_HUNT002,
        "mitre_attck": ATTCK_HUNT002,
        "nist_csf_2": NIST_HUNT002,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_path),
        "statistics": stats,
        "total_findings": len(findings),
        "findings_by_severity": {
            "CRITICAL": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        },
        "findings": findings,
    }

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    report_path = out_dir / f"ddi-hunt002-{timestamp_str}.json"

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    return str(report_path)


# ---------------------------------------------------------------------------
# Main analysis pipeline
# ---------------------------------------------------------------------------

def analyze(input_path: str, log_format: str, agent_cidrs: list,
            entropy_threshold: float, query_rate_threshold: int,
            window_seconds: int, output_dir: str) -> int:
    """
    Main analysis pipeline. Returns count of findings.
    """
    path = Path(input_path)
    if not path.exists():
        logger.error(f"Input file not found: {input_path}")
        return -1

    parser_fn = FORMAT_PARSERS.get(log_format)
    if parser_fn is None:
        logger.error(f"Unknown format '{log_format}'. Choices: {list(FORMAT_PARSERS)}")
        return -1

    logger.info(f"Parsing {input_path} as format='{log_format}'")
    logger.info(f"Entropy threshold: {entropy_threshold} bits | "
                f"Rate threshold: {query_rate_threshold}/window | "
                f"Window: {window_seconds}s")

    findings: list[dict] = []
    beaconing_detector = BeaconingDetector(window_seconds, query_rate_threshold)

    stats = {
        "total_records_parsed": 0,
        "records_from_agent_ips": 0,
        "unique_source_ips": set(),
        "unique_queries": set(),
    }

    with open(path, "r", errors="replace") as f:
        for record in parser_fn(f):
            stats["total_records_parsed"] += 1
            stats["unique_source_ips"].add(record.src_ip)
            stats["unique_queries"].add(record.query)

            agent_flag = is_agent_ip(record.src_ip, agent_cidrs)
            if agent_flag:
                stats["records_from_agent_ips"] += 1

            # Run detections
            finding = check_high_entropy_subdomain(record, entropy_threshold)
            if finding:
                finding["from_agent_ip"] = agent_flag
                emit_finding(finding, output_dir, findings)

            finding = check_long_label(record)
            if finding:
                finding["from_agent_ip"] = agent_flag
                emit_finding(finding, output_dir, findings)

            finding = check_high_risk_tld(record)
            if finding:
                finding["from_agent_ip"] = agent_flag
                emit_finding(finding, output_dir, findings)

            finding = beaconing_detector.record(record)
            if finding:
                finding["from_agent_ip"] = agent_flag
                emit_finding(finding, output_dir, findings)

    stats["unique_source_ips"] = len(stats["unique_source_ips"])
    stats["unique_queries"] = len(stats["unique_queries"])

    logger.info(f"Analysis complete | records={stats['total_records_parsed']} | "
                f"findings={len(findings)}")

    if findings:
        report_path = write_report(findings, input_path, output_dir, stats)
        logger.info(f"Report written to: {report_path}")
    else:
        logger.info("No anomalies detected.")

    return len(findings)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ddi-log-parser-ai",
        description=(
            "GSH Framework - DDI Log Parser with AI Agent Anomaly Detection\n"
            "Hunt-002: DDI Covert Channel / C2 via DNS\n"
            "Maps to MITRE ATLAS AML.T0048, AML.T0051 | MITRE ATT&CK T1071.004, T1048\n"
            "NIST CSF 2.0: DE.CM-01, DE.AE-04, PR.DS-01"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ddi-log-parser-ai.py --input logs/dns-query.log
  python ddi-log-parser-ai.py --input logs/dns.json --format json --agent-cidrs 10.10.50.0/24
  python ddi-log-parser-ai.py --input logs/infoblox.log --format infoblox --output reports/
        """,
    )
    parser.add_argument("--input", required=True, help="Path to DDI log file")
    parser.add_argument(
        "--format", default="bind9",
        choices=list(FORMAT_PARSERS),
        help="Log format. Default: bind9"
    )
    parser.add_argument(
        "--agent-cidrs", default="",
        help="Comma-separated list of CIDR ranges for known LLM agent IPs "
             "(e.g. 10.10.50.0/24,10.10.51.0/24)"
    )
    parser.add_argument(
        "--threshold-entropy", type=float, default=DEFAULT_ENTROPY_THRESHOLD,
        help=f"Minimum Shannon entropy (bits) to flag subdomain. Default: {DEFAULT_ENTROPY_THRESHOLD}"
    )
    parser.add_argument(
        "--threshold-query-rate", type=int, default=DEFAULT_QUERY_RATE_THRESHOLD,
        help=f"Max DNS queries per source IP per window. Default: {DEFAULT_QUERY_RATE_THRESHOLD}"
    )
    parser.add_argument(
        "--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS,
        help=f"Sliding window duration for rate analysis (seconds). Default: {DEFAULT_WINDOW_SECONDS}"
    )
    parser.add_argument(
        "--output", default="reports",
        help="Output directory for JSON reports. Default: reports/"
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity. Default: INFO"
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    # Parse agent CIDR list
    agent_cidrs = []
    if args.agent_cidrs:
        for cidr_str in args.agent_cidrs.split(","):
            cidr_str = cidr_str.strip()
            if cidr_str:
                try:
                    agent_cidrs.append(ip_network(cidr_str, strict=False))
                except ValueError as e:
                    logger.error(f"Invalid CIDR '{cidr_str}': {e}")
                    return 1

    logger.info("=" * 72)
    logger.info("  GSH Framework v1.0.0-beta - DDI Log Parser")
    logger.info("  Hunt-002: DDI Covert Channel / C2 via DNS")
    logger.info(f"  Input   : {args.input}")
    logger.info(f"  Format  : {args.format}")
    logger.info(f"  CIDRs   : {[str(c) for c in agent_cidrs] or 'none specified'}")
    logger.info("=" * 72)

    finding_count = analyze(
        input_path=args.input,
        log_format=args.format,
        agent_cidrs=agent_cidrs,
        entropy_threshold=args.threshold_entropy,
        query_rate_threshold=args.threshold_query_rate,
        window_seconds=args.window_seconds,
        output_dir=args.output,
    )

    if finding_count < 0:
        return 1
    elif finding_count > 0:
        logger.warning(f"HUNT COMPLETE: {finding_count} anomalies detected. Review report in {args.output}/")
        return 2  # Non-zero to allow CI/CD pipeline integration
    else:
        logger.info("HUNT COMPLETE: No anomalies detected.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
