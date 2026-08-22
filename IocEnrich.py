#!/usr/bin/env python3
"""
IOC Enrichment Tool
--------------------
Takes Indicators of Compromise (IPs, domains, URLs, file hashes) and enriches
them against multiple threat intelligence sources:

    - VirusTotal (v3 API)
    - AbuseIPDB (IP reputation)
    - AlienVault OTX

Usage:
    # Single IOC
    python3 ioc_enrich.py --ioc 8.8.8.8

    # Batch from a file (one IOC per line, blank lines / '#' comments ignored)
    python3 ioc_enrich.py --input iocs.txt --output report.csv

    # JSON output instead of CSV
    python3 ioc_enrich.py --input iocs.txt --output report.json --format json

API keys are read from environment variables so nothing sensitive lives in
the code:
    export VT_API_KEY="..."
    export ABUSEIPDB_API_KEY="..."
    export OTX_API_KEY="..."

Any source whose key is missing is skipped automatically (not treated as an
error) so the tool still runs with partial coverage.
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import requests  # pyright: ignore[reportMissingModuleSource]

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

VT_API_KEY = os.environ.get("VT_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.environ.get("OTX_API_KEY")

# Free-tier VirusTotal is 4 req/min. Keep a conservative delay between calls
# to any single source so the tool doesn't get rate-limited mid-run.
REQUEST_DELAY_SECONDS = 16

HASH_RE = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


# --------------------------------------------------------------------------
# IOC classification
# --------------------------------------------------------------------------

def classify_ioc(raw: str) -> str:
    """Return one of: ip, url, hash, domain, unknown."""
    value = raw.strip()

    if value.startswith(("http://", "https://")):
        return "url"

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    for _, pattern in HASH_RE.items():
        if pattern.match(value):
            return "hash"

    if DOMAIN_RE.match(value):
        return "domain"

    return "unknown"


# --------------------------------------------------------------------------
# Result container
# --------------------------------------------------------------------------

@dataclass
class EnrichmentResult:
    ioc: str
    ioc_type: str
    sources_checked: list = field(default_factory=list)
    malicious_votes: int = 0
    total_votes: int = 0
    abuse_confidence_score: Optional[int] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    tags: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def verdict(self) -> str:
        if self.abuse_confidence_score and self.abuse_confidence_score >= 75:
            return "MALICIOUS"
        if self.total_votes == 0:
            return "UNKNOWN"
        ratio = self.malicious_votes / self.total_votes
        if ratio >= 0.2:
            return "MALICIOUS"
        if ratio > 0:
            return "SUSPICIOUS"
        return "CLEAN"


# --------------------------------------------------------------------------
# Source: VirusTotal
# --------------------------------------------------------------------------

def query_virustotal(ioc: str, ioc_type: str, result: EnrichmentResult) -> None:
    if not VT_API_KEY:
        result.notes.append("VirusTotal skipped: VT_API_KEY not set")
        return

    headers = {"x-apikey": VT_API_KEY}
    base = "https://www.virustotal.com/api/v3"

    if ioc_type == "ip":
        url = f"{base}/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"{base}/domains/{ioc}"
    elif ioc_type == "hash":
        url = f"{base}/files/{ioc}"
    elif ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        url = f"{base}/urls/{url_id}"
    else:
        return

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        result.sources_checked.append("VirusTotal")
        if resp.status_code == 404:
            result.notes.append("VirusTotal: no record found")
            return
        if resp.status_code == 401:
            result.notes.append("VirusTotal: invalid API key")
            return
        if resp.status_code == 429:
            result.notes.append("VirusTotal: rate limited")
            return
        resp.raise_for_status()

        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        result.malicious_votes += malicious + suspicious
        result.total_votes += malicious + suspicious + harmless + undetected

        if data.get("country"):
            result.country = data["country"]
        if data.get("as_owner"):
            result.isp = data["as_owner"]

        tags = data.get("tags", [])
        result.tags.extend(tags)
        result.raw["virustotal"] = stats
    except requests.RequestException as exc:
        result.notes.append(f"VirusTotal error: {exc}")


# --------------------------------------------------------------------------
# Source: AbuseIPDB (IP only)
# --------------------------------------------------------------------------

def query_abuseipdb(ioc: str, ioc_type: str, result: EnrichmentResult) -> None:
    if ioc_type != "ip":
        return
    if not ABUSEIPDB_API_KEY:
        result.notes.append("AbuseIPDB skipped: ABUSEIPDB_API_KEY not set")
        return

    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": 90}

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=15,
        )
        result.sources_checked.append("AbuseIPDB")
        if resp.status_code == 401:
            result.notes.append("AbuseIPDB: invalid API key")
            return
        if resp.status_code == 429:
            result.notes.append("AbuseIPDB: rate limited")
            return
        resp.raise_for_status()

        data = resp.json().get("data", {})
        result.abuse_confidence_score = data.get("abuseConfidenceScore")
        result.country = result.country or data.get("countryCode")
        result.isp = result.isp or data.get("isp")
        result.raw["abuseipdb"] = {
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "totalReports": data.get("totalReports"),
            "usageType": data.get("usageType"),
        }
    except requests.RequestException as exc:
        result.notes.append(f"AbuseIPDB error: {exc}")


# --------------------------------------------------------------------------
# Source: AlienVault OTX
# --------------------------------------------------------------------------

def query_otx(ioc: str, ioc_type: str, result: EnrichmentResult) -> None:
    if not OTX_API_KEY:
        result.notes.append("OTX skipped: OTX_API_KEY not set")
        return

    section_map = {
        "ip": f"IPv4/{ioc}",
        "domain": f"domain/{ioc}",
        "hash": f"file/{ioc}",
        "url": f"url/{requests.utils.quote(ioc, safe='')}",
    }
    if ioc_type not in section_map:
        return

    url = f"https://otx.alienvault.com/api/v1/indicators/{section_map[ioc_type]}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        result.sources_checked.append("AlienVault OTX")
        if resp.status_code == 404:
            result.notes.append("OTX: no record found")
            return
        if resp.status_code == 403:
            result.notes.append("OTX: invalid API key")
            return
        resp.raise_for_status()

        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        result.malicious_votes += 1 if pulse_count > 0 else 0
        result.total_votes += 1
        pulses = data.get("pulse_info", {}).get("pulses", [])
        for pulse in pulses[:5]:
            name = pulse.get("name")
            if name:
                result.tags.append(name)
        result.raw["otx_pulse_count"] = pulse_count
    except requests.RequestException as exc:
        result.notes.append(f"OTX error: {exc}")


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

SOURCE_FUNCS = [query_virustotal, query_abuseipdb, query_otx]


def enrich_ioc(raw_ioc: str, delay: float) -> EnrichmentResult:
    ioc = raw_ioc.strip()
    ioc_type = classify_ioc(ioc)
    result = EnrichmentResult(ioc=ioc, ioc_type=ioc_type)

    if ioc_type == "unknown":
        result.notes.append("Could not classify IOC type; skipped enrichment")
        return result

    for func in SOURCE_FUNCS:
        func(ioc, ioc_type, result)
        if delay:
            time.sleep(delay)

    result.tags = sorted(set(result.tags))
    return result


def load_iocs(path: Optional[str], single: Optional[str]) -> list:
    if single:
        return [single]
    iocs = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            iocs.append(line)
    return iocs


def write_csv(results: list, path: str) -> None:
    fieldnames = [
        "ioc", "ioc_type", "verdict", "malicious_votes", "total_votes",
        "abuse_confidence_score", "country", "isp", "sources_checked",
        "tags", "notes",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "ioc": r.ioc,
                "ioc_type": r.ioc_type,
                "verdict": r.verdict(),
                "malicious_votes": r.malicious_votes,
                "total_votes": r.total_votes,
                "abuse_confidence_score": r.abuse_confidence_score,
                "country": r.country,
                "isp": r.isp,
                "sources_checked": "; ".join(r.sources_checked),
                "tags": "; ".join(r.tags),
                "notes": "; ".join(r.notes),
            })


def write_json(results: list, path: str) -> None:
    payload = []
    for r in results:
        payload.append({
            "ioc": r.ioc,
            "ioc_type": r.ioc_type,
            "verdict": r.verdict(),
            "malicious_votes": r.malicious_votes,
            "total_votes": r.total_votes,
            "abuse_confidence_score": r.abuse_confidence_score,
            "country": r.country,
            "isp": r.isp,
            "sources_checked": r.sources_checked,
            "tags": r.tags,
            "notes": r.notes,
            "raw": r.raw,
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def print_summary(results: list) -> None:
    print(f"\n{'IOC':<40} {'TYPE':<8} {'VERDICT':<12} {'NOTES'}")
    print("-" * 100)
    for r in results:
        notes = "; ".join(r.notes[:1]) if r.notes else ""
        print(f"{r.ioc:<40} {r.ioc_type:<8} {r.verdict():<12} {notes}")

    malicious = sum(1 for r in results if r.verdict() == "MALICIOUS")
    suspicious = sum(1 for r in results if r.verdict() == "SUSPICIOUS")
    print(
        f"\nChecked {len(results)} IOC(s): "
        f"{malicious} malicious, {suspicious} suspicious, "
        f"{len(results) - malicious - suspicious} clean/unknown."
    )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Enrich IOCs (IP, domain, URL, hash) against VirusTotal, "
                     "AbuseIPDB, and AlienVault OTX."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ioc", help="Single IOC to enrich")
    group.add_argument("--input", help="File with one IOC per line")

    parser.add_argument("--output", help="Path to write the report to")
    parser.add_argument(
        "--format", choices=["csv", "json"], default="csv",
        help="Output format when --output is used (default: csv)"
    )
    parser.add_argument(
        "--delay", type=float, default=REQUEST_DELAY_SECONDS,
        help=f"Seconds to wait between API calls per source "
             f"(default: {REQUEST_DELAY_SECONDS}, tuned for free-tier VT limits)"
    )
    args = parser.parse_args()

    if not any([VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY]):
        print(
            "Warning: no API keys found in environment (VT_API_KEY, "
            "ABUSEIPDB_API_KEY, OTX_API_KEY). All sources will be skipped.\n",
            file=sys.stderr,
        )

    iocs = load_iocs(args.input, args.ioc)
    if not iocs:
        print("No IOCs to process.", file=sys.stderr)
        sys.exit(1)

    results = []
    for i, ioc in enumerate(iocs):
        print(f"[{i + 1}/{len(iocs)}] Enriching {ioc} ...", file=sys.stderr)
        results.append(enrich_ioc(ioc, args.delay))

    print_summary(results)

    if args.output:
        if args.format == "csv":
            write_csv(results, args.output)
        else:
            write_json(results, args.output)
        print(f"\nReport written to {args.output}")


if __name__ == "__main__":
    main()
    