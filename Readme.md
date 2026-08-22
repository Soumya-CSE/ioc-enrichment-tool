# IOC Enrichment Tool

A command-line tool for enriching Indicators of Compromise (IPs, domains,
URLs, and file hashes) against multiple free-tier threat intelligence
sources. Built as a practical SOC analyst tool — feed it IOCs from an alert
or a phishing email, and it tells you whether they're known-bad.

## Sources

| Source          | Covers                  | Free tier?              |
|-----------------|--------------------------|--------------------------|
| VirusTotal      | IP, domain, URL, hash    | Yes (4 req/min limit)   |
| AbuseIPDB       | IP only                  | Yes (1000 req/day)      |
| AlienVault OTX  | IP, domain, URL, hash    | Yes                      |

Each source is optional — the tool skips any source whose API key isn't
set, so it still runs (just with less coverage).

## Setup

```bash
pip install -r requirements.txt

export VT_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export OTX_API_KEY="your_otx_key"
```

Get free API keys at:
- https://www.virustotal.com/gui/join-us
- https://www.abuseipdb.com/register
- https://otx.alienvault.com/

## Usage

**Single IOC:**
```bash
python3 ioc_enrich.py --ioc 8.8.8.8
```

**Batch from a file** (one IOC per line, `#` for comments):
```bash
python3 ioc_enrich.py --input sample_iocs.txt --output report.csv
```

**JSON output:**
```bash
python3 ioc_enrich.py --input sample_iocs.txt --output report.json --format json
```

**Adjust the delay between API calls** (default 16s, tuned for VirusTotal's
free-tier rate limit of 4 requests/minute):
```bash
python3 ioc_enrich.py --input sample_iocs.txt --delay 5
```

## How it works

1. **Classification** — each IOC is auto-detected as an IP, domain, URL, or
   hash (MD5/SHA1/SHA256) using regex/stdlib checks.
2. **Enrichment** — the IOC is queried against every configured source
   relevant to its type.
3. **Scoring** — a verdict (`MALICIOUS` / `SUSPICIOUS` / `CLEAN` /
   `UNKNOWN`) is derived from combined detection ratios and AbuseIPDB's
   confidence score.
4. **Reporting** — results print to the console as a summary table, and
   optionally export to CSV or JSON for further triage or ticketing.

## Extending it

The source functions (`query_virustotal`, `query_abuseipdb`, `query_otx`)
all follow the same signature — `(ioc, ioc_type, result)` — so adding a new
source (e.g. Shodan, GreyNoise, URLhaus) means writing one function and
adding it to `SOURCE_FUNCS`.

## Notes

- This tool is read-only threat intel lookup — it does not block, quarantine,
  or take any action on IOCs. It's meant to speed up triage, not replace it.
- Respect each provider's terms of service and rate limits.
