# IOC Enrichment Tool

A lightweight command-line **Threat Intelligence and IOC enrichment tool** designed for practical SOC analyst workflows. It accepts Indicators of Compromise (IOCs) such as **IP addresses, domains, URLs, and file hashes**, then enriches them using multiple free-tier threat intelligence platforms to determine whether an indicator is potentially malicious, suspicious, clean, or unknown.

## Threat Intelligence Sources

| Source             | Supported IOCs        | Free Tier                |
| ------------------ | --------------------- | ------------------------ |
| **VirusTotal**     | IP, Domain, URL, Hash | Yes — rate limited       |
| **AbuseIPDB**      | IP addresses          | Yes — 1,000 requests/day |
| **AlienVault OTX** | IP, Domain, URL, Hash | Yes                      |

Each intelligence source is optional. If an API key is not configured, the tool automatically skips that source and continues with the available integrations.

## Installation & Configuration

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Configure the API keys as environment variables:

```bash
export VT_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export OTX_API_KEY="your_otx_key"
```

### Windows PowerShell

```powershell
$env:VT_API_KEY="your_virustotal_key"
$env:ABUSEIPDB_API_KEY="your_abuseipdb_key"
$env:OTX_API_KEY="your_otx_key"
```

### API Key Registration

* VirusTotal: https://www.virustotal.com/gui/join-us
* AbuseIPDB: https://www.abuseipdb.com/register
* AlienVault OTX: https://otx.alienvault.com/

## Usage

### 1. Enrich a Single IOC

```bash
python3 ioc_enrich.py --ioc 8.8.8.8
```

Example inputs:

```bash
python3 ioc_enrich.py --ioc 8.8.8.8
python3 ioc_enrich.py --ioc example.com
python3 ioc_enrich.py --ioc https://example.com/login
python3 ioc_enrich.py --ioc d41d8cd98f00b204e9800998ecf8427e
```

### 2. Batch IOC Enrichment

Create a file containing one IOC per line:

```text
8.8.8.8
example.com
https://example.com/login
d41d8cd98f00b204e9800998ecf8427e

# Comments are ignored
```

Run:

```bash
python3 ioc_enrich.py --input sample_iocs.txt
```

### 3. Export Results to CSV

```bash
python3 ioc_enrich.py --input sample_iocs.txt --output report.csv
```

CSV reports can be useful for **SOC documentation, incident tickets, threat-hunting records, and further analysis**.

### 4. Export Results to JSON

```bash
python3 ioc_enrich.py \
    --input sample_iocs.txt \
    --output report.json \
    --format json
```

JSON output is useful for integrating the tool with other security automation or analysis workflows.

### 5. Configure API Request Delay

VirusTotal's free API tier has a request-rate limitation. The tool therefore supports a configurable delay between requests.

Default:

```bash
python3 ioc_enrich.py --input sample_iocs.txt --delay 16
```

Custom delay:

```bash
python3 ioc_enrich.py --input sample_iocs.txt --delay 5
```

> **Note:** Lowering the delay does not increase the provider's rate limit and may result in rate-limit errors.

## How the Tool Works

The enrichment pipeline follows a simple SOC-oriented workflow:

```text
IOC Input
   │
   ▼
IOC Classification
   │
   ├── IP Address
   ├── Domain
   ├── URL
   └── File Hash
   │
   ▼
Threat Intelligence Enrichment
   │
   ├── VirusTotal
   ├── AbuseIPDB
   └── AlienVault OTX
   │
   ▼
Result Normalization
   │
   ▼
Risk Scoring
   │
   ├── MALICIOUS
   ├── SUSPICIOUS
   ├── CLEAN
   └── UNKNOWN
   │
   ▼
SOC Report
   │
   ├── Console
   ├── CSV
   └── JSON
```

### 1. IOC Classification

The tool automatically identifies the IOC type using standard-library validation and pattern matching.

Supported types include:

* IPv4 addresses
* Domains
* URLs
* MD5 hashes
* SHA-1 hashes
* SHA-256 hashes

### 2. Threat Intelligence Enrichment

The classified IOC is sent only to the threat intelligence sources that support that IOC type.

For example:

```text
IP Address
 ├── VirusTotal
 ├── AbuseIPDB
 └── AlienVault OTX

Domain
 ├── VirusTotal
 └── AlienVault OTX
```

This avoids unnecessary API requests.

### 3. Risk Scoring

Results from multiple intelligence providers are normalized and combined to produce an overall verdict:

* **MALICIOUS** — strong evidence that the IOC is associated with malicious activity.
* **SUSPICIOUS** — indicators of potentially malicious or abnormal activity are present.
* **CLEAN** — available intelligence sources do not report significant malicious activity.
* **UNKNOWN** — insufficient intelligence is available to determine a reliable verdict.

For IP addresses, the scoring can also incorporate **AbuseIPDB's confidence score**.

> A `CLEAN` or `UNKNOWN` result should not be interpreted as proof that an IOC is safe. Threat intelligence coverage varies between providers.

## Source Integration

The source integrations use a consistent function interface:

```python
query_source(ioc, ioc_type, result)
```

Current integrations include:

```python
query_virustotal(ioc, ioc_type, result)
query_abuseipdb(ioc, ioc_type, result)
query_otx(ioc, ioc_type, result)
```

They are registered through:

```python
SOURCE_FUNCS
```

This modular structure makes the project easy to extend.

## Extending the Tool

Additional threat intelligence providers can be integrated without redesigning the entire application.

Potential future integrations include:

* Shodan
* GreyNoise
* URLhaus
* ThreatFox
* MalwareBazaar
* CIRCL
* SecurityTrails

A new provider should follow the existing source function interface and then be registered in `SOURCE_FUNCS`.

## Example SOC Workflow

A SOC analyst receives a phishing alert containing:

```text
185.XX.XX.XX
malicious-example.com
https://malicious-example.com/login
```

The analyst can place these indicators into:

```text
sample_iocs.txt
```

and run:

```bash
python3 ioc_enrich.py --input sample_iocs.txt --output report.json --format json
```

The tool then:

1. Classifies each IOC.
2. Queries the configured threat intelligence providers.
3. Collects detection and reputation data.
4. Calculates an overall verdict.
5. Generates a structured report.
6. Provides evidence that can support further SOC investigation.

## Security Considerations

* Never hard-code API keys in the source code.
* Store credentials using environment variables or a secure secrets manager.
* Do not commit API keys to GitHub.
* Respect each provider's API rate limits and terms of service.
* Treat threat-intelligence verdicts as investigation signals rather than absolute proof.
* Avoid submitting sensitive internal indicators to external services unless organizational policy permits it.

## Project Highlights

**IOC Enrichment Tool** demonstrates practical SOC and threat-intelligence concepts including:

* IOC classification
* Threat intelligence APIs
* API integration
* IP/domain/URL/hash analysis
* Reputation analysis
* Risk scoring
* Rate-limit handling
* Batch processing
* CSV/JSON reporting
* Security automation
* Modular Python architecture

This project can be used as a practical **SOC Analyst portfolio project** demonstrating how raw indicators from alerts or phishing investigations can be enriched and prioritized for further analysis.


- This tool is read-only threat intel lookup — it does not block, quarantine,
  or take any action on IOCs. It's meant to speed up triage, not replace it.
- Respect each provider's terms of service and rate limits.
