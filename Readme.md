# 🔍 IOC Enrichment Tool

A lightweight **Python-based Threat Intelligence and IOC Enrichment Tool** designed for practical **SOC Analyst and Blue Team workflows**.

The tool accepts **Indicators of Compromise (IOCs)** such as IP addresses, domains, URLs, and file hashes, then enriches them using multiple free-tier threat-intelligence platforms.

It helps SOC analysts quickly investigate suspicious indicators, compare reputation data from multiple sources, calculate an overall risk verdict, and generate structured reports.

---

## 🛡️ Key Features

* 🔍 Automatic IOC classification
* 🌐 IPv4 address enrichment
* 🔗 Domain enrichment
* 🌎 URL enrichment
* 🔐 MD5, SHA-1, and SHA-256 hash analysis
* 🦠 VirusTotal integration
* 📊 Combined threat scoring
* 📁 Batch IOC processing
* 📄 CSV report generation
* 🧾 JSON report generation
* ⏱️ Configurable API request delay
* 🔑 Environment-variable based API key management
* 💻 Command-line interface
* 🎯 Designed for SOC investigation workflows

---

## 🧩 Supported IOC Types

| IOC Type   | Example                                    | Supported Sources          |
| ---------- | ------------------------------------------ | -------------------------- |
| IP Address | `8.8.8.8`                                  | VirusTotal, AbuseIPDB, OTX |
| Domain     | `example.com`                              | VirusTotal, OTX            |
| URL        | `https://example.com/login`                | VirusTotal, OTX            |
| MD5        | `d41d8cd98f00b204e9800998ecf8427e`         | VirusTotal, OTX            |
| SHA-1      | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | VirusTotal, OTX            |
| SHA-256    | `e3b0c44298fc1c149afbf4c8996fb924...`      | VirusTotal, OTX            |

---

# 🧠 Threat Intelligence Sources

| Source             |  IP | Domain | URL | Hash | Free Tier |
| ------------------ | :-: | :----: | :-: | :--: | :-------: |
| **VirusTotal**     |  ✅  |    ✅   |  ✅  |   ✅  |     ✅     |
| **AbuseIPDB**      |  ✅  |    ❌   |  ❌  |   ❌  |     ✅     |
| **AlienVault OTX** |  ✅  |    ✅   |  ✅  |   ✅  |     ✅     |

Each source is optional.

If an API key is not configured, the tool automatically skips that provider and continues using the available sources.

---

# 🏗️ Architecture

```text
                         ┌───────────────────┐
                         │     IOC Input     │
                         │                   │
                         │ IP / Domain / URL │
                         │      / Hash       │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ IOC Classification│
                         │                   │
                         │ Regex + Stdlib    │
                         └─────────┬─────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
              ▼                    ▼                    ▼
       ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
       │ VirusTotal  │      │ AbuseIPDB   │      │ AlienVault  │
       │     API     │      │     API     │      │   OTX API   │
       └──────┬──────┘      └──────┬──────┘      └──────┬──────┘
              │                    │                    │
              └────────────────────┼────────────────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ Result Collection│
                         │                   │
                         │ Detection Ratios  │
                         │ Reputation Data   │
                         │ Confidence Scores │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │   Risk Scoring    │
                         └─────────┬─────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
               MALICIOUS      SUSPICIOUS        CLEAN
                    │
                    ▼
                 UNKNOWN
                    │
                    ▼
                         ┌───────────────────┐
                         │     Reporting     │
                         │                   │
                         │ Console / CSV /   │
                         │       JSON        │
                         └───────────────────┘
```

---

# 🚀 Installation

## 1. Clone the Repository

```bash
git clone https://github.com/your-username/ioc-enrichment-tool.git
cd ioc-enrichment-tool
```

## 2. Install Dependencies

```bash
pip install -r Requirements.txt
```

For systems using `python3`:

```bash
pip3 install -r Requirements.txt
```

---

# 🔑 API Configuration

The tool uses environment variables for API credentials instead of storing API keys directly in the source code.

## Linux / macOS

```bash
export VT_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export OTX_API_KEY="your_otx_key"
```

## Windows PowerShell

```powershell
$env:VT_API_KEY="your_virustotal_key"
$env:ABUSEIPDB_API_KEY="your_abuseipdb_key"
$env:OTX_API_KEY="your_otx_key"
```

> ⚠️ **Important:** Never commit API keys to GitHub.

---

# 🔐 Obtaining API Keys

### VirusTotal

Create an account and obtain your API key from the VirusTotal platform.

https://www.virustotal.com/gui/join-us

### AbuseIPDB

Register for an account and obtain your API key.

https://www.abuseipdb.com/register

### AlienVault OTX

Create an account and obtain an OTX API key.

https://otx.alienvault.com/

---

# 💻 Usage

## Analyze a Single IOC

### IP Address

```bash
python iocEnrich.py --ioc 8.8.8.8
```

### Domain

```bash
python iocEnrich.py --ioc example.com
```

### URL

```bash
python iocEnrich.py --ioc https://example.com/login
```

### File Hash

```bash
python iocEnrich.py --ioc d41d8cd98f00b204e9800998ecf8427e
```

---

# 📁 Batch IOC Analysis

The tool can process multiple IOCs from a text file.

Example `sample_iocs.txt`:

```text
8.8.8.8
example.com
https://example.com/login
d41d8cd98f00b204e9800998ecf8427e

# Comments are ignored
```

Run:

```bash
python iocEnrich.py --input sample_iocs.txt
```

Batch analysis is useful when investigating:

* Phishing emails
* SOC alerts
* Malware reports
* Firewall logs
* Proxy logs
* EDR alerts
* Suspicious DNS activity
* Incident response cases

---

# 📊 Reporting

## CSV Report

```bash
python iocEnrich.py --input sample_iocs.txt --output report.csv
```

CSV reports are useful for:

* Analyst review
* Excel/LibreOffice
* Incident tickets
* SOC documentation
* IOC tracking
* Threat hunting
* Security reports

## JSON Report

```bash
python iocEnrich.py \
    --input sample_iocs.txt \
    --output report.json \
    --format json
```

JSON output can be used for:

* Security automation
* SOAR integrations
* Custom dashboards
* SIEM pipelines
* API-based workflows
* Further Python processing

---

# ⚠️ Risk Scoring

The tool generates four overall verdicts.

### 🔴 MALICIOUS

Strong evidence indicates that the IOC is associated with malicious activity.

Possible indicators include:

* Multiple security engines detecting the IOC
* High abuse confidence
* Strong malicious reputation
* Multiple threat-intelligence reports

### 🟠 SUSPICIOUS

The IOC contains indicators of potentially malicious activity, but the available evidence may not be conclusive.

### 🟢 CLEAN

Available intelligence sources do not currently report significant malicious activity.

### ⚪ UNKNOWN

There is insufficient intelligence to make a reliable determination.

> **Important:** `CLEAN` or `UNKNOWN` does not guarantee that an IOC is safe. Threat-intelligence databases may have incomplete or outdated coverage.

---

# 🔬 How It Works

## 1. IOC Classification

Each input is automatically classified as:

```text
IP Address
Domain
URL
MD5
SHA-1
SHA-256
```

Classification is performed using regular expressions and Python standard-library validation.

## 2. Source Selection

After classification, the tool determines which intelligence sources support the IOC type.

```text
IP Address
 ├── VirusTotal
 ├── AbuseIPDB
 └── AlienVault OTX

Domain
 ├── VirusTotal
 └── AlienVault OTX

URL
 ├── VirusTotal
 └── AlienVault OTX

File Hash
 ├── VirusTotal
 └── AlienVault OTX
```

This prevents unnecessary API requests.

## 3. Threat Intelligence Enrichment

The tool queries the configured providers and collects available reputation and detection information.

The collected data is normalized into a common result structure, making information from different providers easier to compare.

## 4. Risk Verdict

The collected intelligence is analyzed to produce one of four verdicts:

```text
MALICIOUS
SUSPICIOUS
CLEAN
UNKNOWN
```

## 5. Reporting

Results can be displayed through:

```text
Console
   │
   ├── CSV
   │
   └── JSON
```

---

# 🧪 Example SOC Investigation Workflow

Suppose a SOC analyst receives a phishing alert containing:

```text
185.XX.XX.XX
malicious-example.com
https://malicious-example.com/login
```

The indicators can be added to:

```text
sample_iocs.txt
```

Then run:

```bash
python iocEnrich.py \
    --input sample_iocs.txt \
    --output report.json \
    --format json
```

The investigation workflow becomes:

```text
Phishing Alert
      │
      ▼
Extract IOCs
      │
      ▼
IOC Classification
      │
      ▼
Threat Intelligence Lookup
      │
      ▼
Detection & Reputation Analysis
      │
      ▼
Risk Verdict
      │
      ▼
SOC Investigation
```

The resulting report can help the analyst determine whether additional investigation or containment is required.

---

# 🧩 Source Function Architecture

The project uses a modular source-integration architecture.

Source functions follow a common interface:

```python
query_source(ioc, ioc_type, result)
```

Current integrations include:

```python
query_virustotal(ioc, ioc_type, result)
query_abuseipdb(ioc, ioc_type, result)
query_otx(ioc, ioc_type, result)
```

The integrations are registered through:

```python
SOURCE_FUNCS
```

This makes it easier to add additional threat-intelligence providers.

---

# 🔌 Extending the Tool

Additional threat-intelligence providers can be added using the same architecture.

Potential future integrations include:

* **Shodan**
* **GreyNoise**
* **URLhaus**
* **ThreatFox**
* **MalwareBazaar**
* **CIRCL**
* **SecurityTrails**

Example:

```python
def query_new_source(ioc, ioc_type, result):
    # API request
    # Process response
    # Update result
    pass
```

The new provider can then be registered through the source configuration.

---

# ⏱️ API Request Delay

Threat-intelligence APIs enforce rate limits.

The tool supports a configurable delay between requests.

Example:

```bash
python iocEnrich.py --input sample_iocs.txt --delay 16
```

Or:

```bash
python iocEnrich.py --input sample_iocs.txt --delay 5
```

The default delay is designed to reduce the chance of exceeding free-tier API limits.

> ⚠️ Lowering the delay does not increase an API provider's rate limit and may cause rate-limit errors.

---

# 🛡️ Security Best Practices

## Never Hard-Code API Keys

Avoid:

```python
VT_API_KEY = "123456789abcdef"
```

Use environment variables instead.

## Protect Sensitive Information

Do not upload the following to public repositories:

* API keys
* Private credentials
* Internal IP information
* Confidential URLs
* Sensitive incident data

## Use `.gitignore`

Example:

```text
.env
*.key
*.pem
__pycache__/
*.pyc
```

---

# 📸 Screenshots

## PowerShell Output

<img width="1104" height="402" alt="IOC Enrichment Tool PowerShell Output" src="https://github.com/user-attachments/assets/a07921ac-8fa7-4373-ba03-f8b49a103392" />

---

# 🗂️ Project Structure

```text
IOC/
│
├── .gitignore
│
├── iocEnrich.py
│   └── Main IOC enrichment engine
│
├── Readme.md
│   └── Project documentation
│
├── report.csv
│   └── Generated enrichment report
│
├── Requirements.txt
│   └── Python dependencies
│
└── sample_iocs.txt
    └── Sample IOC input dataset
```

---

# 🧰 Technologies Used

| Technology             | Purpose                           |
| ---------------------- | --------------------------------- |
| **Python**             | Core development language         |
| **Requests**           | API communication                 |
| **Regex**              | IOC classification                |
| **JSON**               | Structured reporting and API data |
| **CSV**                | Report generation                 |
| **VirusTotal API**     | Multi-engine threat intelligence  |
| **AbuseIPDB API**      | IP reputation analysis            |
| **AlienVault OTX API** | Threat intelligence and IOC data  |

---

# 🎯 Project Objectives

The main objectives are to:

1. Automate IOC classification.
2. Reduce manual threat-intelligence lookups.
3. Combine intelligence from multiple sources.
4. Provide a simple risk-oriented verdict.
5. Support batch IOC analysis.
6. Generate structured investigation reports.
7. Demonstrate practical SOC automation skills.
8. Create an extensible foundation for additional threat-intelligence integrations.

---

# 📈 SOC Analyst Use Cases

## 🔎 Phishing Investigation

Extract and enrich:

* Sender IP
* URLs
* Domains
* File hashes

## 🦠 Malware Investigation

Submit:

* MD5
* SHA-1
* SHA-256

hashes to identify known malware detections.

## 🌐 Network Investigation

Analyze suspicious:

* Source IPs
* Destination IPs
* Domains

from firewall, proxy, DNS, or network-monitoring alerts.

## 🎯 Threat Hunting

Process suspicious indicators collected from:

* SIEM alerts
* EDR alerts
* Threat reports
* Firewall logs
* DNS logs
* Email security systems

---

# 🚀 Future Enhancements

* [ ] Shodan integration
* [ ] ThreatFox integration
* [ ] Automatic IOC extraction from emails
* [ ] SIEM integration
* [ ] REST API
* [ ] Web dashboard
* [ ] IOC caching
* [ ] Improved scoring engine
* [ ] MITRE ATT&CK mapping
* [ ] Threat-intelligence confidence scoring
* [ ] Automated PDF reporting
* [ ] Docker support
* [ ] Unit and integration tests
* [ ] Async API requests

---

# 📦 Requirements

Project dependencies are listed in:

```text
Requirements.txt
```

Install them using:

```bash
pip install -r Requirements.txt
```

---

# 👨‍💻 Skills Demonstrated

This project demonstrates practical knowledge of:

* SOC Operations
* Blue Team Security
* Threat Intelligence
* IOC Analysis
* Incident Response
* Python Automation
* REST API Integration
* API Authentication
* Risk Scoring
* Log/Alert Investigation
* Security Reporting
* Batch Processing
* JSON & CSV Data Processing
* Secure Credential Handling
* Modular Software Architecture

---

# ⭐ Project Summary

**IOC Enrichment Tool** is a practical Python-based SOC utility that automates the investigation of Indicators of Compromise.

Instead of manually checking every IP address, domain, URL, or file hash across multiple threat-intelligence platforms, analysts can provide indicators to the tool and receive consolidated enrichment and risk information.

The project demonstrates how:

```text
Python Automation
       +
Threat Intelligence APIs
       +
IOC Classification
       +
Risk Scoring
       +
Structured Reporting
       ↓
Practical SOC Investigation Workflow
```

---

# ⚠️ Disclaimer

This project is intended for **educational, defensive security, threat-intelligence, SOC analysis, and authorized security testing purposes**.

Threat-intelligence results should be treated as investigative evidence rather than absolute truth. Different providers may have different coverage, detection methodologies, and update frequencies.

Always follow the terms of service and API usage policies of the external threat-intelligence providers.
