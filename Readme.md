# IOC Enrichment Tool

A lightweight **Python-based Threat Intelligence and IOC Enrichment Tool** designed for practical **SOC Analyst and Blue Team workflows**.

The tool accepts Indicators of Compromise (IOCs), including **IP addresses, domains, URLs, and file hashes**, and enriches them using multiple free-tier threat intelligence platforms.

It can help a SOC analyst quickly determine whether an IOC has known malicious activity, identify its reputation across multiple sources, and generate structured reports for further investigation or incident documentation.

---

## 🛡️ Features

* 🔍 Automatic IOC classification
* 🌐 IPv4 address enrichment
* 🔗 Domain enrichment
* 🌎 URL enrichment
* 🔐 MD5, SHA-1, and SHA-256 hash analysis
* 🦠 VirusTotal integration
* 🚨 AbuseIPDB integration
* 👽 AlienVault OTX integration
* 📊 Combined threat scoring
* ⚠️ `MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN` verdicts
* 📁 Batch IOC processing
* 📄 CSV report generation
* 🧾 JSON report generation
* ⏱️ Configurable API request delay
* 🔑 Environment-variable based API key management
* 🧩 Modular source architecture
* 💻 Command-line interface
* 🎯 Designed for SOC investigation workflows

---

## 🔎 Supported IOC Types

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

# 🏗️ Project Structure

```text
IOC/
│
├── .gitignore
├── iocEnrich.py
├── Readme.md
├── report.csv
├── Requirements.txt
└── sample_iocs.txt
```

## 📂 File Description

| File               | Description                                                                         |
| ------------------ | ----------------------------------------------------------------------------------- |
| `.gitignore`       | Prevents sensitive or unnecessary files from being committed to Git.                |
| `iocEnrich.py`     | Main Python application for IOC classification, enrichment, scoring, and reporting. |
| `Readme.md`        | Project documentation and usage instructions.                                       |
| `report.csv`       | Generated IOC enrichment report.                                                    |
| `Requirements.txt` | Python dependencies required by the project.                                        |
| `sample_iocs.txt`  | Sample IOC dataset for testing batch enrichment.                                    |

---
## 🖥️ Screenshots
### 📄 PowerShell Output
<img width="1104" height="402" alt="Screenshot 2026-08-22 170508" src="https://github.com/user-attachments/assets/a07921ac-8fa7-4373-ba03-f8b49a103392" />

---
# ⚙️ Architecture

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
                  ┌────────────────┼────────────────┐
                  ▼                ▼                ▼
             MALICIOUS        SUSPICIOUS         CLEAN
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

If your system uses `python3`:

```bash
pip3 install -r Requirements.txt
```

---

# 🔑 API Configuration

The tool uses environment variables for API credentials.

This is safer than hard-coding API keys directly into the Python source code.

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

> **Important:** Never commit API keys to GitHub.

---

# 🔐 Obtain API Keys

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

## Single IOC

Analyze a single IP address:

```bash
python iocEnrich.py --ioc 8.8.8.8
```

Analyze a domain:

```bash
python iocEnrich.py --ioc example.com
```

Analyze a URL:

```bash
python iocEnrich.py --ioc https://example.com/login
```

Analyze a file hash:

```bash
python iocEnrich.py --ioc d41d8cd98f00b204e9800998ecf8427e
```

---

# 📁 Batch IOC Analysis

The tool supports processing multiple IOCs from a text file.

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

This is useful when investigating:

* Phishing emails
* SOC alerts
* Malware reports
* Firewall logs
* Proxy logs
* EDR alerts
* Suspicious DNS activity
* Incident response cases

---

# 📊 CSV Reporting

Export enrichment results to CSV:

```bash
python iocEnrich.py --input sample_iocs.txt --output report.csv
```

The generated `report.csv` can be used for:

* Incident tickets
* SOC documentation
* Threat hunting
* IOC tracking
* Security reports
* Further data analysis

---

# 🧾 JSON Reporting

Generate a structured JSON report:

```bash
python iocEnrich.py \
    --input sample_iocs.txt \
    --output report.json \
    --format json
```

JSON output can be useful for:

* Security automation
* SOAR integrations
* Custom dashboards
* SIEM pipelines
* API-based workflows
* Further Python processing

---

# ⏱️ API Request Delay

Threat intelligence APIs enforce rate limits.

The tool supports a configurable delay between requests.

Example:

```bash
python iocEnrich.py --input sample_iocs.txt --delay 16
```

You can specify a shorter or longer delay:

```bash
python iocEnrich.py --input sample_iocs.txt --delay 5
```

The default delay is designed to reduce the chance of exceeding free-tier API limits.

> Lowering the delay does not increase an API provider's rate limit and may cause rate-limit errors.

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

---

## 2. Source Selection

After classification, the tool determines which intelligence sources support the IOC type.

For example:

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

---

## 3. Threat Intelligence Enrichment

The tool queries the configured providers and collects available reputation and detection information.

The collected data is normalized into a common result structure.

This makes it easier to compare information from multiple intelligence providers.

---

# ⚠️ Risk Scoring

The tool generates one of four overall verdicts:

### 🔴 MALICIOUS

Strong evidence indicates that the IOC is associated with malicious activity.

Possible indicators include:

* Multiple security engines detecting the IOC
* High abuse confidence
* Strong malicious reputation
* Multiple threat-intelligence reports

### 🟠 SUSPICIOUS

The IOC has some indicators of potentially malicious activity, but the available evidence may not be conclusive.

### 🟢 CLEAN

Available intelligence sources do not currently report significant malicious activity.

### ⚪ UNKNOWN

There is insufficient intelligence to make a reliable determination.

> **Important:** `CLEAN` or `UNKNOWN` does not guarantee that an IOC is safe. Threat intelligence databases may have incomplete or outdated coverage.

---

# 🧪 Example Investigation Workflow

A SOC analyst receives a phishing alert containing:

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
python iocEnrich.py --input sample_iocs.txt --output report.json --format json
```

The tool performs:

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

The resulting report can then be used by the analyst to decide whether additional investigation or containment is required.

---

# 🧩 Source Function Architecture

The project uses a modular source-integration architecture.

The source functions follow a common interface:

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

This makes it easier to add additional threat intelligence providers.

---

# 🔌 Extending the Tool

Additional sources can be added using the same architecture.

Potential future integrations include:

* **Shodan**
* **GreyNoise**
* **URLhaus**
* **ThreatFox**
* **MalwareBazaar**
* **CIRCL**
* **SecurityTrails**

A new provider can be implemented as a source function and added to `SOURCE_FUNCS`.

Example:

```python
def query_new_source(ioc, ioc_type, result):
    # API request
    # Process response
    # Update result
    pass
```

Then register it with the source configuration.

---

# 🛡️ Security Best Practices

### Never hard-code API keys

Avoid:

```python
VT_API_KEY = "123456789abcdef"
```

Use environment variables instead.

### Protect sensitive information

Do not upload:

* API keys
* Private credentials
* Internal IP information
* Confidential URLs
* Sensitive incident data

to public repositories.

### Use `.gitignore`

The project includes `.gitignore` to prevent sensitive files from accidentally being committed.

Example:

```text
.env
*.key
*.pem
__pycache__/
*.pyc
```

---

# 📈 SOC Analyst Use Cases

This project can be used during several SOC activities.

### Phishing Investigation

Extract:

* Sender IP
* URLs
* Domains
* File hashes

and enrich them using the tool.

### Malware Investigation

Submit:

* MD5
* SHA-1
* SHA-256

hashes to identify known malware detections.

### Network Investigation

Analyze suspicious:

* Source IPs
* Destination IPs
* Domains

from firewall, proxy, DNS, or network monitoring alerts.

### Threat Hunting

Process a list of suspicious indicators collected from:

* SIEM alerts
* EDR alerts
* Threat reports
* Firewall logs
* DNS logs
* Email security systems

---

# 🗂️ Reporting

The tool supports multiple reporting formats:

```text
IOC
 │
 ├── Console Output
 │
 ├── CSV Report
 │
 └── JSON Report
```

### CSV

Best suited for:

* Analyst review
* Excel/LibreOffice
* Ticket attachments
* IOC tracking

### JSON

Best suited for:

* Automation
* APIs
* SOAR
* SIEM integration
* Python-based processing

---

# 🧰 Technologies Used

| Technology             | Purpose                          |
| ---------------------- | -------------------------------- |
| **Python**             | Core development language        |
| **Requests**           | API communication                |
| **Regex**              | IOC classification               |
| **JSON**               | Structured reporting/API data    |
| **CSV**                | Report generation                |
| **VirusTotal API**     | Multi-engine threat intelligence |
| **AbuseIPDB API**      | IP reputation analysis           |
| **AlienVault OTX API** | Threat intelligence and IOC data |

---

# 📦 Requirements

The project dependencies are listed in:

```text
Requirements.txt
```

Install them with:

```bash
pip install -r Requirements.txt
```

---

# 🎯 Project Objectives

The main objectives of this project are to:

1. Automate IOC classification.
2. Reduce manual threat-intelligence lookups.
3. Combine intelligence from multiple sources.
4. Provide a simple risk-oriented verdict.
5. Support batch IOC analysis.
6. Generate structured investigation reports.
7. Demonstrate practical SOC automation skills.
8. Create an extensible foundation for additional threat-intelligence integrations.

---

# 🚀 Future Enhancements

Planned improvements could include:

* [ ] Shodan integration
* [ ] GreyNoise integration
* [ ] URLhaus integration
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
* [ ] Configurable provider profiles

---

# ⚠️ Disclaimer

This project is intended for **educational, defensive security, threat-intelligence, SOC analysis, and authorized security testing purposes**.

Threat intelligence results should be treated as investigative evidence rather than absolute truth. Different providers may have different coverage, detection methodologies, and update frequencies.

Always follow the terms of service and API usage policies of the external threat-intelligence providers.

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

**IOC Enrichment Tool** is a practical Python-based SOC utility that automates the process of investigating Indicators of Compromise.

Instead of manually checking every IP address, domain, URL, or file hash across multiple threat-intelligence platforms, analysts can provide the indicators to the tool and receive consolidated enrichment and risk information.

The project demonstrates how **Python automation + threat intelligence APIs + IOC classification + risk scoring + structured reporting** can be combined into a practical cybersecurity workflow.

---

## 📌 Project Structure

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

