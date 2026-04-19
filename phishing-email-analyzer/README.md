# Phishing Email Analyzer

A powerful, open-source tool for analyzing phishing emails, extracting IoCs (Indicators of Compromise), and enriching results with threat intelligence.

![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Stars](https://img.shields.io/badge/Stars-Welcome-cyan)

## Features

### Core Analysis
- **Email Header Extraction** - Parse and analyze SPF, DKIM, DMARC authentication
- **URL Extraction** - Extract all URLs from email content with context
- **Domain Analysis** - Analyze domains for suspicious patterns (brand spoofing, numbers, keywords)
- **Email Address Extraction** - Extract email addresses
- **Hash Extraction** - Extract MD5, SHA1, SHA256 hashes
- **HTML Analysis** - Detect malicious scripts, iframes, obfuscated links, forms
- **Attachment Detection** - Identify suspicious file types (.exe, .scr, .zip, etc.)
- **Reply-To Analysis** - Detect mismatch between From and Reply-To addresses
- **Sender Domain Analysis** - Analyze TLD suspiciousness, domain length, keywords

### Advanced Detection
- **Urgency Keyword Detection** - Detect phishing urgency patterns
- **Financial Keyword Detection** - Detect payment/transfer related keywords
- **Suspicious Phishing Patterns** - Common phishing phrases and tactics
- **Bitcoin/Ethereum Address Detection** - Crypto wallet addresses
- **IBAN Detection** - Bank account numbers
- **Phone Number Extraction** - Contact numbers in emails

### Threat Intelligence
- **Abuse.ch Integration**
  - URLhaus: Malicious URL database
  - MalwareBazaar: Malware sample database
- **AlienVault OTX** - Open Threat Exchange (optional API key)
- **VirusTotal** - Industry-standard threat intel (API key required)

### Output Formats
- **CLI** - Colorized terminal output
- **JSON** - For automation and integration
- **Markdown** - Human-readable reports
- **CSV** - Spreadsheet-compatible export
- **HTML** - Professional visual reports

### File Support
- **.eml** - Standard email format
- **.msg** - Microsoft Outlook messages (requires `extract-msg` package)
- **.txt** - Plain text emails

### Interface
- **CLI** - Command-line interface
- **GUI** - Streamlit web interface

## Installation

### Prerequisites
- Python 3.10+
- Internet connection (for threat intel enrichment)

### Install

```bash
# Clone repository
git clone https://github.com/hypes999/phishing-email-analyzer.git
cd phishing-email-analyzer

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

### CLI Basic

```bash
# Analyze email file
python main.py -f email.eml

# Analyze from stdin
cat email.eml | python main.py -

# JSON output
python main.py -f email.eml --format json

# CSV output (for spreadsheets)
python main.py -f email.eml --format csv -o result.csv

# HTML report (professional visual)
python main.py -f email.eml --format html -o report.html

# Markdown report
python main.py -f email.eml --format markdown -o report.md

# Verbose output
python main.py -f email.eml -v

# Save to file
python main.py -f email.eml -o result.json --format json
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --file` | Email file to analyze | None |
| `-o, --output` | Output file | stdout |
| `--format` | Output format (json/cli/markdown) | cli |
| `--no-colors` | Disable colors | False |
| `-v, --verbose` | Detailed output | False |
| `--no-enrich` | Skip threat intelligence | False |
| `--gui` | Launch Streamlit GUI | False |
| `--virustotal-key` | VirusTotal API key | env variable |
| `--timeout` | API timeout (seconds) | 30 |

### GUI (Streamlit)

```bash
# Launch GUI
python main.py --gui
# Or
streamlit run gui/app.py
```

Then open http://localhost:8501 in your browser.

### Python API

```python
from analyzer import PhishingEmailAnalyzer, AnalysisConfig

config = AnalysisConfig(
    virustotal_api_key="your-api-key",  # Optional
    verbose=True
)

with PhishingEmailAnalyzer(config) as analyzer:
    result = analyzer.analyze_email(email_content)

    print(f"Threat Level: {result.summary['threat_level']}")
    print(f"URLs Found: {len(result.urls)}")
    print(f"Malicious URLs: {sum(1 for u in result.urls if u['is_malicious'])}")
```

## Configuration

### Environment Variables

```bash
# VirusTotal (get free key at virustotal.com)
export VIRUSTOTAL_API_KEY="your-api-key"

# AlienVault OTX (optional)
export ALIENVAULT_API_KEY="your-api-key"
```

### API Keys

| Service | Required | Free | Registration |
|---------|----------|-----|-------------|
| Abuse.ch | No | Yes | No registration needed |
| AlienVault OTX | No | Yes | Optional |
| VirusTotal | No | Yes (limited) | Required |

## Threat Intelligence

### Authentication Analysis

The tool analyzes email authentication headers:

- **SPF** (Sender Policy Framework) - Validates sender IP
- **DKIM** (DomainKeys Identified Mail) - Validates email signature
- **DMARC** (Domain-based Message Authentication) - Policy enforcement

### IoC Extraction

Extracts and analyzes:

- URLs (with shortened link detection)
- Domains (suspicious pattern analysis)
- Email addresses
- File hashes (MD5, SHA1, SHA256)

### Threat Level Calculation

Threat level is calculated based on:

| Factor | Weight |
|--------|-------|
| Malicious URL found | +3 |
| Malicious domain found | +3 |
| Malicious hash found | +3 |
| SPF/DKIM failure | +2 |
| Suspicious domain patterns | +1 |

| Score | Threat Level |
|-------|--------------|
| 0-2 | LOW |
| 3-5 | MEDIUM |
| 6+ | HIGH |

## Project Structure

```
phishing-email-analyzer/
├── main.py              # CLI entrypoint
├── analyzer.py          # Core analysis logic
├── requirements.txt
├── README.md
├── extractors/
│   ├── __init__.py
│   ├── headers.py       # Email header parsing
│   ├── urls.py        # URL/domain extraction
│   └── hashes.py      # Hash extraction
├── enrichers/
│   ├── __init__.py
│   ├── abusech.py     # Abuse.ch integration
│   ├── otx.py        # AlienVault OTX
│   └── virustotal.py  # VirusTotal
├── output/
│   ├── __init__.py
│   └── formatters.py  # JSON/CLI/Markdown
└── gui/
    ├── __init__.py
    └── app.py        # Streamlit GUI
```

## Examples

### Basic Analysis

```bash
$ python main.py -f test.eml

============================================================
  PHISHING EMAIL ANALYZER - RESULTS
============================================================
  Timestamp: 2026-04-18T12:00:00

----------------------------------------
  SUMMARY
----------------------------------------
  urls_total: 5
  urls_malicious: 1 [!]
  domains_total: 3
  domains_malicious: 0
  hashes_total: 1
  hashes_malicious: 0

----------------------------------------
  AUTHENTICATION
----------------------------------------
  SPF: ✓ PASS
  DKIM: ✓ PASS
  DMARC: ✓ PASS
```

### JSON Output

```bash
$ python main.py -f test.eml --format json | jq .summary

{
  "timestamp": "2026-04-18T12:00:00",
  "threat_level": "medium",
  "urls_total": 5,
  "urls_malicious": 1,
  ...
}
```

### CSV Output

```bash
$ python main.py -f test.eml --format csv -o result.csv

# Opens in Excel with columns:
# URL, Domain, Hash, Threat Level, SPF, DKIM, DMARC
```

### HTML Report

```bash
$ python main.py -f test.eml --format html -o report.html

# Generates professional visual report with:
# - Threat level badge
# - Summary cards
# - Authentication table
# - Color-coded URLs, domains, hashes
```

## Requirements

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28.0 | HTTP requests |
| termcolor | >=2.3.0 | CLI colors |
| streamlit | >=1.28.0 | GUI (optional) |
| extract-msg | >=0.43.0 | .msg file support (optional) |

### Optional: MSG Support

For Outlook .msg file support:

```bash
pip install extract-msg
```

## Roadmap

- [x] Email header parsing (SPF/DKIM/DMARC)
- [x] URL extraction with context
- [x] Domain analysis (brand spoofing, patterns)
- [x] Hash extraction (MD5, SHA1, SHA256)
- [x] Abuse.ch enrichment (URLhaus, MalwareBazaar)
- [x] CLI interface
- [x] JSON output
- [x] CSV output
- [x] HTML report
- [x] .msg file support
- [x] HTML analysis (scripts, iframes, forms)
- [x] Attachment detection
- [x] Reply-To mismatch detection
- [x] Sender domain analysis
- [x] Urgency/financial keyword detection
- [x] Crypto address detection (Bitcoin, Ethereum)
- [x] IBAN detection
- [ ] YAML configuration
- [ ] Integration with Wazuh
- [ ] Integration with TheHive

## Contributing

Contributions are welcome! Please open an issue or submit a PR.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Credits

- [Abuse.ch](https://www.abuse.ch/) - URLhaus, MalwareBazaar
- [AlienVault OTX](https://otx.alienvault.com/) - Open Threat Exchange
- [VirusTotal](https://www.virustotal.com/) - Threat intelligence
