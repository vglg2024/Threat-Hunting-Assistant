# 🛡 Threat Hunting Assistant (THA)

> **AI-augmented threat hunting. eCTHP-aligned. SOC-ready.**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![eCTHP Aligned](https://img.shields.io/badge/eCTHP-Aligned-38BDF8)](https://elearnsecurity.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

THA is a modular, analyst-focused platform that guides defenders through the complete threat hunting lifecycle — from raw evidence to structured hypotheses, MITRE ATT&CK mapping, and polished SOC-ready reports. Built around the eCTHP methodology, it replaces fragmented, manual workflows with a unified, repeatable system.

---

## 🎯 Purpose

THA executes the full eCTHP hunt cycle:

| Step | Description | THA Module |
|------|-------------|------------|
| 1 | Planning & Scoping | `tha_core.py` — Session management |
| 2 | Evidence Collection | `tha_pcap.py` + `tha_logs.py` |
| 3 | IOC & Threat Intel | `tha_ioc.py` — Correlation engine |
| 4 | Hypothesis Development | `tha_hypothesis.py` — MITRE mapping |
| 5 | Validation | GUI analyst notes + evidence tables |
| 6 | Documentation | `tha_report.py` — HTML/PDF output |

---

## 🧩 Key Capabilities

### 🌐 PCAP Analysis Engine
- Flow extraction (src → dst, bytes, ports)
- DGA detection via subdomain entropy analysis
- C2 beaconing pattern identification
- ICMP tunneling payload inspection
- Non-standard port flagging (T1571)
- Large transfer / exfiltration detection (T1041)

### 📋 Multi-Format Log Triage
- **Windows**: JSON events, CSV exports, Sysmon XML
- **Linux**: Syslog, auth.log, cron anomalies
- LOLBin execution detection (certutil, mshta, rundll32, etc.)
- Suspicious command-line pattern matching (20+ detection rules)
- Brute force / failed login aggregation
- Windows Security Event ID coverage (4624, 4648, 4698, 7045, 1102, and more)

### 🔍 IOC Correlation Engine
- Load threat intel from CSV or JSON (MISP-compatible)
- Artifact extraction: IPs, domains, hashes, URLs, CVEs, emails
- Private IP & benign domain filtering
- Automatic cross-reference and severity tagging

### 💡 Hypothesis Generator
- Auto-generates structured, eCTHP-aligned hypotheses per finding
- Maps all evidence to MITRE ATT&CK techniques and tactics
- Synthesizes a plain-English adversary kill-chain narrative
- Severity-ranked hypothesis output (Critical → Low)

### 📄 SOC-Ready Report Builder
- Dark-theme HTML report with full evidence tables
- PDF export via WeasyPrint
- Exec summary, adversary narrative, MITRE coverage map, IOC table
- Designed for client delivery, interviews, and portfolio use

---

## 🏗️ Architecture

```
THA/
├── tha_gui.py            # Main Tkinter GUI
├── tha_core.py           # Session management & orchestration
├── tha_pcap.py           # PCAP analysis engine
├── tha_logs.py           # Log parsing (JSON, CSV, Sysmon, Linux)
├── tha_ioc.py            # IOC correlation engine
├── tha_hypothesis.py     # Hypothesis generation & MITRE mapping
├── tha_report.py         # HTML/PDF report builder
│
├── samples/
│   └── sample_iocs.csv   # Sample threat-intel IOC database
│
└── output/               # Generated reports and saved sessions
```

---

## 🚀 Getting Started

### Requirements

- Python 3.10+
- pip packages (see `requirements.txt`)

```bash
pip install -r requirements.txt
```

**Optional for PCAP analysis:**
```bash
pip install scapy
```

**Optional for PDF export:**
```bash
pip install weasyprint
```

### Running THA

```bash
python tha_gui.py
```

The GUI will open. From there:

1. Set your **Hunt Name** and **Analyst Name**
2. Load evidence files: PCAP, logs (JSON/CSV/XML/log), IOC database
3. Click **▶ Run Full Analysis**
4. Review findings across the **Network**, **Logs**, and **IOCs** tabs
5. Click **💡 Generate Hypotheses** for MITRE-mapped hypothesis output
6. Export your **HTML** or **PDF** report

### Using THA as a Library

```python
from tha_core import THASession
from tha_pcap import PCAPAnalyzer
from tha_logs import LogAnalyzer
from tha_ioc import IOCDatabase, IOCCorrelator
from tha_hypothesis import HypothesisGenerator
from tha_report import ReportBuilder

# Create session
session = THASession(analyst_name="Your Name", hunt_name="Hunt-2024-001")

# Analyze evidence
pcap_findings = PCAPAnalyzer("capture.pcap").analyze()
log_findings  = LogAnalyzer("sysmon.json").analyze()

# IOC correlation
db = IOCDatabase()
db.load_csv("iocs.csv")
correlator = IOCCorrelator(db)
correlator.extract_from_findings(pcap_findings + log_findings)
ioc_matches = correlator.correlate()

# Generate hypotheses
all_findings = pcap_findings + log_findings + ioc_matches
gen = HypothesisGenerator()
gen.generate(all_findings)
hyp_summary = gen.get_summary()

# Build report
session.pcap_findings = pcap_findings
session.log_findings = log_findings
builder = ReportBuilder(session, hyp_summary, correlator.get_summary())
builder.build_html("output/hunt_report.html")
```

---

## 📄 Report Output

Each hunt produces a SOC-ready report including:

- **Executive Summary** with risk severity rating
- **Adversary Narrative** — plain-English kill-chain description
- **Hunt Hypotheses** — severity-ranked, evidence-backed
- **MITRE ATT&CK Coverage Map** — techniques and tactics observed
- **IOC Match Table** — matched indicators with attribution
- **Network & Log Findings** — detailed evidence tables
- **Analyst Notes** — your manual observations

---

## 🎓 eCTHP Certification Alignment

THA is built around the **eCTHP (eLearnSecurity Certified Threat Hunting Professional)** methodology:

- Structured hypothesis-driven hunting approach
- Evidence-based MITRE ATT&CK mapping
- Professional hunt report generation
- Real-world PCAP, Sysmon, and Windows Event Log analysis
- IOC threat intelligence integration

Use THA as a **hands-on practice environment** for eCTHP exam preparation, or as a portfolio piece that demonstrates applied certification knowledge.

---

## 🧠 Why This Project Matters

Threat hunting is one of the highest-value blue-team disciplines — and one of the most undersupported with tooling. THA demonstrates:

- Network forensics expertise (PCAP, protocol analysis)
- Log analysis and detection engineering
- Threat intelligence enrichment workflows
- Structured, hypothesis-driven methodology
- Professional reporting and documentation

This makes THA valuable as a **portfolio project**, **SOC tool**, **training platform**, and **consulting deliverable**.

---

## 📦 Roadmap

**v1.5 (planned)**
- Cloud log ingestion (Azure Sentinel, AWS CloudTrail, GCP Logging)
- Sigma rule integration
- Behavioral scoring engine
- Timeline reconstruction module
- API-based threat intel enrichment (VirusTotal, OTX)

**v2.0 (planned)**
- Web-based SaaS interface
- Multi-analyst collaboration
- SOAR integration hooks
- Executive dashboard
- Custom detection rules engine

---

## 📜 License

MIT License — free for personal, educational, and commercial use.

---

## 🤝 Contributing

Pull requests and module contributions are welcome. The modular architecture is designed to encourage community extensions — add new log parsers, detection rules, IOC feed adapters, or report templates.

---

*Built by a blue-teamer, for blue-teamers.*
