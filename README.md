# 🛡 Threat Hunting Assistant (THA)

> **AI-augmented threat hunting. eCTHP-aligned. SOC-ready.**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![eCTHP Aligned](https://img.shields.io/badge/eCTHP-Aligned-38BDF8)](https://elearnsecurity.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org)
[![Version](https://img.shields.io/badge/Version-1.5-brightgreen)]()

---

THA is a modular, analyst-focused platform that guides defenders through the complete threat hunting lifecycle — from raw evidence to structured hypotheses, MITRE ATT&CK mapping, and polished SOC-ready reports. Built around the eCTHP methodology, it replaces fragmented, manual workflows with a unified, repeatable system.

---

## 🎯 Purpose

THA executes the full eCTHP hunt cycle:

| Step | Description | THA Module |
|------|-------------|------------|
| 1 | Planning & Scoping | `tha_core.py` — Session management |
| 2 | Evidence Collection | `tha_pcap.py` + `tha_logs.py` |
| 3 | Network Protocol Analysis | `tha_icmp.py`, `tha_dns.py`, `tha_dhcp.py`, `tha_http.py` |
| 4 | IOC & Threat Intel | `tha_ioc.py` — Correlation engine |
| 5 | Hypothesis Development | `tha_hypothesis.py` — MITRE mapping |
| 6 | Validation | GUI analyst notes + evidence tables |
| 7 | Documentation | `tha_report.py` — HTML/PDF output |

---

## 🧩 Key Capabilities

### 🌐 Network Analysis Engine (v1.5)

**Network Summary (NetworkMiner-style)**
- Passive host discovery — builds full asset inventory from PCAP
- Service and role identification (DNS server, DHCP server, web server, workstation)
- Top talkers by traffic volume
- Cleartext protocol detection (Telnet, FTP, SMTP, SNMP)
- Internal-to-internal lateral movement detection (RDP, SMB, WinRM, SSH)

**ICMP Analysis**
- ICMP flood detection (100+ packets/window)
- Large payload detection — ICMP tunneling (PTunnel, ICMPTX)
- Reply-without-request anomalies — spoofed/reflected traffic
- Unusual ICMP type codes — OS fingerprinting and reconnaissance
- Bidirectional tunnel pattern detection (consistent payload sizes)

**DNS Analysis**
- NXDomain flood detection — DGA indicator (malware rotating C2 domains)
- Domain Generation Algorithm (DGA) detection via Shannon entropy analysis
- DNS exfiltration via subdomain encoding — data chunked into queries
- High-frequency DNS queries — C2 keepalive/beaconing
- DNS over TCP (port 53) — Iodine, dnscat2 tunneling indicator
- Non-standard resolver detection — malware bypassing corporate DNS
- TXT/ANY record type abuse — DNS tunnel tool signatures

**DHCP Analysis**
- Rogue DHCP server detection — Man-in-the-Middle precursor
- DHCP starvation attack detection — spoofed MAC pool exhaustion
- DHCP Offer without Discover — replay attack or rogue server indicator

**HTTP / C2 Beaconing**
- Beacon interval analysis using coefficient of variation
- Cobalt Strike default interval detection (60s)
- Cobalt Strike malleable C2 URI pattern matching
- Suspicious User-Agent detection (Python, curl, Go, PowerShell, Empire)
- Large HTTP POST exfiltration detection
- Suspicious HTTP method detection (CONNECT, TRACE, TRACK)
- High-frequency connection analysis

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
│
├── tha_pcap.py           # PCAP orchestration engine (v1.5)
├── tha_netsummary.py     # Passive asset discovery — NetworkMiner style
├── tha_icmp.py           # ICMP tunnel/flood/anomaly detection
├── tha_dns.py            # DNS exfiltration, DGA, tunneling detection
├── tha_dhcp.py           # Rogue DHCP server, starvation detection
├── tha_http.py           # C2 beaconing, Cobalt Strike, UA detection
│
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
- Npcap (Windows) — required for PCAP analysis: [npcap.com](https://npcap.com)

```bash
pip install -r requirements.txt
pip install scapy        # PCAP analysis
pip install weasyprint   # PDF export (optional)
```

### Running THA

```bash
python tha_gui.py
```

1. Set your **Hunt Name** and **Analyst Name**
2. Load evidence files: PCAP, logs (JSON/CSV/XML/log), IOC database
3. Click **▶ Run Full Analysis**
4. Review findings across the **Network**, **Logs**, and **IOCs** tabs
5. Click **💡 Generate Hypotheses** for MITRE-mapped output
6. Export your **HTML** or **PDF** report

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
- Protocol-level network anomaly detection
- Professional hunt report generation
- Real-world PCAP, Sysmon, and Windows Event Log analysis
- IOC threat intelligence integration

---

## 📦 Roadmap

| Version | Status | Highlights |
|---------|--------|------------|
| **v1.0** | ✅ Shipped | Log analysis, IOC correlation, MITRE mapping, hunt reports |
| **v1.5** | ✅ Shipped | Network hunting — ICMP, DNS, DHCP, HTTP, C2 beaconing detection |
| **v2.0** | 🔲 Planned | Cloud log ingestion, Sigma rules, behavioral scoring, timeline reconstruction, VirusTotal/OTX enrichment |
| **v3.0** | 🔲 Planned | Web-based SaaS interface, multi-analyst collaboration, SOAR integration, executive dashboard |

---

## 🔗 Blue Team Suite

THA is part of a larger portfolio of blue team tools:

| Tool | Cert Alignment | Purpose |
|------|---------------|---------|
| **THA** — Threat Hunting Assistant | eCTHP | Network & log analysis, IOC correlation, hunt reports |
| **MTA** — Malware Triage Assistant | ECIH | Static malware analysis, PE inspection, triage reports |
| **RCA** — RMF Control Assessment Assistant | CASP+ / Security+ | RMF assessments, POA&M, ST&E, ACAS triage |

---

## 📜 License

Creative Commons Attribution-NonCommercial 4.0 — free for personal and educational use. Attribution required.

---

*Built by a blue-teamer, for blue-teamers.*