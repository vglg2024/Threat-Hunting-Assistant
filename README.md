# 🛡 Threat Hunting Assistant (THA)

> **AI-augmented threat hunting. eCTHP-aligned. SOC-ready.**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![eCTHP Aligned](https://img.shields.io/badge/eCTHP-Aligned-38BDF8)](https://elearnsecurity.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org)
[![Version](https://img.shields.io/badge/Version-1.7-brightgreen)]()

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
| 4 | Listener & Process Triage | `tha_listener_hunt.py` — Live endpoint analysis |
| 5 | Enhanced Detection | `tha_beaconing.py`, `tha_exfil_direction.py`, `tha_suspicious_tld_dns.py` |
| 6 | IOC & Threat Intel | `tha_ioc.py` — Correlation engine |
| 7 | Hypothesis Development | `tha_hypothesis.py` — MITRE mapping |
| 8 | Validation | GUI analyst notes + evidence tables |
| 9 | Documentation | `tha_report.py` + `tha_report_pdf.py` — HTML/PDF output |

---

## 🧩 Key Capabilities

### 🎯 Enhanced Detection Engine (v1.7 — New)

Four new modules form a unified detection and scoring pipeline that runs automatically on every loaded PCAP alongside the baseline analysis.

**`tha_suspicious_tld_dns.py`** — TLD & DGA Analysis
- Flags domains using high-risk TLDs (`.ru`, `.cn`, `.top`, `.xyz`, `.tk`, and more)
- Shannon entropy analysis to identify algorithmically generated domain names
- Resolves suspicious domains to IPs for downstream C2 correlation
- MITRE T1071.004 — DNS C2, T1568.002 — DGA

**`tha_exfil_direction.py`** — Exfiltration Direction Classification
- Distinguishes true outbound exfiltration from inbound staging (adversary pushing tools)
- Correctly labels large transfers as `OUTBOUND_EXFIL`, `INBOUND_STAGING`, or `BEACONING`
- Prevents false-positive exfiltration alerts on inbound payload delivery
- MITRE T1041 — Exfil over C2, T1105 — Ingress Tool Transfer

**`tha_beaconing.py`** — Statistical Beacon Detection
- Coefficient of variation (CV) analysis on connection timing to detect jittered C2 beacons
- Detects both regular-interval and jitter-obfuscated beaconing patterns
- DNS beacon detection — periodic queries to single external domain
- Reports session count, mean interval, CV, and jitter percentage per beacon
- MITRE T1071.001 — Web Protocols C2, T1071.004 — DNS C2

**`tha_risk_scoring.py`** — Unified Risk Scoring
- Aggregates findings from all three enhanced modules into a single 0–100 risk score
- Convergence bonus: score increases when multiple modules independently confirm the same IOC
- Kill chain bonus: score increases with each additional kill chain stage covered
- Breadth bonus: accounts for total finding volume across all modules
- Produces IOC convergence table, adversary narrative, and recommended actions

---

### 🔍 Suspicious Listener Hunt (v1.6)

**`tha_listener_hunt.py`** automates network listener triage on live Windows endpoints — the exact workflow an analyst performs manually during incident response, fully scripted.

**Workflow:**
```
netstat -ano output → PID resolution → port baseline scoring →
executable path extraction → SHA-256 hash → VirusTotal enrichment →
disposition report (BENIGN / REVIEW / SUSPICIOUS / MALICIOUS)
```

**Detection capabilities:**
- Non-standard port detection against a curated Windows baseline
- PID-to-process resolution via WMI and PowerShell
- Executable path extraction with suspicious path pattern matching
- Known RAT/C2 tool name detection (ZeroTier, ngrok, Chisel, Meterpreter, AnyDesk, etc.)
- Known bloatware signature database (Acer, HP, Dell, Intel telemetry suites)
- SHA-256 hashing of flagged binaries
- VirusTotal API v3 enrichment for hash-confirmed verdicts
- JSON output for downstream IOC ingestion into THA hunt sessions

**MITRE ATT&CK coverage:**
- T1049 — System Network Connections Discovery
- T1090 — Proxy / Connection Proxy
- T1572 — Protocol Tunneling
- T1219 — Remote Access Software

**Usage:**
```bash
# Live hunt on current system
python tha_listener_hunt.py --live

# Feed saved netstat output
python tha_listener_hunt.py --file netstat_output.txt

# Show only REVIEW and above (skip confirmed benign)
python tha_listener_hunt.py --live --show REVIEW

# Full enrichment with VirusTotal
python tha_listener_hunt.py --live --vt-api-key <key> --output findings.json

# Single PID investigation
python tha_listener_hunt.py --pid 22652
```

**Real-world validated:** Used to triage an unknown Nmap scan result on a live endpoint. Five non-standard ports (4343, 4449, 5141, 9993, 46760) were flagged, traced to Acer bloatware services, and confirmed clean via VirusTotal — full hunt cycle completed in under 30 minutes.

**Pipeline integration with MTA:**
```
THA listener hunt → flags suspicious PID →
python mta_live_triage.py --live-process <PID> --vt-api-key <key> →
MTA returns disposition → feed IOCs back into THA hunt session
```

---

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

---

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
- PDF export via ReportLab — fully wrapping tables, high-contrast severity badges
- Exec summary, adversary narrative, MITRE coverage map, IOC convergence table
- Unified risk score with score breakdown (base + convergence + kill chain + breadth bonuses)
- Designed for client delivery, interviews, and portfolio use

---

## 🏗️ Architecture

```
THA/
├── tha_gui.py                    # Main Tkinter GUI
├── tha_core.py                   # Session management & orchestration
│
├── tha_pcap.py                   # PCAP orchestration engine (v1.5)
├── tha_netsummary.py             # Passive asset discovery — NetworkMiner style
├── tha_icmp.py                   # ICMP tunnel/flood/anomaly detection
├── tha_dns.py                    # DNS exfiltration, DGA, tunneling detection
├── tha_dhcp.py                   # Rogue DHCP server, starvation detection
├── tha_http.py                   # C2 beaconing, Cobalt Strike, UA detection
│
├── tha_listener_hunt.py          # Live listener triage — v1.6
│
├── tha_suspicious_tld_dns.py     # TLD & DGA domain analysis — NEW v1.7
├── tha_exfil_direction.py        # Exfil direction classification — NEW v1.7
├── tha_beaconing.py              # Statistical beacon detection — NEW v1.7
├── tha_risk_scoring.py           # Unified risk scoring engine — NEW v1.7
│
├── tha_logs.py                   # Log parsing (JSON, CSV, Sysmon, Linux)
├── tha_ioc.py                    # IOC correlation engine
├── tha_hypothesis.py             # Hypothesis generation & MITRE mapping
├── tha_report.py                 # HTML/PDF report builder
├── tha_report_pdf.py             # ReportLab PDF engine — NEW v1.7
│
├── samples/
│   └── sample_iocs.csv           # Sample threat-intel IOC database
│
└── output/                       # Generated reports and saved sessions
```

---

## 🚀 Getting Started

### Requirements

- Python 3.10+
- Npcap (Windows) — required for PCAP analysis: [npcap.com](https://npcap.com)

```bash
pip install -r requirements.txt
pip install scapy        # PCAP analysis
pip install reportlab    # PDF export
pip install requests     # Required for VirusTotal enrichment
```

### Running THA

```bash
python tha_gui.py
```

1. Set your **Hunt Name** and **Analyst Name**
2. Load evidence files: PCAP, logs (JSON/CSV/XML/log), IOC database
3. Click **▶ Run Full Analysis**
4. Review findings across the **Network**, **Logs**, **IOCs**, and **Threat Intel** tabs
5. Click **💡 Generate Hypotheses** for MITRE-mapped output
6. Export your **HTML** or **PDF** report

### Running the Listener Hunt (standalone)

```bash
# Requires admin/elevated prompt for full PID resolution
python tha_listener_hunt.py --live --show REVIEW
```

---

## 📄 Report Output

Each hunt produces a SOC-ready report including:

- **Executive Summary** with unified risk score (0–100) and tier rating
- **Score Breakdown** — base finding score + convergence, kill chain, and breadth bonuses
- **Adversary Narrative** — plain-English kill-chain description
- **IOC Convergence Table** — cross-module IOC confirmation with bar indicators
- **Enhanced Detection Findings** — TLD/DNS, exfil direction, and beaconing results
- **Network Analysis Findings** — detailed evidence from baseline PCAP modules
- **Hunt Hypotheses** — severity-ranked, evidence-backed, MITRE-mapped
- **MITRE ATT&CK Coverage Map** — techniques and tactics observed
- **IOC Match Table** — matched indicators with attribution
- **Recommended Actions** — analyst next steps
- **Analyst Notes** — your manual observations

---

## 🎓 eCTHP Certification Alignment

THA is built around the **eCTHP (eLearnSecurity Certified Threat Hunting Professional)** methodology:

- Structured hypothesis-driven hunting approach
- Evidence-based MITRE ATT&CK mapping
- Protocol-level network anomaly detection (ICMP, DNS, DHCP, HTTP)
- Statistical beaconing detection with CV-based jitter analysis
- Exfiltration direction classification (outbound vs inbound staging)
- Live endpoint listener and process triage
- Professional hunt report generation with unified risk scoring
- Real-world PCAP, Sysmon, and Windows Event Log analysis
- IOC threat intelligence integration

---

## 📦 Roadmap

| Version | Status | Highlights |
|---------|--------|------------|
| **v1.0** | ✅ Shipped | Log analysis, IOC correlation, MITRE mapping, hunt reports |
| **v1.5** | ✅ Shipped | Network hunting — ICMP, DNS, DHCP, HTTP, C2 beaconing detection |
| **v1.6** | ✅ Shipped | Live listener hunt — netstat triage, PID resolution, VT enrichment |
| **v1.7** | ✅ Shipped | Enhanced detection — beaconing CV scoring, exfil direction, TLD/DGA analysis, unified risk scoring, ReportLab PDF engine |
| **v2.0** | 🔲 Planned | Cloud log ingestion, Sigma rules, behavioral scoring, timeline reconstruction, OTX enrichment |
| **v3.0** | 🔲 Planned | Web-based SaaS interface, multi-analyst collaboration, SOAR integration, executive dashboard |

---

## 🔗 Blue Team Suite

THA is part of a larger portfolio of blue team tools:

| Tool | Cert Alignment | Purpose |
|------|---------------|---------|
| **THA** — Threat Hunting Assistant | eCTHP | Network & log analysis, live listener triage, IOC correlation, hunt reports |
| **MTA** — Malware Triage Assistant | ECIH | Static malware analysis, FLOSS strings, VirusTotal enrichment, live process triage |
| **RCA** — RMF Control Assessment Assistant | CASP+ / Security+ | RMF assessments, POA&M, ST&E, ACAS triage |

---

## 📜 License

Creative Commons Attribution-NonCommercial 4.0 — free for personal and educational use. Attribution required.

---

*Built by a blue-teamer, for blue-teamers.*
