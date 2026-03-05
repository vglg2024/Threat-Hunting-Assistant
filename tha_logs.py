"""
THA Log Analysis Engine
Supports: JSON, CSV, Sysmon XML, Windows Event Logs, Linux syslog
eCTHP-aligned: Hunt Step 2 — Log Triage & Behavioral Analysis
"""

import os
import re
import json
import csv
import logging
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict

logger = logging.getLogger("THA.logs")

# ─────────────────────────────────────────────
# Detection Signatures
# ─────────────────────────────────────────────

# Sysmon Event ID mappings
SYSMON_EVENT_IDS = {
    1:  "Process Create",
    3:  "Network Connection",
    7:  "Image Load",
    8:  "CreateRemoteThread",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryAdd/Delete",
    13: "RegistrySet",
    15: "FileCreateStreamHash",
    22: "DNS Query",
    23: "FileDelete",
    25: "ProcessTamper",
}

# Suspicious process names / execution chains
SUSPICIOUS_PROCESSES = [
    "mimikatz", "procdump", "wce.exe", "fgdump", "pwdump",
    "cobalt", "empire", "metasploit", "meterpreter",
    "psexec", "wmiexec", "smbexec", "atexec",
    "certutil", "bitsadmin", "regsvr32", "mshta", "wscript",
    "cscript", "rundll32", "powershell", "cmd.exe",
]

# LOLBins (Living off the Land Binaries)
LOLBINS = [
    "certutil.exe", "bitsadmin.exe", "regsvr32.exe",
    "mshta.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "msiexec.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "odbcconf.exe",
    "microsoft.workflow.compiler.exe", "pcwrun.exe",
]

# Suspicious command-line patterns
SUSPICIOUS_CMDLINE_PATTERNS = [
    (r"-enc\s+[A-Za-z0-9+/=]{20,}", "PowerShell encoded command", "T1059.001", "High"),
    (r"invoke-(expression|iex|mimikatz|shellcode)", "PowerShell offensive technique", "T1059.001", "Critical"),
    (r"downloadstring|downloadfile|webclient|webrequest", "PS download cradle", "T1105", "High"),
    (r"net\s+(user|localgroup|group).*\/add", "Account manipulation", "T1136", "High"),
    (r"vssadmin\s+delete", "Shadow copy deletion", "T1490", "Critical"),
    (r"bcdedit.*recoveryenabled\s+no", "Disable recovery", "T1490", "Critical"),
    (r"wevtutil\s+(cl|clear)", "Event log clearing", "T1070.001", "High"),
    (r"reg\s+(add|delete).*run", "Registry persistence", "T1547.001", "High"),
    (r"schtasks.*(create|\/sc)", "Scheduled task persistence", "T1053.005", "High"),
    (r"certutil.*(-decode|-encode|-urlcache)", "CertUtil abuse", "T1140", "High"),
    (r"base64|frombase64string|tobase64string", "Base64 encoding activity", "T1027", "Medium"),
    (r"bypass|executionpolicy\s+bypass", "Security bypass", "T1562", "High"),
    (r"\\\\.*\\(c|admin|ipc)\$", "Remote share access (lateral movement)", "T1021.002", "High"),
    (r"whoami|hostname|ipconfig|systeminfo|net\s+view", "Reconnaissance commands", "T1082", "Medium"),
]

# Windows Security Event IDs of interest
WIN_SECURITY_EVENTS = {
    4624: ("Successful logon", "Medium"),
    4625: ("Failed logon", "Medium"),
    4648: ("Logon with explicit credentials", "High"),
    4672: ("Special privileges assigned", "High"),
    4688: ("Process creation", "Medium"),
    4698: ("Scheduled task created", "High"),
    4720: ("User account created", "High"),
    4728: ("Member added to security-enabled global group", "High"),
    4732: ("Member added to security-enabled local group", "High"),
    4768: ("Kerberos TGT requested", "Medium"),
    4769: ("Kerberos service ticket requested", "Medium"),
    4771: ("Kerberos pre-authentication failed", "Medium"),
    4776: ("NTLM credential validation", "Medium"),
    4946: ("Windows Firewall rule added", "Medium"),
    7045: ("New service installed", "High"),
    1102: ("Audit log cleared", "Critical"),
}


class LogAnalyzer:
    """
    Multi-format log analyzer aligned with eCTHP hunting methodology.
    Supports JSON, CSV, Sysmon XML, Windows Events, and Linux syslogs.
    """

    def __init__(self, log_path: str):
        if not os.path.exists(log_path):
            raise FileNotFoundError(f"Log file not found: {log_path}")
        self.log_path = log_path
        self.log_type = self._detect_type()
        self.raw_entries: list = []
        self.findings: list[dict] = []
        self.stats: dict = {}

    def _detect_type(self) -> str:
        path = self.log_path.lower()
        if path.endswith(".json"):
            return "json"
        elif path.endswith(".csv"):
            return "csv"
        elif path.endswith(".xml") or "sysmon" in path:
            return "sysmon_xml"
        elif "evtx" in path:
            return "evtx"
        elif path.endswith(".log") or path.endswith(".txt"):
            return "syslog"
        return "unknown"

    def load(self) -> bool:
        logger.info(f"Loading {self.log_type} log: {self.log_path}")
        try:
            if self.log_type == "json":
                with open(self.log_path) as f:
                    data = json.load(f)
                    self.raw_entries = data if isinstance(data, list) else [data]
            elif self.log_type == "csv":
                with open(self.log_path, newline="", encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    self.raw_entries = list(reader)
            elif self.log_type == "syslog":
                with open(self.log_path, encoding="utf-8", errors="replace") as f:
                    self.raw_entries = f.readlines()
            else:
                # Fallback: read as text lines
                with open(self.log_path, encoding="utf-8", errors="replace") as f:
                    self.raw_entries = f.readlines()
            logger.info(f"Loaded {len(self.raw_entries)} log entries")
            return True
        except Exception as e:
            logger.error(f"Failed to load log: {e}")
            self.findings.append({
                "type": "load_error",
                "severity": "info",
                "detail": str(e)
            })
            return False

    def analyze(self) -> list[dict]:
        if not self.raw_entries:
            if not self.load():
                return self.findings

        if self.log_type in ("json", "csv"):
            self._analyze_structured()
        elif self.log_type == "sysmon_xml":
            self._analyze_sysmon()
        else:
            self._analyze_text()

        self._build_stats()
        logger.info(f"Log analysis complete: {len(self.findings)} findings")
        return self.findings

    def _analyze_structured(self):
        """Analyze JSON/CSV logs — look for known-bad fields."""
        event_id_counts = Counter()
        failed_logins = defaultdict(int)

        for entry in self.raw_entries:
            # Flatten to text for pattern matching
            entry_str = json.dumps(entry).lower() if isinstance(entry, dict) else str(entry).lower()
            self._scan_cmdline_patterns(entry_str, entry)

            # Windows Event ID detection
            eid_raw = entry.get("EventID") or entry.get("event_id") or entry.get("id", "")
            try:
                eid = int(str(eid_raw).strip())
                event_id_counts[eid] += 1
                if eid in WIN_SECURITY_EVENTS:
                    desc, sev = WIN_SECURITY_EVENTS[eid]
                    if sev in ("High", "Critical"):
                        self.findings.append({
                            "type": "windows_event",
                            "severity": sev,
                            "event_id": eid,
                            "detail": desc,
                            "raw": entry if isinstance(entry, dict) else {},
                            "mitre": self._eid_to_mitre(eid)
                        })
                # Brute force: track failed logins
                if eid == 4625:
                    user = entry.get("SubjectUserName") or entry.get("TargetUserName", "unknown")
                    failed_logins[user] += 1
            except (ValueError, TypeError):
                pass

        # Flag brute force
        for user, count in failed_logins.items():
            if count >= 5:
                self.findings.append({
                    "type": "brute_force",
                    "severity": "High",
                    "user": user,
                    "count": count,
                    "detail": f"{count} failed logins for user '{user}' — possible brute force.",
                    "mitre": "T1110 - Brute Force"
                })

        self.stats["event_id_distribution"] = dict(event_id_counts.most_common(10))

    def _analyze_sysmon(self):
        """Parse Sysmon XML output and flag suspicious events."""
        # Simple XML text-based parsing for portability
        full_text = "\n".join(self.raw_entries) if isinstance(self.raw_entries[0], str) else ""
        self._scan_cmdline_patterns(full_text.lower(), {})

        # Find EventID 1 (Process Create) with suspicious images
        for lolbin in LOLBINS:
            if lolbin.lower() in full_text.lower():
                self.findings.append({
                    "type": "lolbin_execution",
                    "severity": "High",
                    "binary": lolbin,
                    "detail": f"LOLBin '{lolbin}' detected in Sysmon logs.",
                    "mitre": "T1218 - Signed Binary Proxy Execution"
                })

    def _analyze_text(self):
        """Analyze plain text / syslog entries."""
        full_text = " ".join(self.raw_entries).lower()
        self._scan_cmdline_patterns(full_text, {})

        # Linux-specific: sudo abuse, cron, SSH failures
        patterns = [
            (r"sudo:\s+authentication failure", "Sudo authentication failure", "T1548.003", "Medium"),
            (r"failed password for (invalid user |)(\S+)", "SSH brute force / failed login", "T1110", "High"),
            (r"new user added", "New user added via useradd", "T1136.001", "High"),
            (r"cron.*(/tmp|/dev/shm|/var/tmp)", "Cron job with suspicious path", "T1053.003", "High"),
            (r"chmod (777|4755|755) (/tmp|/dev/shm)", "Suspicious chmod on temp path", "T1222.002", "Medium"),
        ]
        for line in self.raw_entries:
            for pattern, detail, mitre, sev in patterns:
                if re.search(pattern, str(line), re.IGNORECASE):
                    self.findings.append({
                        "type": "linux_event",
                        "severity": sev,
                        "detail": detail,
                        "mitre": mitre,
                        "raw_line": str(line).strip()[:200]
                    })

    def _scan_cmdline_patterns(self, text: str, raw_entry: dict):
        """Scan text against known-bad command-line patterns."""
        for pattern, detail, mitre, sev in SUSPICIOUS_CMDLINE_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                self.findings.append({
                    "type": "suspicious_cmdline",
                    "severity": sev,
                    "pattern": pattern,
                    "match": match.group(0)[:100],
                    "detail": detail,
                    "mitre": mitre,
                    "context": text[:200]
                })

    def _eid_to_mitre(self, eid: int) -> str:
        mapping = {
            4648: "T1550 - Use Alternate Auth Material",
            4698: "T1053.005 - Scheduled Task",
            4720: "T1136 - Create Account",
            4728: "T1098 - Account Manipulation",
            7045: "T1543.003 - Windows Service",
            1102: "T1070.001 - Clear Windows Event Logs",
        }
        return mapping.get(eid, "")

    def _build_stats(self):
        sev_counts = Counter(f["severity"] for f in self.findings)
        self.stats.update({
            "total_entries": len(self.raw_entries),
            "total_findings": len(self.findings),
            "severity_breakdown": dict(sev_counts),
            "log_type": self.log_type,
        })

    def get_summary(self) -> dict:
        return {
            "file": self.log_path,
            "type": self.log_type,
            "stats": self.stats,
            "findings": self.findings
        }
