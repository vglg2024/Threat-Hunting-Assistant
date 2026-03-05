"""
THA Hypothesis Generator & MITRE ATT&CK Mapper
Builds structured, defensible hunt hypotheses from observed evidence.
eCTHP-aligned: Hunt Step 4 — Hypothesis Development
"""

import logging
from collections import Counter
from datetime import datetime

logger = logging.getLogger("THA.hypothesis")

# ─────────────────────────────────────────────
# MITRE ATT&CK Technique Reference (Selected)
# ─────────────────────────────────────────────
MITRE_TECHNIQUES = {
    # Initial Access
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    # Execution
    "T1059": {"name": "Command & Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Execution"},
    # Persistence
    "T1547": {"name": "Boot/Logon Autostart Execution", "tactic": "Persistence"},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence"},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence"},
    "T1136": {"name": "Create Account", "tactic": "Persistence"},
    "T1136.001": {"name": "Local Account Created", "tactic": "Persistence"},
    # Privilege Escalation
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "T1548.003": {"name": "Sudo Abuse", "tactic": "Privilege Escalation"},
    # Defense Evasion
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1070.001": {"name": "Clear Windows Event Logs", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1140": {"name": "Deobfuscate/Decode Files", "tactic": "Defense Evasion"},
    "T1218": {"name": "Signed Binary Proxy Execution", "tactic": "Defense Evasion"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    # Credential Access
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1550": {"name": "Use Alternate Auth Material", "tactic": "Credential Access"},
    # Discovery
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File & Directory Discovery", "tactic": "Discovery"},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    # Collection
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    # C2
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.004": {"name": "DNS C2", "tactic": "Command and Control"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "T1568.002": {"name": "Domain Generation Algorithms", "tactic": "Command and Control"},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control"},
    # Impact
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1498": {"name": "Network DoS", "tactic": "Impact"},
    # Other
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1222.002": {"name": "Linux File/Directory Permissions", "tactic": "Defense Evasion"},
}

# ─────────────────────────────────────────────
# Hypothesis Templates (eCTHP-style)
# ─────────────────────────────────────────────
HYPOTHESIS_TEMPLATES = {
    # Triggered by finding type
    "suspicious_port":       "An adversary is using non-standard ports ({port}) for C2 communication to evade detection by port-based filtering. Host {src} may be compromised.",
    "potential_beacon":      "A compromised host ({src}) is beaconing to an external C2 server ({dst}) at regular intervals using {proto} traffic to maintain persistent access.",
    "dga_suspicious_domain": "An infected host is using Domain Generation Algorithms (DGA) to dynamically resolve C2 infrastructure, making static domain blocking ineffective.",
    "high_frequency_dns":    "Unusual DNS query volume to {domain} suggests DNS tunneling or automated C2 beacon activity using DNS as a covert channel.",
    "large_data_transfer":   "Significant outbound data transfer ({mb}MB) from {src} to {dst} may indicate staged exfiltration via the established C2 channel.",
    "icmp_large_payload":    "ICMP packets with oversized payloads between {src} and {dst} indicate potential ICMP tunneling to covertly exfiltrate data or establish C2.",
    "suspicious_cmdline":    "Suspicious command-line activity ({match}) was observed, consistent with adversarial use of built-in tools to evade endpoint detection.",
    "lolbin_execution":      "The LOLBin '{binary}' was executed in an unusual context, indicating an adversary is abusing trusted system binaries to proxy malicious code execution.",
    "windows_event":         "Windows Security Event {event_id} ({detail}) was detected, suggesting potential adversary activity aligned with {mitre}.",
    "brute_force":           "Multiple failed authentication attempts ({count}) against user '{user}' indicate a password brute-force or credential stuffing attack.",
    "linux_event":           "Suspicious Linux activity was detected: {detail}. This may indicate post-exploitation activity on a Linux host.",
    "ioc_match":             "A known malicious indicator ({value}, {ioc_type}) was identified in collected evidence. This IOC is attributed to: {description}.",
}

# Tactic → adversary narrative mapping
TACTIC_NARRATIVES = {
    "Initial Access":         "The adversary appears to have established an initial foothold.",
    "Execution":              "Malicious code or commands were executed on the victim host.",
    "Persistence":            "The adversary established mechanisms to maintain access across reboots.",
    "Privilege Escalation":   "Evidence suggests the adversary elevated their privileges.",
    "Defense Evasion":        "The adversary took steps to evade detection or disable defenses.",
    "Credential Access":      "The adversary attempted to harvest or abuse credentials.",
    "Discovery":              "Internal reconnaissance was conducted on the compromised host.",
    "Lateral Movement":       "The adversary moved laterally within the environment.",
    "Command and Control":    "Active C2 communication between the adversary and compromised host was observed.",
    "Exfiltration":           "Data exfiltration activity was detected.",
    "Impact":                 "The adversary took actions intended to disrupt or destroy assets.",
}


class HypothesisGenerator:
    """
    Generates structured, evidence-based hunt hypotheses from analyzer findings.
    Maps findings to MITRE ATT&CK and produces a coherent hunt narrative.
    """

    def __init__(self):
        self.hypotheses: list[dict] = []
        self.mitre_coverage: dict[str, dict] = {}
        self.tactic_summary: dict[str, list] = {}
        self.adversary_narrative: str = ""

    def generate(self, all_findings: list[dict]) -> list[dict]:
        """Generate hypotheses from a combined list of findings."""
        self.hypotheses = []
        seen = set()

        for finding in all_findings:
            ftype = finding.get("type", "")
            template = HYPOTHESIS_TEMPLATES.get(ftype)
            if not template:
                continue

            # Render hypothesis text
            try:
                mb_val = round(finding.get("bytes", 0) / 1_000_000, 1) if finding.get("bytes") else 0
                hyp_text = template.format(
                    port=finding.get("port", "unknown"),
                    src=finding.get("src", "unknown"),
                    dst=finding.get("dst", "unknown"),
                    proto="TCP/UDP",
                    domain=finding.get("domain", "unknown"),
                    mb=mb_val,
                    match=(finding.get("match", "unknown pattern") or "")[:60],
                    binary=finding.get("binary", "unknown"),
                    event_id=finding.get("event_id", ""),
                    detail=finding.get("detail", ""),
                    mitre=finding.get("mitre", ""),
                    count=finding.get("count", 0),
                    user=finding.get("user", "unknown"),
                    value=finding.get("value", ""),
                    ioc_type=finding.get("ioc_type", ""),
                    description=finding.get("description", "unknown threat"),
                )
            except Exception:
                hyp_text = template

            # Deduplicate by (type, first 80 chars)
            key = (ftype, hyp_text[:80])
            if key in seen:
                continue
            seen.add(key)

            mitre_id = finding.get("mitre", "").split(" - ")[0].strip()
            technique = MITRE_TECHNIQUES.get(mitre_id, {})

            hypothesis = {
                "id": f"H-{len(self.hypotheses)+1:03d}",
                "type": ftype,
                "hypothesis": hyp_text,
                "severity": finding.get("severity", "Medium"),
                "mitre_technique_id": mitre_id,
                "mitre_technique_name": technique.get("name", ""),
                "mitre_tactic": technique.get("tactic", ""),
                "evidence_ref": finding,
                "generated_at": datetime.utcnow().isoformat(),
                "validated": False,
                "analyst_notes": "",
            }
            self.hypotheses.append(hypothesis)

            # Build MITRE coverage map
            if mitre_id:
                self.mitre_coverage[mitre_id] = {
                    "technique": technique.get("name", mitre_id),
                    "tactic": technique.get("tactic", "Unknown"),
                    "evidence_count": self.mitre_coverage.get(mitre_id, {}).get("evidence_count", 0) + 1
                }

        self._build_tactic_summary()
        self._build_adversary_narrative()
        logger.info(f"Generated {len(self.hypotheses)} hypotheses, {len(self.mitre_coverage)} MITRE techniques")
        return self.hypotheses

    def _build_tactic_summary(self):
        """Group hypotheses by MITRE tactic."""
        self.tactic_summary = {}
        for h in self.hypotheses:
            tactic = h.get("mitre_tactic", "Unclassified")
            if tactic not in self.tactic_summary:
                self.tactic_summary[tactic] = []
            self.tactic_summary[tactic].append(h)

    def _build_adversary_narrative(self):
        """Synthesize a plain-English hunt narrative from observed tactics."""
        observed_tactics = list(self.tactic_summary.keys())
        # Sort by kill-chain order
        kill_chain = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Command and Control", "Exfiltration", "Impact"
        ]
        sorted_tactics = [t for t in kill_chain if t in observed_tactics]
        unsorted = [t for t in observed_tactics if t not in kill_chain]
        all_tactics = sorted_tactics + unsorted

        if not all_tactics:
            self.adversary_narrative = "No threat activity detected. Continue monitoring."
            return

        parts = []
        for tactic in all_tactics:
            narrative = TACTIC_NARRATIVES.get(tactic, f"{tactic} activity observed.")
            parts.append(narrative)

        self.adversary_narrative = " ".join(parts)

    def get_top_severity_hypotheses(self, n: int = 5) -> list[dict]:
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "info": 4}
        return sorted(self.hypotheses, key=lambda h: sev_order.get(h["severity"], 5))[:n]

    def get_summary(self) -> dict:
        sev_counts = Counter(h["severity"] for h in self.hypotheses)
        return {
            "total_hypotheses": len(self.hypotheses),
            "severity_breakdown": dict(sev_counts),
            "mitre_techniques_covered": len(self.mitre_coverage),
            "tactics_observed": list(self.tactic_summary.keys()),
            "adversary_narrative": self.adversary_narrative,
            "hypotheses": self.hypotheses,
            "mitre_coverage": self.mitre_coverage,
        }