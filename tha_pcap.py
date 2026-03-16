"""
THA PCAP Analysis Engine — v1.5
Orchestrates all network analysis modules.
eCTHP-aligned: Hunt Step 2 — Evidence Collection & Triage

Modules:
  tha_netsummary  — Passive asset discovery (NetworkMiner-style)
  tha_icmp        — ICMP tunneling, floods, reply-without-request
  tha_dns         — DNS exfiltration, DGA, NXDomain floods, tunneling
  tha_dhcp        — Rogue DHCP servers, starvation attacks
  tha_http        — C2 beaconing, Cobalt Strike patterns, suspicious UAs
"""

import os
import logging
from collections import Counter, defaultdict

logger = logging.getLogger("THA.pcap")

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. Install with: pip install scapy")

try:
    from tha_netsummary import NetworkSummary
    from tha_icmp import ICMPAnalyzer
    from tha_dns import DNSAnalyzer
    from tha_dhcp import DHCPAnalyzer
    from tha_http import HTTPAnalyzer
    MODULES_AVAILABLE = True
except ImportError as e:
    MODULES_AVAILABLE = False
    logger.warning(f"Network analysis modules not available: {e}")

SUSPICIOUS_PORTS = {
    4444: "Metasploit default listener", 1337: "Leet / C2 common port",
    31337: "Back Orifice / C2", 8080: "HTTP alt / potential C2",
    8443: "HTTPS alt / potential C2", 6667: "IRC / BotNet C2",
    9001: "Tor default OR port", 9050: "Tor SOCKS proxy",
}

BEACON_PACKET_THRESHOLD = 20
LARGE_UPLOAD_BYTES = 5_000_000

WHITELIST_DOMAINS = {
    "google.com", "microsoft.com", "windows.com", "windowsupdate.com",
    "apple.com", "amazonaws.com", "cloudflare.com", "akamai.com",
}


class PCAPAnalyzer:
    def __init__(self, pcap_path: str):
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")
        self.pcap_path = pcap_path
        self.packets = []
        self.findings: list[dict] = []
        self.stats: dict = {}
        self.net_summary: dict = {}

    def load(self) -> bool:
        if not SCAPY_AVAILABLE:
            self.findings.append({"type": "error", "severity": "info",
                                  "detail": "Scapy not installed. Run: pip install scapy"})
            return False
        logger.info(f"Loading PCAP: {self.pcap_path}")
        self.packets = rdpcap(self.pcap_path)
        logger.info(f"Loaded {len(self.packets)} packets")
        return True

    def analyze(self) -> list[dict]:
        if not self.packets:
            if not self.load():
                return self.findings

        logger.info("=== THA Network Analysis v1.5 ===")

        if MODULES_AVAILABLE:
            logger.info("Step 1: Network Summary")
            ns = NetworkSummary()
            self.net_summary = ns.analyze(self.packets)
            self.findings.extend(ns.findings)

            logger.info("Step 2: ICMP Analysis")
            self.findings.extend(ICMPAnalyzer().analyze(self.packets))

            logger.info("Step 3: DNS Analysis")
            self.findings.extend(DNSAnalyzer().analyze(self.packets))

            logger.info("Step 4: DHCP Analysis")
            self.findings.extend(DHCPAnalyzer().analyze(self.packets))

            logger.info("Step 5: HTTP / C2 Analysis")
            self.findings.extend(HTTPAnalyzer().analyze(self.packets))

        logger.info("Step 6: Flow Analysis")
        self._extract_flows()
        self._detect_suspicious_ports()
        self._detect_large_transfers()
        self._build_stats()

        self.findings = self._deduplicate(self.findings)
        self.findings = self._sort_by_severity(self.findings)

        logger.info(f"=== Analysis complete: {len(self.findings)} total findings ===")
        return self.findings

    def _extract_flows(self):
        self.flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set()})
        for pkt in self.packets:
            if IP in pkt:
                src, dst, size = pkt[IP].src, pkt[IP].dst, len(pkt)
                port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
                key = (src, dst)
                self.flows[key]["packets"] += 1
                self.flows[key]["bytes"] += size
                if port:
                    self.flows[key]["ports"].add(port)

    def _detect_suspicious_ports(self):
        for (src, dst), data in self.flows.items():
            for port in data["ports"]:
                if port in SUSPICIOUS_PORTS:
                    self.findings.append({
                        "type": "suspicious_port", "severity": "High",
                        "src": src, "dst": dst, "port": port,
                        "detail": SUSPICIOUS_PORTS[port],
                        "mitre": "T1571 - Non-Standard Port",
                        "recommendation": f"Investigate traffic on port {port}. Block if unauthorized.",
                    })

    def _detect_large_transfers(self):
        for (src, dst), data in self.flows.items():
            if data["bytes"] >= LARGE_UPLOAD_BYTES:
                mb = data["bytes"] / 1_000_000
                self.findings.append({
                    "type": "large_data_transfer", "severity": "High",
                    "src": src, "dst": dst, "bytes": data["bytes"],
                    "detail": f"{mb:.1f} MB transferred from {src} → {dst}. Possible exfiltration.",
                    "mitre": "T1041 - Exfiltration Over C2 Channel",
                    "recommendation": "Inspect transfer content. Check destination reputation.",
                })

    def _build_stats(self):
        total_ips = set()
        for src, dst in self.flows.keys():
            total_ips.add(src)
            total_ips.add(dst)
        severity_counts = Counter(f.get("severity", "Unknown") for f in self.findings)
        self.stats.update({
            "total_packets": len(self.packets),
            "unique_ips": len(total_ips),
            "unique_flows": len(self.flows),
            "total_findings": len(self.findings),
            "critical": severity_counts.get("Critical", 0),
            "high": severity_counts.get("High", 0),
            "medium": severity_counts.get("Medium", 0),
        })
        if self.net_summary:
            self.stats["hosts_discovered"] = len(self.net_summary.get("hosts", {}))

    def _deduplicate(self, findings):
        seen, unique = set(), []
        for f in findings:
            key = (f.get("type"), f.get("src"), f.get("dst"), f.get("domain", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _sort_by_severity(self, findings):
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "info": 4}
        return sorted(findings, key=lambda f: order.get(f.get("severity", "Low"), 3))

    def get_summary(self) -> dict:
        return {"file": self.pcap_path, "stats": self.stats,
                "findings": self.findings, "net_summary": self.net_summary}