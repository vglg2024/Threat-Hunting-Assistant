"""
THA PCAP Analysis Engine
Extracts flows, protocols, suspicious hosts, and network anomalies.
eCTHP-aligned: Maps to Hunt Step 2 — Evidence Collection & Triage
"""

import os
import logging
from collections import Counter, defaultdict
from datetime import datetime

logger = logging.getLogger("THA.pcap")

# Try importing scapy; fall back gracefully
try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. Install with: pip install scapy")


# ─────────────────────────────────────────────
# Suspicious port / protocol indicators
# ─────────────────────────────────────────────
SUSPICIOUS_PORTS = {
    4444: "Metasploit default listener",
    1337: "Leet / C2 common port",
    31337: "Back Orifice / C2",
    8080: "HTTP alt / potential C2",
    8443: "HTTPS alt / potential C2",
    6667: "IRC / BotNet C2",
    9001: "Tor default OR port",
    9050: "Tor SOCKS proxy",
}

SUSPICIOUS_PROTOCOLS = {"dns", "icmp", "ftp", "telnet", "smb"}

# Beacon detection threshold: N packets to same dst in rolling window
BEACON_PACKET_THRESHOLD = 20
LARGE_UPLOAD_BYTES = 5_000_000  # 5MB outbound = possible exfiltration

# Known benign domains (whitelist sample)
WHITELIST_DOMAINS = {
    "google.com", "microsoft.com", "windows.com", "windowsupdate.com",
    "apple.com", "amazonaws.com", "cloudflare.com", "akamai.com"
}


class PCAPAnalyzer:
    """
    Analyzes a PCAP file for network-based threat indicators.
    Returns structured findings for correlation and report generation.
    """

    def __init__(self, pcap_path: str):
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")
        self.pcap_path = pcap_path
        self.packets = []
        self.findings: list[dict] = []
        self.stats: dict = {}

    def load(self):
        if not SCAPY_AVAILABLE:
            self.findings.append({
                "type": "error",
                "severity": "info",
                "detail": "Scapy library not installed. Run: pip install scapy"
            })
            return False
        logger.info(f"Loading PCAP: {self.pcap_path}")
        self.packets = rdpcap(self.pcap_path)
        logger.info(f"Loaded {len(self.packets)} packets")
        return True

    def analyze(self) -> list[dict]:
        if not self.packets:
            if not self.load():
                return self.findings

        self._extract_flows()
        self._detect_suspicious_ports()
        self._detect_dns_anomalies()
        self._detect_beaconing()
        self._detect_large_transfers()
        self._detect_icmp_anomalies()
        self._build_stats()

        logger.info(f"PCAP analysis complete: {len(self.findings)} findings")
        return self.findings

    def _extract_flows(self):
        """Build src→dst flow map."""
        self.flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set()})
        for pkt in self.packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                size = len(pkt)
                port = None
                if TCP in pkt:
                    port = pkt[TCP].dport
                elif UDP in pkt:
                    port = pkt[UDP].dport
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
                        "type": "suspicious_port",
                        "severity": "High",
                        "src": src,
                        "dst": dst,
                        "port": port,
                        "detail": SUSPICIOUS_PORTS[port],
                        "mitre": "T1571 - Non-Standard Port"
                    })

    def _detect_dns_anomalies(self):
        dns_queries = []
        domain_counts = Counter()
        for pkt in self.packets:
            if DNS in pkt and pkt[DNS].qr == 0:  # DNS query
                if DNSQR in pkt:
                    qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                    dns_queries.append(qname)
                    # Check for DGA-like patterns (long random subdomains)
                    parts = qname.split(".")
                    if parts:
                        subdomain = parts[0]
                        if len(subdomain) > 25 and not any(
                            w in subdomain for w in ["www", "mail", "api", "cdn"]
                        ):
                            self.findings.append({
                                "type": "dga_suspicious_domain",
                                "severity": "High",
                                "domain": qname,
                                "detail": f"Long random subdomain ({len(subdomain)} chars) - possible DGA",
                                "mitre": "T1568.002 - DGA"
                            })
                    # Extract base domain
                    base = ".".join(parts[-2:]) if len(parts) >= 2 else qname
                    if base not in WHITELIST_DOMAINS:
                        domain_counts[base] += 1

        # Flag high-frequency non-whitelisted domains (possible C2 beaconing via DNS)
        for domain, count in domain_counts.items():
            if count > 50:
                self.findings.append({
                    "type": "high_frequency_dns",
                    "severity": "Medium",
                    "domain": domain,
                    "count": count,
                    "detail": f"DNS queried {count} times — possible C2 or tunneling",
                    "mitre": "T1071.004 - DNS C2"
                })

        self.stats["unique_dns_queries"] = len(set(dns_queries))
        self.stats["total_dns_queries"] = len(dns_queries)

    def _detect_beaconing(self):
        """Flag IPs with high packet counts to same destination — potential beaconing."""
        for (src, dst), data in self.flows.items():
            if data["packets"] >= BEACON_PACKET_THRESHOLD:
                self.findings.append({
                    "type": "potential_beacon",
                    "severity": "Medium",
                    "src": src,
                    "dst": dst,
                    "packets": data["packets"],
                    "detail": f"{data['packets']} packets from {src} → {dst}. Possible C2 beaconing.",
                    "mitre": "T1071 - Application Layer Protocol C2"
                })

    def _detect_large_transfers(self):
        """Flag unusually large outbound data volumes — potential exfiltration."""
        for (src, dst), data in self.flows.items():
            if data["bytes"] >= LARGE_UPLOAD_BYTES:
                mb = data["bytes"] / 1_000_000
                self.findings.append({
                    "type": "large_data_transfer",
                    "severity": "High",
                    "src": src,
                    "dst": dst,
                    "bytes": data["bytes"],
                    "detail": f"{mb:.1f} MB transferred from {src} → {dst}. Possible exfiltration.",
                    "mitre": "T1041 - Exfiltration Over C2 Channel"
                })

    def _detect_icmp_anomalies(self):
        """ICMP tunneling: unusual payloads or flood."""
        icmp_flows = defaultdict(int)
        for pkt in self.packets:
            if ICMP in pkt and IP in pkt:
                icmp_flows[(pkt[IP].src, pkt[IP].dst)] += 1
                if Raw in pkt and len(pkt[Raw].load) > 100:
                    self.findings.append({
                        "type": "icmp_large_payload",
                        "severity": "Medium",
                        "src": pkt[IP].src,
                        "dst": pkt[IP].dst,
                        "payload_size": len(pkt[Raw].load),
                        "detail": "ICMP packet with large payload — possible tunneling.",
                        "mitre": "T1095 - Non-Application Layer Protocol"
                    })
        for (src, dst), count in icmp_flows.items():
            if count > 100:
                self.findings.append({
                    "type": "icmp_flood",
                    "severity": "Medium",
                    "src": src,
                    "dst": dst,
                    "count": count,
                    "detail": f"ICMP flood: {count} packets from {src} → {dst}.",
                    "mitre": "T1498 - Network Denial of Service"
                })

    def _build_stats(self):
        total_ips = set()
        for src, dst in self.flows.keys():
            total_ips.add(src)
            total_ips.add(dst)
        self.stats.update({
            "total_packets": len(self.packets),
            "unique_ips": len(total_ips),
            "unique_flows": len(self.flows),
            "total_findings": len(self.findings),
        })

    def get_summary(self) -> dict:
        return {
            "file": self.pcap_path,
            "stats": self.stats,
            "findings": self.findings
        }
