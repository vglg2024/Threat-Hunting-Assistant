"""
THA Network Summary Module — v1.5
Passive asset discovery and network summary — NetworkMiner style.
Provides high-level overview before deep-dive protocol analysis.
eCTHP-aligned: Network Threat Hunting — Evidence Collection
"""

import logging
from collections import defaultdict, Counter

logger = logging.getLogger("THA.netsummary")

# Common port to service mapping
PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6667: "IRC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9001: "Tor-OR", 9050: "Tor-SOCKS",
}

# Ports that suggest lateral movement or suspicious activity
LATERAL_MOVEMENT_PORTS = {445, 135, 139, 3389, 5985, 5986, 22}
CLEARTEXT_PORTS = {21, 23, 25, 110, 143, 161}  # unencrypted protocols


class NetworkSummary:
    """
    Builds a passive asset inventory and network summary from PCAP.
    Run this first before protocol-specific analysis.
    """

    def __init__(self):
        self.hosts:    dict = {}   # ip → host profile
        self.findings: list = []
        self.stats:    dict = {}

    def analyze(self, packets) -> dict:
        try:
            from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, Ether
        except ImportError:
            logger.warning("Scapy not available for network summary")
            return {}

        logger.info(f"Building network summary from {len(packets)} packets")

        self._discover_hosts(packets, IP, TCP, UDP, ICMP, Ether)
        self._map_services(packets, IP, TCP, UDP)
        self._detect_cleartext(packets, IP, TCP, UDP)
        self._detect_lateral_movement(packets, IP, TCP)
        self._build_stats(packets, IP, TCP, UDP, ICMP)

        logger.info(f"Network summary: {len(self.hosts)} hosts discovered")
        return self.get_summary()

    def _discover_hosts(self, packets, IP, TCP, UDP, ICMP, Ether):
        """Passively discover all hosts seen in capture."""
        for pkt in packets:
            if IP not in pkt:
                continue
            src = pkt[IP].src
            dst = pkt[IP].dst

            for ip in [src, dst]:
                if ip not in self.hosts:
                    self.hosts[ip] = {
                        "ip":            ip,
                        "mac":           "",
                        "open_ports":    set(),
                        "services":      set(),
                        "protocols":     set(),
                        "packets_sent":  0,
                        "packets_recv":  0,
                        "bytes_sent":    0,
                        "bytes_recv":    0,
                        "dns_names":     set(),
                        "role":          "unknown",
                    }

            # MAC address
            if Ether in pkt:
                self.hosts[src]["mac"] = pkt[Ether].src

            # Packet counts and bytes
            size = len(pkt)
            self.hosts[src]["packets_sent"] += 1
            self.hosts[src]["bytes_sent"]   += size
            self.hosts[dst]["packets_recv"] += 1
            self.hosts[dst]["bytes_recv"]   += size

            # Protocols
            if TCP in pkt:
                self.hosts[src]["protocols"].add("TCP")
                self.hosts[dst]["protocols"].add("TCP")
            if UDP in pkt:
                self.hosts[src]["protocols"].add("UDP")
                self.hosts[dst]["protocols"].add("UDP")
            if ICMP in pkt:
                self.hosts[src]["protocols"].add("ICMP")
                self.hosts[dst]["protocols"].add("ICMP")

    def _map_services(self, packets, IP, TCP, UDP):
        """Map open ports and services to hosts."""
        for pkt in packets:
            if IP not in pkt:
                continue
            dst = pkt[IP].dst

            port = None
            if TCP in pkt:
                port = pkt[TCP].dport
            elif UDP in pkt:
                port = pkt[UDP].dport

            if port and dst in self.hosts:
                self.hosts[dst]["open_ports"].add(port)
                service = PORT_SERVICES.get(port, f"port-{port}")
                self.hosts[dst]["services"].add(service)

        # Assign roles based on services
        for ip, host in self.hosts.items():
            ports = host["open_ports"]
            if 53 in ports:
                host["role"] = "DNS Server"
            elif 67 in ports:
                host["role"] = "DHCP Server"
            elif 80 in ports or 443 in ports:
                host["role"] = "Web Server"
            elif 445 in ports or 139 in ports:
                host["role"] = "File Server / SMB"
            elif 3389 in ports:
                host["role"] = "RDP Target"
            elif 22 in ports:
                host["role"] = "SSH Server"
            elif host["packets_sent"] > host["packets_recv"] * 3:
                host["role"] = "Client / Workstation"

    def _detect_cleartext(self, packets, IP, TCP, UDP):
        """Flag unencrypted protocol usage."""
        cleartext_flows = set()
        for pkt in packets:
            if IP not in pkt:
                continue
            port = None
            if TCP in pkt:
                port = pkt[TCP].dport
            elif UDP in pkt:
                port = pkt[UDP].dport
            if port in CLEARTEXT_PORTS:
                key = (pkt[IP].src, pkt[IP].dst, port)
                if key not in cleartext_flows:
                    cleartext_flows.add(key)
                    service = PORT_SERVICES.get(port, str(port))
                    self.findings.append({
                        "type":     "cleartext_protocol",
                        "severity": "Medium",
                        "src":      pkt[IP].src,
                        "dst":      pkt[IP].dst,
                        "port":     port,
                        "service":  service,
                        "detail": (
                            f"Unencrypted {service} traffic from {pkt[IP].src} → {pkt[IP].dst}:{port}. "
                            f"Credentials and data are transmitted in cleartext."
                        ),
                        "mitre": "T1040 - Network Sniffing",
                        "recommendation": f"Replace {service} with encrypted alternative. Disable {service} if not required.",
                    })

    def _detect_lateral_movement(self, packets, IP, TCP):
        """
        Detect potential lateral movement indicators.
        Internal hosts connecting to each other on admin ports
        (RDP, SMB, WinRM, SSH) may indicate lateral movement.
        """
        lateral_flows = set()
        for pkt in packets:
            if IP not in pkt or TCP not in pkt:
                continue
            src  = pkt[IP].src
            dst  = pkt[IP].dst
            port = pkt[TCP].dport

            # Skip external traffic (simple RFC1918 check)
            src_internal = (
                src.startswith("10.") or
                src.startswith("192.168.") or
                src.startswith("172.")
            )
            dst_internal = (
                dst.startswith("10.") or
                dst.startswith("192.168.") or
                dst.startswith("172.")
            )

            if src_internal and dst_internal and port in LATERAL_MOVEMENT_PORTS:
                key = (src, dst, port)
                if key not in lateral_flows:
                    lateral_flows.add(key)
                    service = PORT_SERVICES.get(port, str(port))
                    self.findings.append({
                        "type":     "potential_lateral_movement",
                        "severity": "High",
                        "src":      src,
                        "dst":      dst,
                        "port":     port,
                        "service":  service,
                        "detail": (
                            f"Internal-to-internal {service} connection: {src} → {dst}:{port}. "
                            f"Admin protocol use between internal hosts may indicate lateral movement."
                        ),
                        "mitre": "T1021 - Remote Services",
                        "recommendation": (
                            f"Verify {service} connection is authorized. "
                            f"Check if source host is compromised. "
                            f"Review authentication logs on destination."
                        ),
                    })

    def _build_stats(self, packets, IP, TCP, UDP, ICMP):
        """Build top-level capture statistics."""
        total = len(packets)
        ip_packets   = sum(1 for p in packets if IP in p)
        tcp_packets  = sum(1 for p in packets if TCP in p)
        udp_packets  = sum(1 for p in packets if UDP in p)
        icmp_packets = sum(1 for p in packets if ICMP in p)

        # Top talkers by bytes sent
        top_talkers = sorted(
            [(ip, h["bytes_sent"]) for ip, h in self.hosts.items()],
            key=lambda x: x[1], reverse=True
        )[:5]

        self.stats = {
            "total_packets":    total,
            "ip_packets":       ip_packets,
            "tcp_packets":      tcp_packets,
            "udp_packets":      udp_packets,
            "icmp_packets":     icmp_packets,
            "unique_hosts":     len(self.hosts),
            "top_talkers":      top_talkers,
            "summary_findings": len(self.findings),
        }

    def get_summary(self) -> dict:
        """Return full network summary including host inventory."""
        # Convert sets to lists for JSON serialization
        serializable_hosts = {}
        for ip, host in self.hosts.items():
            serializable_hosts[ip] = {
                **host,
                "open_ports": sorted(list(host["open_ports"])),
                "services":   sorted(list(host["services"])),
                "protocols":  sorted(list(host["protocols"])),
                "dns_names":  list(host["dns_names"]),
            }

        return {
            "stats":    self.stats,
            "hosts":    serializable_hosts,
            "findings": self.findings,
        }