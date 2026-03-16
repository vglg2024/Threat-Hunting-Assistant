"""
THA DHCP Analysis Module — v1.5
Detects rogue DHCP servers, starvation attacks, and scope exhaustion.
eCTHP-aligned: Network Threat Hunting
MITRE: T1557.003 - DHCP Spoofing, T1498 - Network DoS
"""

import logging
from collections import defaultdict, Counter

logger = logging.getLogger("THA.dhcp")

# ── Thresholds ──────────────────────────────────────────────
STARVATION_THRESHOLD = 50   # DHCP Discovers in capture window = starvation
ROGUE_OFFER_THRESHOLD = 2   # More than N unique servers offering = rogue

# DHCP Message Types (option 53)
DHCP_MSG_TYPES = {
    1: "Discover",
    2: "Offer",
    3: "Request",
    4: "Decline",
    5: "ACK",
    6: "NAK",
    7: "Release",
    8: "Inform",
}

# Known legitimate DHCP server ports
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


class DHCPAnalyzer:
    """
    Analyzes DHCP traffic for rogue servers, starvation, and anomalies.
    """

    def __init__(self):
        self.findings: list[dict] = []
        self.stats: dict = {}

    def analyze(self, packets) -> list[dict]:
        try:
            from scapy.all import DHCP, BOOTP, IP, UDP, Ether
        except ImportError:
            logger.warning("Scapy not available for DHCP analysis")
            return []

        self.findings = []

        dhcp_packets = [p for p in packets if DHCP in p]
        if not dhcp_packets:
            logger.info("No DHCP packets found")
            self.stats = {"total_dhcp": 0}
            return []

        logger.info(f"Analyzing {len(dhcp_packets)} DHCP packets")

        discovers, offers, acks, requests = self._parse_dhcp(dhcp_packets, DHCP, BOOTP, IP, Ether)

        self._detect_starvation(discovers)
        self._detect_rogue_server(offers, acks)
        self._detect_offer_without_discover(discovers, offers)

        self.stats = {
            "total_dhcp_packets": len(dhcp_packets),
            "discovers":          len(discovers),
            "offers":             len(offers),
            "acks":               len(acks),
            "requests":           len(requests),
            "dhcp_findings":      len(self.findings),
        }

        logger.info(f"DHCP analysis complete: {len(self.findings)} findings")
        return self.findings

    def _get_dhcp_type(self, pkt, DHCP) -> int:
        """Extract DHCP message type from options."""
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                return opt[1]
        return 0

    def _parse_dhcp(self, packets, DHCP, BOOTP, IP, Ether):
        """Parse DHCP packets by message type."""
        discovers = []
        offers    = []
        acks      = []
        requests  = []

        for pkt in packets:
            msg_type = self._get_dhcp_type(pkt, DHCP)
            src_mac  = pkt[Ether].src if Ether in pkt else "Unknown"
            src_ip   = pkt[IP].src if IP in pkt else "0.0.0.0"
            client_mac = pkt[BOOTP].chaddr.hex()[:12] if BOOTP in pkt else "Unknown"
            offered_ip = pkt[BOOTP].yiaddr if BOOTP in pkt else ""

            entry = {
                "src_ip":     src_ip,
                "src_mac":    src_mac,
                "client_mac": client_mac,
                "offered_ip": offered_ip,
            }

            if msg_type == 1:   discovers.append(entry)
            elif msg_type == 2: offers.append(entry)
            elif msg_type == 5: acks.append(entry)
            elif msg_type == 3: requests.append(entry)

        return discovers, offers, acks, requests

    def _detect_starvation(self, discovers):
        """
        DHCP Starvation Attack — attacker sends massive DHCP Discovers
        with spoofed MAC addresses to exhaust the DHCP IP pool.
        Legitimate clients then cannot get an IP address.
        Often precedes a rogue DHCP server attack.
        """
        if len(discovers) < STARVATION_THRESHOLD:
            return

        # Check for many unique MAC addresses (spoofed)
        mac_counts = Counter(d["client_mac"] for d in discovers)
        unique_macs = len(mac_counts)

        if unique_macs > STARVATION_THRESHOLD // 2:
            self.findings.append({
                "type":        "dhcp_starvation",
                "severity":    "Critical",
                "discover_count": len(discovers),
                "unique_macs": unique_macs,
                "detail": (
                    f"DHCP starvation attack detected: {len(discovers)} DHCP Discover "
                    f"packets from {unique_macs} unique MAC addresses. "
                    f"Attacker is exhausting the DHCP pool with spoofed MACs. "
                    f"Legitimate clients will be unable to obtain IP addresses."
                ),
                "mitre": "T1498 - Network Denial of Service",
                "recommendation": (
                    "Enable DHCP snooping on switches. Implement port security to limit "
                    "MAC addresses per port. Identify source port and isolate attacker."
                ),
            })
        elif len(discovers) >= STARVATION_THRESHOLD:
            # High volume from fewer MACs — still suspicious
            self.findings.append({
                "type":        "dhcp_discover_flood",
                "severity":    "High",
                "discover_count": len(discovers),
                "unique_macs": unique_macs,
                "detail": (
                    f"High volume of DHCP Discovers: {len(discovers)} packets "
                    f"from {unique_macs} MAC addresses. "
                    f"Possible starvation attempt or misconfigured client."
                ),
                "mitre": "T1498 - Network Denial of Service",
                "recommendation": "Investigate DHCP server logs. Check for scope exhaustion. Enable DHCP snooping.",
            })

    def _detect_rogue_server(self, offers, acks):
        """
        Rogue DHCP Server — unauthorized server responding to DHCP requests.
        Attacker sets up their own DHCP server to hand out:
        - Malicious default gateway (MITM)
        - Malicious DNS server (DNS hijacking)
        - Wrong subnet mask
        Classic precursor to Man-in-the-Middle attacks.
        """
        # Collect all IPs that sent DHCP Offers or ACKs (server behavior)
        dhcp_servers = set()
        for offer in offers:
            if offer["src_ip"] not in ("0.0.0.0", "255.255.255.255"):
                dhcp_servers.add(offer["src_ip"])
        for ack in acks:
            if ack["src_ip"] not in ("0.0.0.0", "255.255.255.255"):
                dhcp_servers.add(ack["src_ip"])

        if len(dhcp_servers) > ROGUE_OFFER_THRESHOLD:
            self.findings.append({
                "type":           "rogue_dhcp_server",
                "severity":       "Critical",
                "dhcp_servers":   list(dhcp_servers),
                "server_count":   len(dhcp_servers),
                "detail": (
                    f"Multiple DHCP servers detected: {len(dhcp_servers)} IPs sending "
                    f"DHCP Offers/ACKs ({', '.join(list(dhcp_servers))}). "
                    f"Rogue DHCP servers are used for Man-in-the-Middle attacks by "
                    f"supplying malicious gateway or DNS server addresses to clients."
                ),
                "mitre": "T1557.003 - DHCP Spoofing",
                "recommendation": (
                    "Enable DHCP snooping — trust only authorized server ports. "
                    "Identify unauthorized servers and remove from network immediately. "
                    "Check clients that received offers from rogue server."
                ),
            })
        elif len(dhcp_servers) == 2:
            self.findings.append({
                "type":           "possible_rogue_dhcp",
                "severity":       "High",
                "dhcp_servers":   list(dhcp_servers),
                "detail": (
                    f"Two DHCP servers detected: {', '.join(dhcp_servers)}. "
                    f"Verify both are authorized. One may be a rogue server."
                ),
                "mitre": "T1557.003 - DHCP Spoofing",
                "recommendation": "Verify both servers are authorized. Check DHCP snooping configuration.",
            })

    def _detect_offer_without_discover(self, discovers, offers):
        """
        DHCP Offer with no corresponding Discover.
        Legitimate DHCP flow: Discover → Offer → Request → ACK.
        An Offer without a Discover suggests a rogue server proactively
        offering addresses, or a replay attack.
        """
        discover_macs = set(d["client_mac"] for d in discovers)
        orphan_offers = []

        for offer in offers:
            client_mac = offer["client_mac"]
            if client_mac and client_mac != "0" * 12:
                if client_mac not in discover_macs:
                    orphan_offers.append(offer)

        if orphan_offers:
            servers = set(o["src_ip"] for o in orphan_offers)
            self.findings.append({
                "type":          "dhcp_offer_without_discover",
                "severity":      "High",
                "offer_count":   len(orphan_offers),
                "servers":       list(servers),
                "detail": (
                    f"{len(orphan_offers)} DHCP Offer(s) sent without corresponding Discover. "
                    f"Source(s): {', '.join(servers)}. "
                    f"Indicates rogue DHCP server proactively offering addresses "
                    f"or DHCP replay attack in progress."
                ),
                "mitre": "T1557.003 - DHCP Spoofing",
                "recommendation": "Investigate DHCP server sources. Enable DHCP snooping. Check for replay attack.",
            })