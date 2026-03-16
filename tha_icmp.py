"""
THA ICMP Analysis Module — v1.5
Detects ICMP tunneling, floods, and reply-without-request anomalies.
eCTHP-aligned: Network Threat Hunting
MITRE: T1095 - Non-Application Layer Protocol, T1498 - Network DoS
"""

import logging
from collections import defaultdict

logger = logging.getLogger("THA.icmp")

# ── Thresholds ──────────────────────────────────────────────
FLOOD_THRESHOLD     = 100   # packets from same src→dst in capture window
FLOOD_WINDOW_SEC    = 10    # seconds to measure flood
LARGE_PAYLOAD_BYTES = 100   # anything above normal ping (default 32-56 bytes)
TUNNEL_PAYLOAD_BYTES = 200  # strong tunneling indicator

# Normal ICMP type codes
# Type 8 = Echo Request, Type 0 = Echo Reply
# Type 3 = Destination Unreachable, Type 11 = Time Exceeded
EXPECTED_ICMP_TYPES = {0, 3, 8, 11}

# ICMP type names for reporting
ICMP_TYPE_NAMES = {
    0:  "Echo Reply",
    3:  "Destination Unreachable",
    4:  "Source Quench",
    5:  "Redirect",
    8:  "Echo Request",
    11: "Time Exceeded",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply",
}


class ICMPAnalyzer:
    """
    Analyzes ICMP packets for tunneling, flooding, and protocol abuse.
    Ingests pre-filtered packet list from PCAPAnalyzer.
    """

    def __init__(self):
        self.findings: list[dict] = []
        self.stats: dict = {}

    def analyze(self, packets) -> list[dict]:
        """
        Main entry point. Accepts scapy packet list.
        Returns list of finding dicts.
        """
        try:
            from scapy.all import ICMP, IP, Raw
        except ImportError:
            logger.warning("Scapy not available for ICMP analysis")
            return []

        self.findings = []

        icmp_packets = [p for p in packets if ICMP in p and IP in p]
        if not icmp_packets:
            logger.info("No ICMP packets found in capture")
            self.stats = {"total_icmp": 0}
            return []

        logger.info(f"Analyzing {len(icmp_packets)} ICMP packets")

        self._detect_flood(icmp_packets, IP, ICMP)
        self._detect_large_payload(icmp_packets, IP, ICMP, Raw)
        self._detect_reply_without_request(icmp_packets, IP, ICMP)
        self._detect_unusual_types(icmp_packets, IP, ICMP)
        self._detect_tunneling_patterns(icmp_packets, IP, ICMP, Raw)

        self.stats = {
            "total_icmp_packets": len(icmp_packets),
            "icmp_findings": len(self.findings),
        }

        logger.info(f"ICMP analysis complete: {len(self.findings)} findings")
        return self.findings

    def _detect_flood(self, packets, IP, ICMP):
        """
        Detect ICMP floods: 100+ packets from same src→dst.
        Attacker sends massive ICMP echo requests to overwhelm target
        or use as DoS carrier.
        """
        flow_counts = defaultdict(int)
        for pkt in packets:
            if pkt[ICMP].type == 8:  # Echo Request only
                key = (pkt[IP].src, pkt[IP].dst)
                flow_counts[key] += 1

        for (src, dst), count in flow_counts.items():
            if count >= FLOOD_THRESHOLD:
                self.findings.append({
                    "type":   "icmp_flood",
                    "severity": "High",
                    "src":    src,
                    "dst":    dst,
                    "count":  count,
                    "detail": (
                        f"ICMP flood detected: {count} Echo Requests from {src} → {dst}. "
                        f"Threshold: {FLOOD_THRESHOLD} packets. "
                        f"Possible DoS attack or network reconnaissance."
                    ),
                    "mitre":  "T1498.001 - Direct Network Flood",
                    "recommendation": "Investigate source host for compromise. Check if target experienced degraded performance.",
                })

    def _detect_large_payload(self, packets, IP, ICMP, Raw):
        """
        Detect ICMP packets with unusually large payloads.
        Normal ping payload is 32-56 bytes. Large payloads suggest
        data tunneling — attacker exfiltrating data inside ICMP.
        """
        seen = set()
        for pkt in packets:
            src = pkt[IP].src
            dst = pkt[IP].dst
            key = (src, dst, pkt[ICMP].type)

            if Raw in pkt:
                payload_size = len(pkt[Raw].load)
                if payload_size > LARGE_PAYLOAD_BYTES and key not in seen:
                    seen.add(key)
                    severity = "Critical" if payload_size > TUNNEL_PAYLOAD_BYTES else "High"
                    self.findings.append({
                        "type":         "icmp_large_payload",
                        "severity":     severity,
                        "src":          src,
                        "dst":          dst,
                        "payload_size": payload_size,
                        "icmp_type":    pkt[ICMP].type,
                        "detail": (
                            f"ICMP packet with {payload_size}-byte payload from {src} → {dst}. "
                            f"Normal ping payload is 32-56 bytes. "
                            f"{'Strong indicator of ICMP tunneling.' if payload_size > TUNNEL_PAYLOAD_BYTES else 'Possible ICMP tunneling or Ping of Death.'}"
                        ),
                        "mitre": "T1095 - Non-Application Layer Protocol",
                        "recommendation": "Inspect payload contents. Check for encoded data or known C2 tool signatures (e.g., ICMPTX, PTunnel).",
                    })

    def _detect_reply_without_request(self, packets, IP, ICMP):
        """
        Detect ICMP Echo Replies with no corresponding Request.
        Legitimate replies always follow a request. Replies without
        requests indicate spoofed traffic or C2 response channel.
        """
        requests  = set()  # (src, dst, seq)
        replies   = []     # (src, dst, seq, pkt)

        for pkt in packets:
            icmp_type = pkt[ICMP].type
            seq = getattr(pkt[ICMP], "seq", 0)
            src = pkt[IP].src
            dst = pkt[IP].dst

            if icmp_type == 8:   # Echo Request
                requests.add((src, dst, seq))
            elif icmp_type == 0: # Echo Reply
                replies.append((src, dst, seq))

        orphan_count = 0
        orphan_pairs = set()
        for (src, dst, seq) in replies:
            # Reply src/dst is swapped from request
            if (dst, src, seq) not in requests:
                pair = (src, dst)
                if pair not in orphan_pairs:
                    orphan_pairs.add(pair)
                    orphan_count += 1

        if orphan_count > 0:
            for (src, dst) in orphan_pairs:
                self.findings.append({
                    "type":     "icmp_reply_without_request",
                    "severity": "High",
                    "src":      src,
                    "dst":      dst,
                    "detail": (
                        f"ICMP Echo Reply from {src} → {dst} with no corresponding Request. "
                        f"Indicates spoofed traffic, reflected attack, or covert C2 response channel."
                    ),
                    "mitre": "T1095 - Non-Application Layer Protocol",
                    "recommendation": "Investigate source. May indicate Smurf attack reflection or ICMP-based C2.",
                })

    def _detect_unusual_types(self, packets, IP, ICMP):
        """
        Detect unusual ICMP type codes not normally seen in healthy networks.
        Types 13/14 (Timestamp), 17/18 (Address Mask) are rarely legitimate
        and often used for OS fingerprinting or reconnaissance.
        """
        unusual = defaultdict(set)
        for pkt in packets:
            icmp_type = pkt[ICMP].type
            if icmp_type not in EXPECTED_ICMP_TYPES:
                src = pkt[IP].src
                unusual[icmp_type].add(src)

        for icmp_type, sources in unusual.items():
            type_name = ICMP_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}")
            self.findings.append({
                "type":      "icmp_unusual_type",
                "severity":  "Medium",
                "icmp_type": icmp_type,
                "type_name": type_name,
                "sources":   list(sources),
                "detail": (
                    f"Unusual ICMP type detected: {type_name} (Type {icmp_type}) "
                    f"from {len(sources)} source(s). "
                    f"Possible network reconnaissance or OS fingerprinting."
                ),
                "mitre": "T1046 - Network Service Discovery",
                "recommendation": "Investigate sources. Consider blocking unusual ICMP types at perimeter.",
            })

    def _detect_tunneling_patterns(self, packets, IP, ICMP, Raw):
        """
        Detect ICMP tunneling patterns:
        - Consistent payload sizes across many packets (structured data)
        - High volume bidirectional ICMP between same pair
        - Non-zero ICMP ID/sequence patterns suggesting tool use
        """
        bidirectional = defaultdict(lambda: {"out": 0, "in": 0, "sizes": []})

        for pkt in packets:
            src = pkt[IP].src
            dst = pkt[IP].dst
            icmp_type = pkt[ICMP].type

            if Raw in pkt:
                size = len(pkt[Raw].load)
                key = tuple(sorted([src, dst]))
                if icmp_type == 8:
                    bidirectional[key]["out"] += 1
                    bidirectional[key]["sizes"].append(size)
                elif icmp_type == 0:
                    bidirectional[key]["in"] += 1

        for pair, data in bidirectional.items():
            total = data["out"] + data["in"]
            if total < 20:
                continue

            # Check for consistent payload sizes — structured tunneled data
            sizes = data["sizes"]
            if sizes:
                unique_sizes = set(sizes)
                consistency = len(unique_sizes) / len(sizes)
                if consistency < 0.2 and total > 30:
                    self.findings.append({
                        "type":     "icmp_tunnel_pattern",
                        "severity": "Critical",
                        "hosts":    list(pair),
                        "total_packets": total,
                        "unique_payload_sizes": len(unique_sizes),
                        "detail": (
                            f"ICMP tunneling pattern between {pair[0]} and {pair[1]}: "
                            f"{total} packets with {len(unique_sizes)} unique payload size(s). "
                            f"Highly consistent payload sizes suggest structured tunneled data. "
                            f"Known tools: PTunnel, ICMPTX, Hans."
                        ),
                        "mitre": "T1572 - Protocol Tunneling",
                        "recommendation": "Capture and inspect payload. Block ICMP at perimeter if not required. Check for PTunnel/ICMPTX signatures.",
                    })