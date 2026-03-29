"""
THA Module: Suspicious TLD DNS Monitoring
==========================================
Detects C2 and malware-related DNS activity by analyzing:
  1. Queries to high-risk TLDs
  2. Repeated queries to the same external domain (beaconing indicator)
  3. Successful resolution of suspicious domains followed by TCP connection (C2 confirmation)

MITRE ATT&CK Coverage:
  T1071.004 - Application Layer Protocol: DNS
  T1568     - Dynamic Resolution
  T1583.001 - Acquire Infrastructure: Domains

eCTHP Alignment:
  Hunt Hypothesis: Adversary is using DNS to locate or beacon to C2 infrastructure
  Evidence Needed: DNS query logs or pcap with DNS traffic
"""

import struct
import socket
import collections
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# TLDs with historically high abuse rates for C2 and malware infrastructure.
# Sources: Spamhaus, Passive DNS research, abuse.ch data.
HIGH_RISK_TLDS = {
    ".su",   # Soviet Union legacy - rarely legitimate, heavily abused
    ".pw",   # Palau - high spam/malware ratio
    ".cc",   # Cocos Islands - frequently abused
    ".to",   # Tonga - common C2 registration
    ".ws",   # Samoa - high malware ratio
    ".biz",  # High phishing/malware rate
    ".xyz",  # Frequently used in DGA-style domains
    ".top",  # High abuse rate
    ".club", # Used in phishing campaigns
    ".online",
    ".site",
    ".tk",   # Free domain, heavily abused
    ".ml",   # Mali - free domain, heavily abused
    ".ga",   # Gabon - free domain, heavily abused
    ".cf",   # Central African Republic - free domain
}

# Alert thresholds
REPEAT_QUERY_THRESHOLD = 5       # Same domain queried this many times = suspicious
BEACONING_QUERY_THRESHOLD = 3    # Queries to same suspicious TLD domain = high confidence
MIN_TCP_BYTES_FOR_C2_CONFIRM = 10_000  # Bytes transferred to resolved IP to confirm C2

# Risk score contributions (feeds into THA overall risk engine)
RISK_SCORES = {
    "high_risk_tld_query":        40,
    "repeat_suspicious_query":    25,
    "c2_confirmed_by_tcp":        60,
    "multiple_suspicious_tlds":   30,
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DnsEvent:
    packet_num: int
    timestamp: float
    src_ip: str
    dst_ip: str
    query_name: str
    is_response: bool
    rcode: int                          # 0=NOERROR, 3=NXDOMAIN
    resolved_ips: list = field(default_factory=list)


@dataclass
class SuspiciousDnsAlert:
    alert_type: str
    severity: str                       # High / Medium / Low
    domain: str
    tld: str
    query_count: int
    resolved_ips: list
    tcp_bytes_to_resolved: int
    mitre_technique: str
    risk_score: int
    detail: str
    packet_refs: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# PCAP parsing helpers (same approach as THA core)
# ---------------------------------------------------------------------------

def _read_pcap(path: str):
    """Read a pcap file, return (packets, endian) where packets is a list of
    (ts_sec, ts_usec, incl_len, orig_len, raw_bytes)."""
    with open(path, "rb") as f:
        data = f.read()

    magic = struct.unpack_from("<I", data, 0)[0]
    endian = "<" if magic == 0xa1b2c3d4 else ">"
    offset = 24  # skip global header
    packets = []

    while offset < len(data) - 16:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(
            f"{endian}IIII", data, offset
        )
        offset += 16
        if offset + incl_len > len(data):
            break
        packets.append((ts_sec, ts_usec, incl_len, orig_len, data[offset : offset + incl_len]))
        offset += incl_len

    return packets, endian


def _parse_dns_name(data: bytes, offset: int, depth: int = 0):
    """Parse a DNS wire-format name. Returns (name_string, new_offset)."""
    if depth > 10:
        return "(max-depth)", offset
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:          # pointer
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            name, _ = _parse_dns_name(data, ptr, depth + 1)
            labels.append(name)
            break
        else:
            labels.append(data[offset + 1 : offset + 1 + length].decode(errors="replace"))
            offset += 1 + length
    return ".".join(labels), offset


def _parse_dns_answers(dns_data: bytes, qdcount: int, ancount: int):
    """Parse A record answers from DNS response. Returns list of IP strings."""
    resolved_ips = []
    try:
        offset = 12
        # Skip questions
        for _ in range(qdcount):
            _, offset = _parse_dns_name(dns_data, offset)
            offset += 4  # qtype + qclass
        # Parse answers
        for _ in range(ancount):
            _, offset = _parse_dns_name(dns_data, offset)
            rtype, rclass, ttl, rdlen = struct.unpack_from(">HHIH", dns_data, offset)
            offset += 10
            if rtype == 1 and rdlen == 4:   # A record
                resolved_ips.append(socket.inet_ntoa(dns_data[offset : offset + 4]))
            offset += rdlen
    except Exception:
        pass
    return resolved_ips


# ---------------------------------------------------------------------------
# Core detection functions
# ---------------------------------------------------------------------------

def get_tld(domain: str) -> str:
    """Extract the TLD from a domain name."""
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return "." + parts[-1].lower()
    return ""


def is_high_risk_tld(domain: str) -> bool:
    return get_tld(domain) in HIGH_RISK_TLDS


def extract_dns_events(packets) -> list[DnsEvent]:
    """
    Walk all packets and extract DNS events (both queries and responses).
    Only processes IPv4/UDP port 53 traffic.
    """
    events = []

    for i, (ts_sec, ts_usec, incl_len, orig_len, pkt) in enumerate(packets):
        # Ethernet header
        if len(pkt) < 14:
            continue
        etype = struct.unpack_from(">H", pkt, 12)[0]
        if etype != 0x0800:     # Only IPv4
            continue

        # IP header
        if len(pkt) < 34:
            continue
        ihl = (pkt[14] & 0x0F) * 4
        proto = pkt[23]
        if proto != 17:         # Only UDP
            continue
        src_ip = socket.inet_ntoa(pkt[26:30])
        dst_ip = socket.inet_ntoa(pkt[30:34])

        # UDP header
        udp_start = 14 + ihl
        if len(pkt) < udp_start + 8:
            continue
        sport, dport = struct.unpack_from(">HH", pkt, udp_start)
        if sport != 53 and dport != 53:
            continue

        # DNS payload
        dns_data = pkt[udp_start + 8:]
        if len(dns_data) < 12:
            continue

        flags = struct.unpack_from(">H", dns_data, 2)[0]
        qr      = (flags >> 15) & 1         # 0=query, 1=response
        rcode   = flags & 0x000F
        qdcount = struct.unpack_from(">H", dns_data, 4)[0]
        ancount = struct.unpack_from(">H", dns_data, 6)[0]

        # Parse question name
        try:
            query_name, _ = _parse_dns_name(dns_data, 12)
        except Exception:
            continue

        if not query_name:
            continue

        # Parse answer IPs if this is a response
        resolved_ips = []
        if qr == 1 and ancount > 0:
            resolved_ips = _parse_dns_answers(dns_data, qdcount, ancount)

        events.append(DnsEvent(
            packet_num   = i + 1,
            timestamp    = ts_sec + ts_usec / 1e6,
            src_ip       = src_ip,
            dst_ip       = dst_ip,
            query_name   = query_name.lower(),
            is_response  = bool(qr),
            rcode        = rcode,
            resolved_ips = resolved_ips,
        ))

    return events


def measure_tcp_bytes_to_ips(packets, target_ips: set) -> dict[str, int]:
    """
    Count total TCP payload bytes sent TO each target IP.
    This confirms whether a resolved suspicious IP actually received traffic (C2 beacon).
    """
    bytes_to_ip = collections.defaultdict(int)

    for ts_sec, ts_usec, incl_len, orig_len, pkt in packets:
        if len(pkt) < 14:
            continue
        etype = struct.unpack_from(">H", pkt, 12)[0]
        if etype != 0x0800:
            continue

        ihl = (pkt[14] & 0x0F) * 4
        proto = pkt[23]
        if proto != 6:          # TCP only
            continue

        dst_ip = socket.inet_ntoa(pkt[30:34])
        if dst_ip not in target_ips:
            continue

        tcp_start = 14 + ihl
        if len(pkt) < tcp_start + 13:
            continue

        data_offset = ((pkt[tcp_start + 12] >> 4) * 4)
        payload_len = incl_len - tcp_start - data_offset
        if payload_len > 0:
            bytes_to_ip[dst_ip] += payload_len

    return dict(bytes_to_ip)


def analyze_suspicious_tld_dns(pcap_path: str) -> list[SuspiciousDnsAlert]:
    """
    Main entry point for the suspicious TLD DNS detection module.

    Detection pipeline:
      1. Extract all DNS events from pcap
      2. Identify queries to high-risk TLDs
      3. Track repeat query counts per domain
      4. Correlate successful resolutions with TCP traffic
      5. Score and return alerts

    Args:
        pcap_path: Path to the pcap file to analyze

    Returns:
        List of SuspiciousDnsAlert objects, sorted by risk_score descending
    """
    packets, _ = _read_pcap(pcap_path)
    dns_events  = extract_dns_events(packets)
    alerts      = []

    # --- Step 1: Build domain intelligence from DNS events ---

    # Track query counts per domain (queries only, not responses)
    query_counts: dict[str, int] = collections.defaultdict(int)
    query_packets: dict[str, list] = collections.defaultdict(list)

    # Track resolved IPs per domain (from successful responses)
    domain_to_ips: dict[str, set] = collections.defaultdict(set)

    for event in dns_events:
        domain = event.query_name.rstrip(".")

        if not event.is_response:
            # It's a query
            query_counts[domain] += 1
            query_packets[domain].append(event.packet_num)
        else:
            # It's a response — capture resolved IPs
            for ip in event.resolved_ips:
                domain_to_ips[domain].add(ip)

    # --- Step 2: Identify high-risk TLD domains that were queried ---

    suspicious_domains = {
        domain for domain in query_counts
        if is_high_risk_tld(domain)
    }

    if not suspicious_domains:
        return []  # Nothing to report

    # --- Step 3: Measure TCP traffic to resolved IPs of suspicious domains ---

    all_suspicious_resolved_ips = set()
    for domain in suspicious_domains:
        all_suspicious_resolved_ips.update(domain_to_ips.get(domain, set()))

    tcp_bytes = measure_tcp_bytes_to_ips(packets, all_suspicious_resolved_ips)

    # --- Step 4: Build alerts per suspicious domain ---

    for domain in suspicious_domains:
        tld         = get_tld(domain)
        count       = query_counts[domain]
        resolved    = list(domain_to_ips.get(domain, set()))
        pkt_refs    = query_packets[domain]
        risk_score  = 0
        detail_parts = []

        # Base score: high-risk TLD query
        risk_score += RISK_SCORES["high_risk_tld_query"]
        detail_parts.append(f"Domain '{domain}' uses high-risk TLD '{tld}'")

        # Repeat query check
        if count >= BEACONING_QUERY_THRESHOLD:
            risk_score += RISK_SCORES["repeat_suspicious_query"]
            detail_parts.append(
                f"Queried {count}x — exceeds beaconing threshold "
                f"({BEACONING_QUERY_THRESHOLD}). Consistent with periodic C2 check-in."
            )

        # C2 confirmation: suspicious domain resolved + TCP traffic sent to that IP
        tcp_to_resolved = sum(tcp_bytes.get(ip, 0) for ip in resolved)
        if tcp_to_resolved >= MIN_TCP_BYTES_FOR_C2_CONFIRM:
            risk_score += RISK_SCORES["c2_confirmed_by_tcp"]
            detail_parts.append(
                f"Resolved to {resolved} and {tcp_to_resolved:,} bytes of TCP traffic "
                f"sent to that IP — C2 beacon CONFIRMED."
            )

        # Severity mapping
        if risk_score >= 80:
            severity = "Critical"
            mitre    = "T1071.004, T1041"
        elif risk_score >= 60:
            severity = "High"
            mitre    = "T1071.004"
        elif risk_score >= 40:
            severity = "Medium"
            mitre    = "T1568"
        else:
            severity = "Low"
            mitre    = "T1071.004"

        alerts.append(SuspiciousDnsAlert(
            alert_type             = "suspicious_tld_dns",
            severity               = severity,
            domain                 = domain,
            tld                    = tld,
            query_count            = count,
            resolved_ips           = resolved,
            tcp_bytes_to_resolved  = tcp_to_resolved,
            mitre_technique        = mitre,
            risk_score             = risk_score,
            detail                 = " | ".join(detail_parts),
            packet_refs            = pkt_refs[:10],  # First 10 packet refs for evidence
        ))

    # Sort by risk score descending so highest-confidence findings surface first
    alerts.sort(key=lambda a: a.risk_score, reverse=True)

    return alerts


# ---------------------------------------------------------------------------
# Output formatter (plugs into THA report engine)
# ---------------------------------------------------------------------------

def format_alerts_for_tha(alerts: list[SuspiciousDnsAlert]) -> list[dict]:
    """
    Convert alerts to THA's standard network_findings dict format
    so they slot directly into the existing report pipeline.
    """
    findings = []
    for alert in alerts:
        findings.append({
            "type":        alert.alert_type,
            "severity":    alert.severity,
            "source":      "internal_host",
            "destination": alert.domain,
            "detail":      alert.detail,
            "mitre":       alert.mitre_technique,
            "risk_score":  alert.risk_score,
            "evidence": {
                "resolved_ips":           alert.resolved_ips,
                "query_count":            alert.query_count,
                "tcp_bytes_to_resolved":  alert.tcp_bytes_to_resolved,
                "packet_refs":            alert.packet_refs,
            },
        })
    return findings


# ---------------------------------------------------------------------------
# Standalone test — run directly against the exercise pcap
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    pcap_path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "2026-01-31-traffic-analysis-exercise.pcap"
    )

    print(f"\n[THA] Suspicious TLD DNS Monitor — analyzing: {pcap_path}\n")
    print("=" * 70)

    alerts = analyze_suspicious_tld_dns(pcap_path)

    if not alerts:
        print("[+] No suspicious TLD DNS activity detected.")
    else:
        print(f"[!] {len(alerts)} suspicious domain(s) detected:\n")
        for alert in alerts:
            print(f"  DOMAIN      : {alert.domain}")
            print(f"  TLD         : {alert.tld}")
            print(f"  SEVERITY    : {alert.severity}")
            print(f"  RISK SCORE  : {alert.risk_score}")
            print(f"  QUERIES     : {alert.query_count}x")
            print(f"  RESOLVED TO : {alert.resolved_ips}")
            print(f"  TCP BYTES   : {alert.tcp_bytes_to_resolved:,}")
            print(f"  MITRE       : {alert.mitre_technique}")
            print(f"  DETAIL      : {alert.detail}")
            print(f"  PKT REFS    : {alert.packet_refs}")
            print()

    # Show what THA report format looks like
    print("=" * 70)
    print("[THA] Report-ready findings dict:\n")
    import json
    formatted = format_alerts_for_tha(alerts)
    print(json.dumps(formatted, indent=2))
