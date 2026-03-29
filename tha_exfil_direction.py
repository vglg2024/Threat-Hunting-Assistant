"""
THA Module: Exfiltration Direction Analysis
===========================================
Fixes THA's inverted exfiltration logic by correctly distinguishing:
  - INBOUND large transfers  → staging / download (not exfiltration)
  - OUTBOUND large transfers → potential data exfiltration (alert)

The original THA flagged 104.21.46.67 → 10.1.21.58 (16.1MB INBOUND)
as exfiltration. That is a staging event — the adversary pushing tools
or payloads TO the compromised host. Real exfiltration is the opposite
direction: internal host pushing data OUT to an external IP.

The actual exfiltration in the exercise pcap was:
  10.1.21.58 → 153.92.1.49 (whitepepper.su) — repeated outbound TLS
  sessions with chunked data uploads. THA missed this entirely.

MITRE ATT&CK Coverage:
  T1041  - Exfiltration Over C2 Channel
  T1048  - Exfiltration Over Alternative Protocol
  T1105  - Ingress Tool Transfer (for inbound staging — correctly labeled)
  T1071  - Application Layer Protocol

eCTHP Alignment:
  Hunt Hypothesis: Adversary is exfiltrating data over encrypted channels
  Evidence Needed: Large outbound transfers to external IPs, especially
                   to IPs already identified as C2 infrastructure
"""

import struct
import socket
import collections
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# RFC 1918 private address ranges — traffic TO these is internal, not exfil
PRIVATE_RANGES = [
    (0x0A000000, 0xFF000000),   # 10.0.0.0/8
    (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
    (0x7F000000, 0xFF000000),   # 127.0.0.0/8 (loopback)
]

# Thresholds
EXFIL_BYTES_THRESHOLD   = 500_000    # 500KB outbound to single external IP = alert
STAGING_BYTES_THRESHOLD = 1_000_000  # 1MB inbound from external IP = staging alert
BEACONING_SESSION_MIN   = 3          # Minimum repeated sessions to flag as beaconing exfil

# Risk score contributions
RISK_SCORES = {
    "large_outbound_transfer":       55,
    "outbound_to_known_c2":          70,  # Elevated if dest IP already flagged as C2
    "chunked_beaconing_exfil":       65,  # Repeated small sessions = staged exfil
    "inbound_staging":               35,  # Correctly labeled — tool/payload staging
    "exfil_over_non_standard_port":  20,  # Extra weight for non-80/443 outbound
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TrafficFlow:
    """Represents a directional traffic flow between two IPs."""
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    bytes_sent:  int = 0
    packet_count: int = 0
    session_count: int = 0      # Number of distinct TCP sessions (SYN count)
    is_outbound: bool = False   # True if src is internal, dst is external
    is_inbound:  bool = False   # True if src is external, dst is internal


@dataclass
class ExfilAlert:
    alert_type:       str
    severity:         str
    direction:        str       # "OUTBOUND_EXFIL" | "INBOUND_STAGING" | "BEACONING_EXFIL"
    src_ip:           str
    dst_ip:           str
    dst_port:         int
    bytes_transferred: int
    session_count:    int
    mitre_technique:  str
    risk_score:       int
    detail:           str
    confirmed_c2:     bool = False


# ---------------------------------------------------------------------------
# IP classification helpers
# ---------------------------------------------------------------------------

def ip_to_int(ip_str: str) -> int:
    try:
        packed = socket.inet_aton(ip_str)
        return struct.unpack(">I", packed)[0]
    except Exception:
        return 0


def is_private(ip_str: str) -> bool:
    """Return True if the IP is RFC 1918 / loopback (internal network)."""
    ip_int = ip_to_int(ip_str)
    for network, mask in PRIVATE_RANGES:
        if (ip_int & mask) == network:
            return True
    return False


def is_external(ip_str: str) -> bool:
    return not is_private(ip_str)


def classify_direction(src_ip: str, dst_ip: str) -> str:
    """
    Classify traffic direction based on IP ranges.

    Returns one of:
      "OUTBOUND"  — internal src → external dst  (potential exfil)
      "INBOUND"   — external src → internal dst  (potential staging/C2 push)
      "INTERNAL"  — both IPs are private         (lateral movement)
      "EXTERNAL"  — both IPs are public          (unusual, flag separately)
    """
    src_private = is_private(src_ip)
    dst_private = is_private(dst_ip)

    if src_private and not dst_private:
        return "OUTBOUND"
    elif not src_private and dst_private:
        return "INBOUND"
    elif src_private and dst_private:
        return "INTERNAL"
    else:
        return "EXTERNAL"


# ---------------------------------------------------------------------------
# PCAP parsing
# ---------------------------------------------------------------------------

def _read_pcap(path: str):
    with open(path, "rb") as f:
        data = f.read()
    magic = struct.unpack_from("<I", data, 0)[0]
    endian = "<" if magic == 0xa1b2c3d4 else ">"
    offset = 24
    packets = []
    while offset < len(data) - 16:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(
            f"{endian}IIII", data, offset
        )
        offset += 16
        if offset + incl_len > len(data):
            break
        packets.append((ts_sec, ts_usec, incl_len, orig_len, data[offset:offset + incl_len]))
        offset += incl_len
    return packets, endian


def build_flow_table(packets) -> dict[tuple, TrafficFlow]:
    """
    Build a directional flow table from all TCP packets.
    Key: (src_ip, dst_ip, dst_port)
    Tracks bytes, packet count, and TCP session (SYN) count per flow.

    Why dst_port only (not src_port):
      Source ports are ephemeral and change per session. Grouping by
      dst_port correctly aggregates all sessions from one host to one
      service on another host — which is exactly what reveals beaconing.
    """
    flows: dict[tuple, TrafficFlow] = {}

    for ts_sec, ts_usec, incl_len, orig_len, pkt in packets:
        if len(pkt) < 14:
            continue
        etype = struct.unpack_from(">H", pkt, 12)[0]
        if etype != 0x0800:
            continue

        ihl = (pkt[14] & 0x0F) * 4
        proto = pkt[23]
        if proto != 6:      # TCP only
            continue

        src_ip = socket.inet_ntoa(pkt[26:30])
        dst_ip = socket.inet_ntoa(pkt[30:34])

        tcp_start = 14 + ihl
        if len(pkt) < tcp_start + 14:
            continue

        sport = struct.unpack_from(">H", pkt, tcp_start)[0]
        dport = struct.unpack_from(">H", pkt, tcp_start + 2)[0]
        flags = struct.unpack_from(">H", pkt, tcp_start + 12)[0] & 0x1FF

        data_offset = ((pkt[tcp_start + 12] >> 4) * 4)
        payload_len = max(0, incl_len - (tcp_start - 0) - data_offset)

        key = (src_ip, dst_ip, dport)

        if key not in flows:
            direction = classify_direction(src_ip, dst_ip)
            flows[key] = TrafficFlow(
                src_ip      = src_ip,
                dst_ip      = dst_ip,
                src_port    = sport,
                dst_port    = dport,
                is_outbound = (direction == "OUTBOUND"),
                is_inbound  = (direction == "INBOUND"),
            )

        flows[key].bytes_sent    += payload_len
        flows[key].packet_count  += 1

        # Count TCP sessions (SYN without ACK = new session)
        if (flags & 0x02) and not (flags & 0x10):
            flows[key].session_count += 1

    return flows


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def analyze_exfiltration_direction(
    pcap_path: str,
    known_c2_ips: Optional[set] = None
) -> list[ExfilAlert]:
    """
    Main entry point. Analyzes traffic flows for exfiltration vs staging.

    Args:
        pcap_path:    Path to pcap file
        known_c2_ips: Optional set of IPs already identified as C2
                      (e.g., from tha_suspicious_tld_dns module).
                      Used to elevate risk score when exfil destination
                      matches a confirmed C2 IP.

    Returns:
        List of ExfilAlert objects sorted by risk_score descending.

    Detection logic:
        OUTBOUND large transfer   → Exfiltration Over C2 Channel (T1041)
        OUTBOUND repeated sessions → Chunked/beaconing exfil (T1041)
        INBOUND large transfer    → Ingress Tool Transfer (T1105) — staging
        NOT flagging inbound as exfiltration (the original THA bug)
    """
    if known_c2_ips is None:
        known_c2_ips = set()

    packets, _ = _read_pcap(pcap_path)
    flows = build_flow_table(packets)
    alerts = []

    for (src_ip, dst_ip, dport), flow in flows.items():

        # ----------------------------------------------------------------
        # OUTBOUND detection (internal → external)
        # This is where real exfiltration lives.
        # ----------------------------------------------------------------
        if flow.is_outbound:

            risk_score   = 0
            detail_parts = []
            alert_type   = None

            # Case 1: Large single outbound transfer
            if flow.bytes_sent >= EXFIL_BYTES_THRESHOLD:
                risk_score += RISK_SCORES["large_outbound_transfer"]
                alert_type  = "OUTBOUND_EXFIL"
                detail_parts.append(
                    f"Large outbound transfer: {flow.bytes_sent:,} bytes "
                    f"from {src_ip} → {dst_ip}:{dport}"
                )

            # Case 2: Repeated sessions to same external IP:port (beaconing exfil)
            # Chunked exfil sends data in multiple sessions to evade size thresholds
            if flow.session_count >= BEACONING_SESSION_MIN and flow.bytes_sent > 50_000:
                risk_score += RISK_SCORES["chunked_beaconing_exfil"]
                alert_type  = "BEACONING_EXFIL"
                detail_parts.append(
                    f"Chunked exfiltration pattern: {flow.session_count} sessions "
                    f"to {dst_ip}:{dport}, {flow.bytes_sent:,} bytes total. "
                    f"Consistent with adversary staging data in periodic uploads."
                )

            # Elevation: destination is a known C2 IP
            if dst_ip in known_c2_ips and risk_score > 0:
                risk_score += RISK_SCORES["outbound_to_known_c2"]
                detail_parts.append(
                    f"Destination {dst_ip} is a CONFIRMED C2 IP. "
                    f"Exfiltration over C2 channel confirmed."
                )

            # Elevation: non-standard port (not 80/443)
            if dport not in (80, 443) and risk_score > 0:
                risk_score += RISK_SCORES["exfil_over_non_standard_port"]
                detail_parts.append(
                    f"Non-standard destination port {dport} — "
                    f"potential exfil over alternative protocol (T1048)."
                )

            if risk_score > 0 and alert_type:
                if risk_score >= 100:
                    severity = "Critical"
                    mitre    = "T1041, T1048"
                elif risk_score >= 70:
                    severity = "High"
                    mitre    = "T1041"
                elif risk_score >= 40:
                    severity = "Medium"
                    mitre    = "T1041"
                else:
                    severity = "Low"
                    mitre    = "T1071"

                alerts.append(ExfilAlert(
                    alert_type        = "suspicious_outbound_transfer",
                    severity          = severity,
                    direction         = alert_type,
                    src_ip            = src_ip,
                    dst_ip            = dst_ip,
                    dst_port          = dport,
                    bytes_transferred = flow.bytes_sent,
                    session_count     = flow.session_count,
                    mitre_technique   = mitre,
                    risk_score        = risk_score,
                    detail            = " | ".join(detail_parts),
                    confirmed_c2      = (dst_ip in known_c2_ips),
                ))

        # ----------------------------------------------------------------
        # INBOUND detection (external → internal)
        # Correctly labeled as STAGING, not exfiltration.
        # ----------------------------------------------------------------
        elif flow.is_inbound and flow.bytes_sent >= STAGING_BYTES_THRESHOLD:

            risk_score = RISK_SCORES["inbound_staging"]
            detail = (
                f"Large inbound transfer: {flow.bytes_sent:,} bytes from "
                f"{src_ip} → {dst_ip}:{dport}. "
                f"Classified as INBOUND STAGING (adversary pushing tools/payloads "
                f"to compromised host), NOT exfiltration. "
                f"MITRE T1105 — Ingress Tool Transfer."
            )

            # Elevate if source is a known C2 IP (confirms adversary-controlled staging)
            if src_ip in known_c2_ips:
                risk_score += 30
                detail += f" | Source {src_ip} is confirmed C2 — staging from C2 server."

            severity = "High" if risk_score >= 60 else "Medium"

            alerts.append(ExfilAlert(
                alert_type        = "inbound_staging",
                severity          = severity,
                direction         = "INBOUND_STAGING",
                src_ip            = src_ip,
                dst_ip            = dst_ip,
                dst_port          = dport,
                bytes_transferred = flow.bytes_sent,
                session_count     = flow.session_count,
                mitre_technique   = "T1105",
                risk_score        = risk_score,
                detail            = detail,
                confirmed_c2      = (src_ip in known_c2_ips),
            ))

    alerts.sort(key=lambda a: a.risk_score, reverse=True)
    return alerts


# ---------------------------------------------------------------------------
# Output formatter — plugs into THA report engine
# ---------------------------------------------------------------------------

def format_alerts_for_tha(alerts: list[ExfilAlert]) -> list[dict]:
    findings = []
    for alert in alerts:
        findings.append({
            "type":        alert.alert_type,
            "severity":    alert.severity,
            "direction":   alert.direction,
            "source":      alert.src_ip,
            "destination": f"{alert.dst_ip}:{alert.dst_port}",
            "detail":      alert.detail,
            "mitre":       alert.mitre_technique,
            "risk_score":  alert.risk_score,
            "evidence": {
                "bytes_transferred": alert.bytes_transferred,
                "session_count":     alert.session_count,
                "confirmed_c2":      alert.confirmed_c2,
            },
        })
    return findings


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import json

    pcap_path = (
        sys.argv[1] if len(sys.argv) > 1
        else "2026-01-31-traffic-analysis-exercise.pcap"
    )

    # Simulate passing in C2 IPs from the TLD DNS module
    # In production THA, this comes from tha_suspicious_tld_dns.analyze_suspicious_tld_dns()
    known_c2_ips = {"153.92.1.49"}

    print(f"\n[THA] Exfiltration Direction Analyzer — analyzing: {pcap_path}\n")
    print("=" * 70)

    alerts = analyze_exfiltration_direction(pcap_path, known_c2_ips)

    if not alerts:
        print("[+] No significant data transfers detected.")
    else:
        outbound = [a for a in alerts if "OUTBOUND" in a.direction or "BEACONING" in a.direction]
        inbound  = [a for a in alerts if a.direction == "INBOUND_STAGING"]

        print(f"[!] {len(outbound)} OUTBOUND exfiltration alert(s)")
        print(f"[i] {len(inbound)} INBOUND staging event(s) (correctly labeled)\n")

        for alert in alerts:
            label = "⚠ EXFIL" if "OUTBOUND" in alert.direction or "BEACONING" in alert.direction else "ℹ STAGING"
            print(f"  {label}")
            print(f"  DIRECTION   : {alert.direction}")
            print(f"  {alert.src_ip} → {alert.dst_ip}:{alert.dst_port}")
            print(f"  SEVERITY    : {alert.severity}")
            print(f"  RISK SCORE  : {alert.risk_score}")
            print(f"  BYTES       : {alert.bytes_transferred:,}")
            print(f"  SESSIONS    : {alert.session_count}")
            print(f"  CONFIRMED C2: {alert.confirmed_c2}")
            print(f"  MITRE       : {alert.mitre_technique}")
            print(f"  DETAIL      : {alert.detail}")
            print()

    print("=" * 70)
    print("[THA] Report-ready findings:\n")
    print(json.dumps(format_alerts_for_tha(alerts), indent=2))
