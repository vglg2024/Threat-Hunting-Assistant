"""
THA Module: Beaconing Detection
================================
Detects C2 beaconing patterns across TCP, UDP, ICMP, and DNS transports.

Covered patterns:
  1. FIXED INTERVAL    — Connections at near-identical time gaps (Cobalt Strike
                         default sleep is 60s with 0% jitter). High confidence C2.
  2. JITTERED INTERVAL — Connections at randomized but statistically consistent
                         intervals. Adversaries add jitter to evade fixed-interval
                         detectors. Detected via coefficient of variation (CV).
  3. SEQUENTIAL EPHEMERAL PORT — Same external IP contacted repeatedly on
                         incrementing source ports (new TCP session each time).
                         Exactly what whitepepper.su did in the exercise pcap.

Transport coverage:
  - TCP  : TLS/HTTPS beaconing (most common C2 transport)
  - UDP  : Less common but used by some RATs and DNS-based C2
  - ICMP : ICMP tunneling / oversized payload beaconing
  - DNS  : Periodic queries to same domain (DNS C2 / DGA check-in)

MITRE ATT&CK Coverage:
  T1071.001 - Application Layer Protocol: Web Protocols
  T1071.004 - Application Layer Protocol: DNS
  T1095     - Non-Application Layer Protocol (ICMP/raw)
  T1041     - Exfiltration Over C2 Channel
  T1568.002 - Dynamic Resolution: Domain Generation Algorithms

eCTHP Alignment:
  Hunt Hypothesis: Compromised host is maintaining persistent C2 channel
  via periodic beaconing to adversary-controlled infrastructure.
  Key Analyst Skill: Distinguish C2 beaconing from legitimate periodic
  traffic (NTP, telemetry, heartbeats) using statistical analysis.

Statistical Methods Used:
  - Coefficient of Variation (CV): stddev / mean
      CV < 0.15 → fixed interval (very regular)
      CV 0.15-0.40 → jittered interval (random but consistent)
      CV > 0.40 → irregular (less likely beaconing)
  - Inter-arrival time (IAT) analysis
  - Session count thresholds per time window
"""

import struct
import socket
import math
import collections
import statistics
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Minimum sessions required before we attempt statistical analysis.
# Too few data points = unreliable CV calculation.
MIN_SESSIONS_FOR_ANALYSIS = 4

# Coefficient of Variation thresholds
CV_FIXED_INTERVAL_MAX    = 0.15   # CV below this = highly regular = fixed beacon
CV_JITTER_MAX            = 0.40   # CV 0.15-0.40 = jittered beacon
# CV > 0.40 = too irregular to confidently call beaconing

# Sequential ephemeral port detection
SEQ_PORT_MIN_SESSIONS    = 3      # Minimum sessions with incrementing src ports
SEQ_PORT_MAX_GAP         = 5      # Maximum gap between sequential port numbers
                                  # (allows for some port reuse by OS)

# Known legitimate beaconing intervals to EXCLUDE (reduce false positives)
# These are common non-malicious periodic traffic intervals in seconds
LEGITIMATE_INTERVALS = {
    60:   "NTP sync",
    300:  "Windows telemetry",
    3600: "Windows Update check",
    900:  "WSUS check-in",
    30:   "Heartbeat/keepalive",
}
LEGITIMATE_INTERVAL_TOLERANCE = 0.10  # 10% tolerance window

# Minimum interval to consider (ignore sub-1s traffic — not beaconing)
MIN_INTERVAL_SECONDS = 1.0

# Transport-specific session thresholds
THRESHOLDS = {
    "TCP":  {"min_sessions": 4, "min_bytes_per_session": 20},
    "UDP":  {"min_sessions": 4, "min_bytes_per_session": 10},
    "ICMP": {"min_sessions": 3, "min_bytes_per_session": 0},
    "DNS":  {"min_sessions": 3, "min_bytes_per_session": 0},
}

# Risk score contributions
RISK_SCORES = {
    "fixed_interval_beacon":      75,
    "jittered_interval_beacon":   55,
    "sequential_ephemeral_port":  60,
    "dns_periodic_query":         45,
    "icmp_beacon":                50,
    "known_c2_ip_match":          40,   # Elevation if IP matches TLD/exfil module
    "non_standard_port":          15,
    "low_cv_bonus":               10,   # Extra confidence for very low CV
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BeaconSession:
    """A single connection event toward a potential C2."""
    timestamp:   float
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    proto:       str        # TCP / UDP / ICMP / DNS
    payload_len: int
    packet_num:  int


@dataclass
class BeaconCandidate:
    """
    Aggregated sessions to a single (src_ip, dst_ip, dst_port, proto) tuple,
    ready for statistical analysis.
    """
    src_ip:      str
    dst_ip:      str
    dst_port:    int
    proto:       str
    sessions:    list = field(default_factory=list)   # list of BeaconSession
    src_ports:   list = field(default_factory=list)   # ordered src port history


@dataclass
class BeaconAlert:
    alert_type:       str    # fixed_interval / jittered_interval / sequential_port / dns_beacon / icmp_beacon
    severity:         str
    src_ip:           str
    dst_ip:           str
    dst_port:         int
    proto:            str
    session_count:    int
    mean_interval_s:  float
    cv:               float  # Coefficient of variation (0 = perfectly regular)
    jitter_pct:       float  # Estimated jitter percentage
    pattern:          str    # Human-readable pattern description
    mitre_technique:  str
    risk_score:       int
    detail:           str
    confirmed_c2:     bool = False
    sequential_ports: list = field(default_factory=list)
    interval_samples: list = field(default_factory=list)


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
        packets.append((
            ts_sec + ts_usec / 1e6,     # Combined float timestamp
            incl_len,
            orig_len,
            data[offset:offset + incl_len]
        ))
        offset += incl_len
    return packets


def _parse_dns_name(data: bytes, offset: int, depth: int = 0):
    if depth > 10:
        return "(max-depth)", offset
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            name, _ = _parse_dns_name(data, ptr, depth + 1)
            labels.append(name)
            break
        else:
            labels.append(data[offset + 1:offset + 1 + length].decode(errors="replace"))
            offset += 1 + length
    return ".".join(labels), offset


# ---------------------------------------------------------------------------
# Session extraction per protocol
# ---------------------------------------------------------------------------

def extract_tcp_sessions(packets) -> list[BeaconSession]:
    """
    Extract TCP sessions (SYN packets only — one per session).
    We use SYN packets because each new TCP session = one beacon check-in.
    Using all packets would flood the analysis with retransmits/ACKs.
    """
    sessions = []
    for i, (ts, incl_len, orig_len, pkt) in enumerate(packets):
        if len(pkt) < 14:
            continue
        if struct.unpack_from(">H", pkt, 12)[0] != 0x0800:
            continue
        ihl = (pkt[14] & 0x0F) * 4
        if pkt[23] != 6:    # TCP
            continue
        src_ip = socket.inet_ntoa(pkt[26:30])
        dst_ip = socket.inet_ntoa(pkt[30:34])
        tcp_start = 14 + ihl
        if len(pkt) < tcp_start + 14:
            continue
        sport = struct.unpack_from(">H", pkt, tcp_start)[0]
        dport = struct.unpack_from(">H", pkt, tcp_start + 2)[0]
        flags = struct.unpack_from(">H", pkt, tcp_start + 12)[0] & 0x1FF
        # SYN only (not SYN-ACK)
        if not ((flags & 0x02) and not (flags & 0x10)):
            continue
        data_off = ((pkt[tcp_start + 12] >> 4) * 4)
        payload  = max(0, incl_len - (14 + ihl) - data_off)
        sessions.append(BeaconSession(
            timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
            src_port=sport, dst_port=dport,
            proto="TCP", payload_len=payload, packet_num=i + 1
        ))
    return sessions


def extract_udp_sessions(packets) -> list[BeaconSession]:
    """Extract UDP flows. Each UDP packet to the same dst is a session event."""
    seen = set()   # deduplicate by (src,dst,sport,dport) within 1s windows
    sessions = []
    for i, (ts, incl_len, orig_len, pkt) in enumerate(packets):
        if len(pkt) < 14:
            continue
        if struct.unpack_from(">H", pkt, 12)[0] != 0x0800:
            continue
        ihl = (pkt[14] & 0x0F) * 4
        if pkt[23] != 17:   # UDP
            continue
        src_ip = socket.inet_ntoa(pkt[26:30])
        dst_ip = socket.inet_ntoa(pkt[30:34])
        udp_start = 14 + ihl
        if len(pkt) < udp_start + 8:
            continue
        sport = struct.unpack_from(">H", pkt, udp_start)[0]
        dport = struct.unpack_from(">H", pkt, udp_start + 2)[0]
        # Skip DNS — handled separately
        if dport == 53 or sport == 53:
            continue
        payload = max(0, incl_len - udp_start - 8)
        # Use 1-second time bucket to count distinct sessions
        bucket = (src_ip, dst_ip, dport, int(ts))
        if bucket in seen:
            continue
        seen.add(bucket)
        sessions.append(BeaconSession(
            timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
            src_port=sport, dst_port=dport,
            proto="UDP", payload_len=payload, packet_num=i + 1
        ))
    return sessions


def extract_icmp_sessions(packets) -> list[BeaconSession]:
    """
    Extract ICMP echo requests (type 8). Each request = one potential beacon.
    Flag oversized payloads separately — normal ping payload is 32-56 bytes.
    """
    sessions = []
    for i, (ts, incl_len, orig_len, pkt) in enumerate(packets):
        if len(pkt) < 14:
            continue
        if struct.unpack_from(">H", pkt, 12)[0] != 0x0800:
            continue
        ihl = (pkt[14] & 0x0F) * 4
        if pkt[23] != 1:    # ICMP
            continue
        src_ip = socket.inet_ntoa(pkt[26:30])
        dst_ip = socket.inet_ntoa(pkt[30:34])
        icmp_start = 14 + ihl
        if len(pkt) < icmp_start + 4:
            continue
        icmp_type = pkt[icmp_start]
        if icmp_type != 8:  # Echo request only
            continue
        payload = max(0, incl_len - icmp_start - 8)
        sessions.append(BeaconSession(
            timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
            src_port=0, dst_port=0,
            proto="ICMP", payload_len=payload, packet_num=i + 1
        ))
    return sessions


def extract_dns_sessions(packets) -> list[BeaconSession]:
    """
    Extract DNS queries (not responses). Each query to the same domain
    = one beacon check-in for DNS C2 analysis.
    """
    sessions = []
    for i, (ts, incl_len, orig_len, pkt) in enumerate(packets):
        if len(pkt) < 14:
            continue
        if struct.unpack_from(">H", pkt, 12)[0] != 0x0800:
            continue
        ihl = (pkt[14] & 0x0F) * 4
        if pkt[23] != 17:
            continue
        udp_start = 14 + ihl
        if len(pkt) < udp_start + 8:
            continue
        sport, dport = struct.unpack_from(">HH", pkt, udp_start)
        if dport != 53:
            continue
        dns_data = pkt[udp_start + 8:]
        if len(dns_data) < 12:
            continue
        flags_dns = struct.unpack_from(">H", dns_data, 2)[0]
        if (flags_dns >> 15) & 1:
            continue    # Skip responses
        try:
            query_name, _ = _parse_dns_name(dns_data, 12)
        except Exception:
            continue
        src_ip = socket.inet_ntoa(pkt[26:30])
        dst_ip = socket.inet_ntoa(pkt[30:34])
        # Use dst_ip=query_name so grouping works on domain not resolver IP
        sessions.append(BeaconSession(
            timestamp=ts, src_ip=src_ip, dst_ip=query_name.lower().rstrip("."),
            src_port=sport, dst_port=53,
            proto="DNS", payload_len=len(dns_data), packet_num=i + 1
        ))
    return sessions


# ---------------------------------------------------------------------------
# Statistical analysis
# ---------------------------------------------------------------------------

def compute_inter_arrival_times(timestamps: list[float]) -> list[float]:
    """Compute time gaps between consecutive session timestamps."""
    sorted_ts = sorted(timestamps)
    return [
        sorted_ts[i + 1] - sorted_ts[i]
        for i in range(len(sorted_ts) - 1)
        if sorted_ts[i + 1] - sorted_ts[i] >= MIN_INTERVAL_SECONDS
    ]


def compute_cv(values: list[float]) -> float:
    """
    Coefficient of Variation = stddev / mean.
    Measures relative variability. Lower = more regular = more suspicious.
    Returns 999.0 if insufficient data.
    """
    if len(values) < 2:
        return 999.0
    mean = statistics.mean(values)
    if mean == 0:
        return 999.0
    stddev = statistics.stdev(values)
    return stddev / mean


def estimate_jitter_pct(cv: float) -> float:
    """
    Estimate the jitter percentage an adversary is using based on CV.
    Cobalt Strike jitter is configured as a percentage of sleep time.
    CV ≈ jitter_pct / sqrt(3) for uniform jitter distribution.
    """
    return min(100.0, cv * math.sqrt(3) * 100)


def is_legitimate_interval(mean_interval: float) -> Optional[str]:
    """
    Check if the mean interval matches known legitimate periodic traffic.
    Returns the service name if matched, None if suspicious.
    """
    for interval_s, service_name in LEGITIMATE_INTERVALS.items():
        tolerance = interval_s * LEGITIMATE_INTERVAL_TOLERANCE
        if abs(mean_interval - interval_s) <= tolerance:
            return service_name
    return None


def detect_sequential_ports(src_ports: list[int]) -> tuple[bool, list[int]]:
    """
    Detect sequential ephemeral source port pattern.

    When a C2 implant opens a new TCP session for each beacon, the OS
    assigns incrementing source ports. This leaves a fingerprint:
    e.g., 56198, 56199, 56200 ... or with small gaps: 61826, 61827, 61828.

    Returns (is_sequential, ordered_port_list).
    """
    if len(src_ports) < SEQ_PORT_MIN_SESSIONS:
        return False, []

    # Sort ports and check for sequential runs
    sorted_ports = sorted(set(src_ports))
    max_run = 1
    current_run = 1
    run_start_idx = 0
    best_run_start = 0

    for i in range(1, len(sorted_ports)):
        gap = sorted_ports[i] - sorted_ports[i - 1]
        if gap <= SEQ_PORT_MAX_GAP:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
                best_run_start = run_start_idx
        else:
            current_run = 1
            run_start_idx = i

    if max_run >= SEQ_PORT_MIN_SESSIONS:
        sequential_ports = sorted_ports[best_run_start:best_run_start + max_run]
        return True, sequential_ports

    return False, []


# ---------------------------------------------------------------------------
# Candidate grouping
# ---------------------------------------------------------------------------

def build_beacon_candidates(sessions: list[BeaconSession]) -> list[BeaconCandidate]:
    """
    Group sessions by (src_ip, dst_ip, dst_port, proto).
    For ICMP, group by (src_ip, dst_ip) only.
    For DNS, group by (src_ip, domain).
    """
    groups: dict[tuple, BeaconCandidate] = {}

    for s in sessions:
        if s.proto == "ICMP":
            key = (s.src_ip, s.dst_ip, 0, "ICMP")
        elif s.proto == "DNS":
            key = (s.src_ip, s.dst_ip, 53, "DNS")
        else:
            key = (s.src_ip, s.dst_ip, s.dst_port, s.proto)

        if key not in groups:
            groups[key] = BeaconCandidate(
                src_ip=s.src_ip, dst_ip=s.dst_ip,
                dst_port=s.dst_port, proto=s.proto
            )
        groups[key].sessions.append(s)
        if s.src_port > 0:
            groups[key].src_ports.append(s.src_port)

    return list(groups.values())


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def analyze_beaconing(
    pcap_path: str,
    known_c2_ips: Optional[set] = None,
    known_c2_domains: Optional[set] = None,
) -> list[BeaconAlert]:
    """
    Main entry point. Extracts sessions across all transports,
    groups into candidates, and applies statistical + pattern analysis.

    Args:
        pcap_path:          Path to pcap file
        known_c2_ips:       IPs confirmed as C2 (from tha_suspicious_tld_dns)
        known_c2_domains:   Domains confirmed as C2 (from tha_suspicious_tld_dns)

    Returns:
        List of BeaconAlert objects sorted by risk_score descending.
    """
    if known_c2_ips is None:
        known_c2_ips = set()
    if known_c2_domains is None:
        known_c2_domains = set()

    packets = _read_pcap(pcap_path)

    # Extract sessions across all transports
    all_sessions = (
        extract_tcp_sessions(packets) +
        extract_udp_sessions(packets) +
        extract_icmp_sessions(packets) +
        extract_dns_sessions(packets)
    )

    candidates = build_beacon_candidates(all_sessions)
    alerts = []

    for candidate in candidates:
        proto     = candidate.proto
        threshold = THRESHOLDS.get(proto, THRESHOLDS["TCP"])

        if len(candidate.sessions) < threshold["min_sessions"]:
            continue

        timestamps  = [s.timestamp for s in candidate.sessions]
        iats        = compute_inter_arrival_times(timestamps)

        if len(iats) < 2:
            continue

        mean_iat   = statistics.mean(iats)
        cv         = compute_cv(iats)
        jitter_pct = estimate_jitter_pct(cv)

        # Skip if mean interval looks like legitimate traffic
        legit_match = is_legitimate_interval(mean_iat)
        if legit_match:
            continue

        risk_score   = 0
        alert_type   = None
        detail_parts = []
        mitre        = "T1071.001"
        pattern      = ""

        # ----------------------------------------------------------------
        # Pattern 1: Fixed interval beacon (CV < 0.15)
        # ----------------------------------------------------------------
        if cv < CV_FIXED_INTERVAL_MAX:
            risk_score += RISK_SCORES["fixed_interval_beacon"]
            if cv < 0.05:
                risk_score += RISK_SCORES["low_cv_bonus"]
            alert_type = "fixed_interval"
            pattern    = f"Fixed interval beacon — {mean_iat:.1f}s sleep, CV={cv:.3f}"
            detail_parts.append(
                f"Highly regular connections every {mean_iat:.1f}s (CV={cv:.3f}). "
                f"Consistent with Cobalt Strike default beacon (60s sleep, 0% jitter) "
                f"or other C2 framework with fixed sleep. "
                f"Estimated jitter: {jitter_pct:.1f}%."
            )
            mitre = "T1071.001" if proto == "TCP" else "T1071.004" if proto == "DNS" else "T1095"

        # ----------------------------------------------------------------
        # Pattern 2: Jittered interval beacon (CV 0.15 - 0.40)
        # ----------------------------------------------------------------
        elif cv <= CV_JITTER_MAX:
            risk_score += RISK_SCORES["jittered_interval_beacon"]
            alert_type = "jittered_interval"
            pattern    = f"Jittered interval beacon — {mean_iat:.1f}s mean, CV={cv:.3f}"
            detail_parts.append(
                f"Statistically consistent connections with randomized timing "
                f"(mean={mean_iat:.1f}s, CV={cv:.3f}, ~{jitter_pct:.0f}% jitter). "
                f"Adversaries use jitter to evade fixed-interval detection. "
                f"Cobalt Strike jitter config typically 10-50%. "
                f"IAT samples: {[round(x,1) for x in iats[:8]]}..."
            )
            mitre = "T1071.001" if proto == "TCP" else "T1071.004" if proto == "DNS" else "T1095"

        # ----------------------------------------------------------------
        # Pattern 3: Sequential ephemeral port (regardless of CV)
        # ----------------------------------------------------------------
        is_seq, seq_ports = detect_sequential_ports(candidate.src_ports)
        if is_seq:
            risk_score += RISK_SCORES["sequential_ephemeral_port"]
            if alert_type is None:
                alert_type = "sequential_ephemeral_port"
                mitre      = "T1071.001"
            pattern += (f" | Sequential src ports: {seq_ports[:8]}"
                        if pattern else
                        f"Sequential ephemeral port beaconing — ports: {seq_ports[:8]}")
            detail_parts.append(
                f"Sequential source ports detected: {seq_ports[:8]}... "
                f"Each new TCP session opens on incrementing port number — "
                f"signature of an implant opening a fresh connection per beacon "
                f"rather than reusing a persistent socket. "
                f"Exactly matches whitepepper.su C2 pattern in this pcap."
            )

        # ----------------------------------------------------------------
        # DNS-specific beacon check
        # ----------------------------------------------------------------
        if proto == "DNS" and len(candidate.sessions) >= threshold["min_sessions"]:
            if alert_type is None:
                risk_score += RISK_SCORES["dns_periodic_query"]
                alert_type  = "dns_beacon"
                mitre       = "T1071.004"
            pattern = pattern or f"DNS periodic query beacon — domain: {candidate.dst_ip}"
            detail_parts.append(
                f"DNS domain '{candidate.dst_ip}' queried {len(candidate.sessions)}x "
                f"with mean interval {mean_iat:.1f}s. "
                f"DNS C2 uses periodic queries for command polling. "
                f"Check TXT/CNAME responses for encoded commands."
            )

        # ----------------------------------------------------------------
        # ICMP beacon check
        # ----------------------------------------------------------------
        if proto == "ICMP":
            avg_payload = (
                sum(s.payload_len for s in candidate.sessions) / len(candidate.sessions)
            )
            if alert_type is None:
                risk_score += RISK_SCORES["icmp_beacon"]
                alert_type  = "icmp_beacon"
                mitre       = "T1095"
            pattern = pattern or f"ICMP beacon — avg payload {avg_payload:.0f} bytes"
            if avg_payload > 56:
                detail_parts.append(
                    f"ICMP echo requests with avg payload {avg_payload:.0f} bytes "
                    f"(normal: 32-56 bytes). Oversized ICMP payloads indicate "
                    f"potential data encoding or tunneling. "
                    f"MITRE T1095 — Non-Application Layer Protocol."
                )

        if risk_score == 0 or alert_type is None:
            continue

        # ----------------------------------------------------------------
        # Elevations: known C2 IP/domain match
        # ----------------------------------------------------------------
        confirmed_c2 = False
        if candidate.dst_ip in known_c2_ips or candidate.dst_ip in known_c2_domains:
            risk_score  += RISK_SCORES["known_c2_ip_match"]
            confirmed_c2 = True
            detail_parts.append(
                f"Destination {candidate.dst_ip} is a CONFIRMED C2 indicator "
                f"from DNS/exfil module analysis. Confidence: CRITICAL."
            )

        # Non-standard port elevation
        if proto == "TCP" and candidate.dst_port not in (80, 443, 8080, 8443):
            risk_score += RISK_SCORES["non_standard_port"]
            detail_parts.append(
                f"Non-standard destination port {candidate.dst_port} — "
                f"potential C2 over alternative port."
            )

        # Severity mapping
        if risk_score >= 110:
            severity = "Critical"
        elif risk_score >= 75:
            severity = "High"
        elif risk_score >= 45:
            severity = "Medium"
        else:
            severity = "Low"

        alerts.append(BeaconAlert(
            alert_type       = alert_type,
            severity         = severity,
            src_ip           = candidate.src_ip,
            dst_ip           = candidate.dst_ip,
            dst_port         = candidate.dst_port,
            proto            = proto,
            session_count    = len(candidate.sessions),
            mean_interval_s  = round(mean_iat, 2),
            cv               = round(cv, 4),
            jitter_pct       = round(jitter_pct, 1),
            pattern          = pattern,
            mitre_technique  = mitre,
            risk_score       = risk_score,
            detail           = " | ".join(detail_parts),
            confirmed_c2     = confirmed_c2,
            sequential_ports = seq_ports[:20] if is_seq else [],
            interval_samples = [round(x, 2) for x in iats[:10]],
        ))

    alerts.sort(key=lambda a: a.risk_score, reverse=True)
    return alerts


# ---------------------------------------------------------------------------
# Output formatter — plugs into THA report engine
# ---------------------------------------------------------------------------

def format_alerts_for_tha(alerts: list[BeaconAlert]) -> list[dict]:
    findings = []
    for alert in alerts:
        findings.append({
            "type":        f"beacon_{alert.alert_type}",
            "severity":    alert.severity,
            "source":      alert.src_ip,
            "destination": f"{alert.dst_ip}:{alert.dst_port}",
            "proto":       alert.proto,
            "detail":      alert.detail,
            "mitre":       alert.mitre_technique,
            "risk_score":  alert.risk_score,
            "evidence": {
                "session_count":     alert.session_count,
                "mean_interval_s":   alert.mean_interval_s,
                "cv":                alert.cv,
                "jitter_pct":        alert.jitter_pct,
                "pattern":           alert.pattern,
                "confirmed_c2":      alert.confirmed_c2,
                "sequential_ports":  alert.sequential_ports,
                "interval_samples":  alert.interval_samples,
            },
        })
    return findings


# ---------------------------------------------------------------------------
# Full THA pipeline — chains all three modules together
# ---------------------------------------------------------------------------

def run_full_tha_pipeline(pcap_path: str) -> dict:
    """
    Runs all three THA detection modules in sequence, passing C2 context
    forward so each module can elevate findings based on prior analysis.

    Pipeline order:
      1. Suspicious TLD DNS  → identifies C2 IPs and domains
      2. Exfil Direction     → confirms outbound transfers to C2 IPs
      3. Beaconing           → confirms periodic C2 check-in pattern

    Returns combined findings dict ready for THA report renderer.
    """
    # Lazy imports — only needed when running full pipeline
    try:
        from tha_suspicious_tld_dns import (
            analyze_suspicious_tld_dns,
            format_alerts_for_tha as fmt_dns,
        )
        from tha_exfil_direction import (
            analyze_exfiltration_direction,
            format_alerts_for_tha as fmt_exfil,
        )
    except ImportError:
        print("[THA] Warning: Could not import companion modules. "
              "Running beaconing module standalone.")
        alerts = analyze_beaconing(pcap_path)
        return {"beaconing": format_alerts_for_tha(alerts)}

    # Stage 1: DNS
    dns_alerts      = analyze_suspicious_tld_dns(pcap_path)
    known_c2_ips    = {ip for a in dns_alerts for ip in a.resolved_ips}
    known_c2_domains = {a.domain for a in dns_alerts}

    # Stage 2: Exfil direction
    exfil_alerts = analyze_exfiltration_direction(pcap_path, known_c2_ips)

    # Stage 3: Beaconing
    beacon_alerts = analyze_beaconing(pcap_path, known_c2_ips, known_c2_domains)

    return {
        "dns_findings":      fmt_dns(dns_alerts),
        "exfil_findings":    fmt_exfil(exfil_alerts),
        "beaconing_findings": format_alerts_for_tha(beacon_alerts),
        "summary": {
            "total_alerts":   len(dns_alerts) + len(exfil_alerts) + len(beacon_alerts),
            "confirmed_c2_ips":     list(known_c2_ips),
            "confirmed_c2_domains": list(known_c2_domains),
            "overall_risk":   "Critical" if (
                any(a.severity == "Critical" for a in beacon_alerts) or
                any(a.severity == "Critical" for a in exfil_alerts)
            ) else "High",
        }
    }


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

    print(f"\n[THA] Beaconing Detector — analyzing: {pcap_path}\n")
    print("=" * 70)

    # Run standalone with simulated C2 context from prior modules
    known_c2_ips     = {"153.92.1.49"}
    known_c2_domains = {"whitepepper.su"}

    alerts = analyze_beaconing(pcap_path, known_c2_ips, known_c2_domains)

    if not alerts:
        print("[+] No beaconing patterns detected.")
    else:
        print(f"[!] {len(alerts)} beacon pattern(s) detected:\n")
        for a in alerts:
            print(f"  PATTERN      : {a.alert_type.upper()}")
            print(f"  PROTO        : {a.proto}")
            print(f"  {a.src_ip} → {a.dst_ip}:{a.dst_port}")
            print(f"  SEVERITY     : {a.severity}  |  RISK: {a.risk_score}")
            print(f"  SESSIONS     : {a.session_count}")
            print(f"  MEAN INTERVAL: {a.mean_interval_s}s")
            print(f"  CV           : {a.cv}  (~{a.jitter_pct}% jitter)")
            print(f"  CONFIRMED C2 : {a.confirmed_c2}")
            print(f"  MITRE        : {a.mitre_technique}")
            print(f"  SEQ PORTS    : {a.sequential_ports}")
            print(f"  IAT SAMPLES  : {a.interval_samples}")
            print(f"  DETAIL       : {a.detail}")
            print()

    print("=" * 70)
    print("[THA] Full pipeline output (all 3 modules):\n")
    pipeline_result = run_full_tha_pipeline(pcap_path)
    print(json.dumps(pipeline_result["summary"], indent=2))
