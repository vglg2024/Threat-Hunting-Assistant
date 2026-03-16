"""
THA HTTP / C2 Beaconing Analysis Module — v1.5
Detects C2 beaconing patterns, suspicious user agents, regular interval
callbacks, and HTTP-based exfiltration.
eCTHP-aligned: Network Threat Hunting
MITRE: T1071.001 - Web Protocols C2, T1132 - Data Encoding, T1041 - Exfil over C2
"""

import logging
import math
import re
from collections import defaultdict, Counter

logger = logging.getLogger("THA.http")

# ── Thresholds ──────────────────────────────────────────────
BEACON_MIN_PACKETS      = 10    # minimum connections to same host to analyze
BEACON_JITTER_THRESHOLD = 0.3   # coefficient of variation below this = regular beacon
LARGE_POST_BYTES        = 100_000  # 100KB POST = possible exfiltration
HIGH_FREQ_THRESHOLD     = 30    # connections to same host per capture

# Cobalt Strike default beacon interval
COBALT_STRIKE_INTERVAL_SEC = 60

# Known C2 framework user agents and patterns
SUSPICIOUS_UA_PATTERNS = [
    (r"python-requests", "Python requests library — common in C2/malware"),
    (r"curl/",           "cURL — common in C2 scripts"),
    (r"wget/",           "Wget — common in malware droppers"),
    (r"Go-http-client",  "Go HTTP client — Sliver/Merlin C2"),
    (r"PowerShell",      "PowerShell HTTP — Empire/PS C2"),
    (r"^$",              "Empty user agent — malware/C2"),
    (r"Mozilla/4\.0 \(compatible;\)$", "Stripped UA — possible Cobalt Strike"),
    (r"masscan",         "Masscan — network scanner"),
    (r"zgrab",           "Zgrab — automated scanner"),
    (r"Havoc",           "Havoc C2 framework"),
    (r"Merlin",          "Merlin C2 framework"),
]

# Suspicious HTTP methods rarely used legitimately
SUSPICIOUS_METHODS = {"CONNECT", "TRACE", "TRACK"}

# Common Cobalt Strike URI patterns
COBALT_STRIKE_URIS = [
    r"/jquery-\d+\.\d+\.\d+\.min\.js$",
    r"/____padding_",
    r"/updates\.rss$",
    r"/load$",
    r"/push$",
    r"/pull$",
]

# Benign hosts — whitelist
WHITELIST_HOSTS = {
    "google.com", "microsoft.com", "windows.com", "office.com",
    "windowsupdate.com", "apple.com", "amazonaws.com", "cloudflare.com",
    "akamai.com", "digicert.com", "ocsp.digicert.com",
}


def _coefficient_of_variation(intervals: list) -> float:
    """
    Measure regularity of time intervals.
    Low CoV (< 0.3) = very regular = likely beaconing.
    High CoV = irregular = likely human browsing.
    """
    if len(intervals) < 3:
        return 1.0
    mean = sum(intervals) / len(intervals)
    if mean == 0:
        return 0.0
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    std_dev = math.sqrt(variance)
    return std_dev / mean


class HTTPAnalyzer:
    """
    Analyzes HTTP traffic for C2 beaconing, suspicious user agents,
    and exfiltration patterns.
    """

    def __init__(self):
        self.findings: list[dict] = []
        self.stats: dict = {}

    def analyze(self, packets) -> list[dict]:
        try:
            from scapy.all import IP, TCP, Raw
        except ImportError:
            logger.warning("Scapy not available for HTTP analysis")
            return []

        self.findings = []

        # Filter HTTP packets (port 80, 8080, 8000, 8443)
        http_ports = {80, 8080, 8000, 8008}
        http_packets = []
        for pkt in packets:
            if IP in pkt and TCP in pkt:
                if pkt[TCP].dport in http_ports or pkt[TCP].sport in http_ports:
                    http_packets.append(pkt)

        if not http_packets:
            logger.info("No HTTP packets found")
            self.stats = {"total_http": 0}
            return []

        logger.info(f"Analyzing {len(http_packets)} HTTP packets")

        http_sessions = self._parse_http(http_packets, IP, TCP, Raw)

        self._detect_beaconing(http_sessions)
        self._detect_suspicious_user_agents(http_sessions)
        self._detect_cobalt_strike_patterns(http_sessions)
        self._detect_large_posts(http_sessions)
        self._detect_suspicious_methods(http_sessions)
        self._detect_high_frequency(http_sessions)

        self.stats = {
            "total_http_packets":  len(http_packets),
            "unique_destinations": len(set(s["dst"] for s in http_sessions)),
            "total_sessions":      len(http_sessions),
            "http_findings":       len(self.findings),
        }

        logger.info(f"HTTP analysis complete: {len(self.findings)} findings")
        return self.findings

    def _parse_http(self, packets, IP, TCP, Raw) -> list[dict]:
        """Extract HTTP request metadata from raw packets."""
        sessions = []
        for pkt in packets:
            if Raw not in pkt:
                continue
            try:
                raw = pkt[Raw].load.decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Only process HTTP requests
            first_line = raw.split("\r\n")[0] if "\r\n" in raw else ""
            method_match = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|TRACK)\s+(\S+)\s+HTTP", first_line)
            if not method_match:
                continue

            method = method_match.group(1)
            uri    = method_match.group(2)

            # Extract headers
            ua_match   = re.search(r"User-Agent:\s*(.+?)\r\n", raw, re.IGNORECASE)
            host_match = re.search(r"Host:\s*(.+?)\r\n", raw, re.IGNORECASE)
            len_match  = re.search(r"Content-Length:\s*(\d+)", raw, re.IGNORECASE)

            user_agent   = ua_match.group(1).strip() if ua_match else ""
            host         = host_match.group(1).strip() if host_match else pkt[IP].dst
            content_len  = int(len_match.group(1)) if len_match else 0

            # Get timestamp
            timestamp = float(pkt.time) if hasattr(pkt, "time") else 0.0

            sessions.append({
                "src":         pkt[IP].src,
                "dst":         pkt[IP].dst,
                "host":        host,
                "method":      method,
                "uri":         uri,
                "user_agent":  user_agent,
                "content_len": content_len,
                "timestamp":   timestamp,
                "raw_size":    len(pkt[Raw].load),
            })

        return sessions

    def _detect_beaconing(self, sessions):
        """
        Detect C2 beaconing — regular interval HTTP callbacks.
        Malware checks in with C2 at fixed intervals (with optional jitter).
        Key indicator: low coefficient of variation in connection timing.
        Cobalt Strike default: every 60 seconds.
        """
        # Group by src→dst
        host_sessions = defaultdict(list)
        for s in sessions:
            base_host = ".".join(s["host"].split(".")[-2:])
            if base_host not in WHITELIST_HOSTS:
                host_sessions[(s["src"], s["host"])].append(s["timestamp"])

        for (src, host), timestamps in host_sessions.items():
            if len(timestamps) < BEACON_MIN_PACKETS:
                continue

            timestamps_sorted = sorted(timestamps)
            intervals = [
                timestamps_sorted[i+1] - timestamps_sorted[i]
                for i in range(len(timestamps_sorted) - 1)
                if timestamps_sorted[i+1] - timestamps_sorted[i] > 0
            ]

            if not intervals:
                continue

            cov = _coefficient_of_variation(intervals)
            avg_interval = sum(intervals) / len(intervals)

            if cov < BEACON_JITTER_THRESHOLD:
                # Check for Cobalt Strike default interval
                cs_match = abs(avg_interval - COBALT_STRIKE_INTERVAL_SEC) < 5
                severity = "Critical" if cs_match else "High"

                self.findings.append({
                    "type":         "http_beaconing",
                    "severity":     severity,
                    "src":          src,
                    "host":         host,
                    "connection_count": len(timestamps),
                    "avg_interval_sec": round(avg_interval, 1),
                    "regularity_cov":   round(cov, 3),
                    "cobalt_strike_match": cs_match,
                    "detail": (
                        f"C2 beaconing detected: {src} → {host} "
                        f"({len(timestamps)} connections, avg interval {avg_interval:.1f}s, CoV {cov:.3f}). "
                        f"{'Interval matches Cobalt Strike default (60s). ' if cs_match else ''}"
                        f"Low CoV indicates regular, automated callbacks — not human browsing."
                    ),
                    "mitre": "T1071.001 - Application Layer Protocol: Web Protocols",
                    "recommendation": (
                        "Isolate source host. Capture full session payload. "
                        "Check for Cobalt Strike, Meterpeter, or other C2 framework signatures. "
                        "Block destination on firewall."
                    ),
                })

    def _detect_suspicious_user_agents(self, sessions):
        """
        Detect suspicious or anomalous HTTP User-Agent strings.
        Malware often uses:
        - Tool default UAs (python-requests, curl, wget)
        - Empty UA strings
        - Known C2 framework UA signatures
        """
        flagged_uas = set()
        for s in sessions:
            ua = s["user_agent"]
            host = s["host"]
            base_host = ".".join(host.split(".")[-2:])
            if base_host in WHITELIST_HOSTS:
                continue

            for pattern, description in SUSPICIOUS_UA_PATTERNS:
                if re.search(pattern, ua, re.IGNORECASE):
                    key = (s["src"], ua[:50])
                    if key not in flagged_uas:
                        flagged_uas.add(key)
                        self.findings.append({
                            "type":       "suspicious_user_agent",
                            "severity":   "High",
                            "src":        s["src"],
                            "dst":        s["dst"],
                            "host":       host,
                            "user_agent": ua or "(empty)",
                            "detail": (
                                f"Suspicious User-Agent from {s['src']} to {host}: "
                                f"'{ua or '(empty)'}' — {description}."
                            ),
                            "mitre": "T1071.001 - Application Layer Protocol: Web Protocols",
                            "recommendation": "Investigate source host. Check for malware or unauthorized tools.",
                        })
                    break

    def _detect_cobalt_strike_patterns(self, sessions):
        """
        Detect Cobalt Strike HTTP C2 patterns.
        CS uses specific URI patterns, GET/POST timing pairs,
        and often masquerades as legitimate web traffic.
        """
        for s in sessions:
            uri = s["uri"]
            for pattern in COBALT_STRIKE_URIS:
                if re.search(pattern, uri, re.IGNORECASE):
                    self.findings.append({
                        "type":     "cobalt_strike_uri",
                        "severity": "Critical",
                        "src":      s["src"],
                        "dst":      s["dst"],
                        "uri":      uri,
                        "detail": (
                            f"Cobalt Strike URI pattern detected: {uri} from {s['src']} → {s['dst']}. "
                            f"This URI pattern matches known Cobalt Strike malleable C2 profiles."
                        ),
                        "mitre": "T1071.001 - Application Layer Protocol: Web Protocols",
                        "recommendation": (
                            "High confidence Cobalt Strike C2. Isolate source immediately. "
                            "Capture full HTTP session. Initiate incident response."
                        ),
                    })
                    break

    def _detect_large_posts(self, sessions):
        """
        Detect unusually large HTTP POST requests.
        Large POSTs may indicate data exfiltration — attacker
        sending stolen data back to C2 via HTTP POST.
        """
        for s in sessions:
            if s["method"] == "POST" and s["content_len"] > LARGE_POST_BYTES:
                mb = s["content_len"] / 1_000_000
                base_host = ".".join(s["host"].split(".")[-2:])
                if base_host not in WHITELIST_HOSTS:
                    self.findings.append({
                        "type":        "large_http_post",
                        "severity":    "High",
                        "src":         s["src"],
                        "dst":         s["dst"],
                        "host":        s["host"],
                        "uri":         s["uri"],
                        "content_len": s["content_len"],
                        "detail": (
                            f"Large HTTP POST ({mb:.1f} MB) from {s['src']} to {s['host']}{s['uri']}. "
                            f"Possible data exfiltration via HTTP POST."
                        ),
                        "mitre": "T1041 - Exfiltration Over C2 Channel",
                        "recommendation": "Inspect POST body. Identify data type. Check for compression or encoding.",
                    })

    def _detect_suspicious_methods(self, sessions):
        """
        Detect suspicious HTTP methods rarely seen in legitimate traffic.
        CONNECT is used for proxy tunneling, TRACE for XST attacks.
        """
        for s in sessions:
            if s["method"] in SUSPICIOUS_METHODS:
                self.findings.append({
                    "type":     "suspicious_http_method",
                    "severity": "Medium",
                    "src":      s["src"],
                    "dst":      s["dst"],
                    "method":   s["method"],
                    "uri":      s["uri"],
                    "detail": (
                        f"Suspicious HTTP method {s['method']} from {s['src']} to {s['dst']}{s['uri']}. "
                        f"CONNECT is used for proxy tunneling, TRACE for cross-site tracing attacks."
                    ),
                    "mitre": "T1090 - Proxy",
                    "recommendation": "Block TRACE/TRACK at web server. Investigate CONNECT for proxy abuse.",
                })

    def _detect_high_frequency(self, sessions):
        """
        Detect high-frequency connections to same destination.
        Complements beaconing detection for cases where timing
        data is unavailable.
        """
        connection_counts = Counter((s["src"], s["host"]) for s in sessions)
        for (src, host), count in connection_counts.items():
            base_host = ".".join(host.split(".")[-2:])
            if base_host in WHITELIST_HOSTS:
                continue
            if count >= HIGH_FREQ_THRESHOLD:
                self.findings.append({
                    "type":     "http_high_frequency",
                    "severity": "Medium",
                    "src":      src,
                    "host":     host,
                    "count":    count,
                    "detail": (
                        f"High-frequency HTTP: {src} made {count} connections to {host}. "
                        f"Possible C2 beaconing or automated tool."
                    ),
                    "mitre": "T1071.001 - Application Layer Protocol: Web Protocols",
                    "recommendation": "Check connection timing. Investigate user agent. Review destination reputation.",
                })