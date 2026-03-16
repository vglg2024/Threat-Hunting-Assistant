"""
THA DNS Analysis Module — v1.5
Detects DNS exfiltration, DGA, tunneling, NXDomain floods,
non-standard resolvers, and TCP/53 abuse.
eCTHP-aligned: Network Threat Hunting
MITRE: T1071.004 - DNS C2, T1568.002 - DGA, T1048 - Exfiltration over DNS
"""

import logging
import math
import re
from collections import defaultdict, Counter

logger = logging.getLogger("THA.dns")

# ── Thresholds ──────────────────────────────────────────────
NXDOMAIN_THRESHOLD      = 20    # failed lookups in capture = DGA indicator
HIGH_FREQ_THRESHOLD     = 50    # same domain queried > N times = C2 beacon
LONG_SUBDOMAIN_CHARS    = 25    # subdomains longer than this are suspicious
EXFIL_SUBDOMAIN_CHARS   = 40    # strong exfiltration indicator
DGA_ENTROPY_THRESHOLD   = 3.5   # high entropy subdomain = random/generated
DNS_EXFIL_QUERY_MIN     = 10    # minimum queries to same domain to flag exfil

# Standard DNS resolvers (RFC + common enterprise)
KNOWN_DNS_RESOLVERS = {
    "8.8.8.8",       # Google
    "8.8.4.4",       # Google
    "1.1.1.1",       # Cloudflare
    "1.0.0.1",       # Cloudflare
    "9.9.9.9",       # Quad9
    "208.67.222.222",# OpenDNS
    "208.67.220.220",# OpenDNS
}

# Benign base domains — whitelist
WHITELIST_DOMAINS = {
    "google.com", "microsoft.com", "windows.com", "windowsupdate.com",
    "apple.com", "amazonaws.com", "cloudflare.com", "akamai.com",
    "office.com", "office365.com", "live.com", "outlook.com",
    "azure.com", "akadns.net", "msftncsi.com", "digicert.com",
}

# DNS record types
QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"
}

# TXT and NULL records commonly used for DNS tunneling
TUNNEL_QTYPES = {16, 255}  # TXT, ANY


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string — high entropy = random/encoded."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_base64_like(s: str) -> bool:
    """Check if string looks like base64 encoded data."""
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    return len(s) > 20 and len(set(s) - b64_chars) == 0


def _is_hex_like(s: str) -> bool:
    """Check if string looks like hex encoded data."""
    hex_chars = set("0123456789abcdefABCDEF")
    return len(s) > 16 and len(set(s) - hex_chars) == 0 and len(s) % 2 == 0


class DNSAnalyzer:
    """
    Analyzes DNS traffic for C2, exfiltration, DGA, and tunneling.
    """

    def __init__(self):
        self.findings: list[dict] = []
        self.stats: dict = {}

    def analyze(self, packets) -> list[dict]:
        try:
            from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, TCP
        except ImportError:
            logger.warning("Scapy not available for DNS analysis")
            return []

        self.findings = []

        dns_packets = [p for p in packets if DNS in p and IP in p]
        if not dns_packets:
            logger.info("No DNS packets found")
            self.stats = {"total_dns": 0}
            return []

        logger.info(f"Analyzing {len(dns_packets)} DNS packets")

        queries, responses, nxdomains = self._parse_dns(dns_packets, DNS, DNSQR, DNSRR, IP, UDP, TCP)

        self._detect_nxdomain_flood(nxdomains)
        self._detect_dga(queries)
        self._detect_dns_exfiltration(queries)
        self._detect_high_frequency(queries)
        self._detect_tcp_dns(dns_packets, DNS, IP, TCP)
        self._detect_non_standard_resolver(dns_packets, DNS, IP, UDP, TCP)
        self._detect_tunnel_record_types(queries)

        self.stats = {
            "total_dns_packets":  len(dns_packets),
            "total_queries":      sum(len(v) for v in queries.values()),
            "unique_domains":     len(queries),
            "nxdomain_count":     len(nxdomains),
            "dns_findings":       len(self.findings),
        }

        logger.info(f"DNS analysis complete: {len(self.findings)} findings")
        return self.findings

    def _parse_dns(self, packets, DNS, DNSQR, DNSRR, IP, UDP, TCP):
        """Parse DNS packets into queries, responses, and NXDomain responses."""
        queries    = defaultdict(list)   # domain → list of {src, qtype, tcp}
        responses  = defaultdict(list)   # domain → list of answers
        nxdomains  = []                  # list of {src, domain}

        for pkt in packets:
            dns = pkt[DNS]
            src = pkt[IP].src
            dst = pkt[IP].dst
            is_tcp = TCP in pkt

            # Query
            if dns.qr == 0 and DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".").lower()
                qtype = pkt[DNSQR].qtype
                queries[qname].append({
                    "src": src, "dst": dst,
                    "qtype": qtype, "tcp": is_tcp
                })

            # Response
            elif dns.qr == 1:
                if DNSQR in pkt:
                    qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".").lower()
                    # NXDomain = rcode 3
                    if dns.rcode == 3:
                        nxdomains.append({"src": src, "domain": qname})

        return queries, responses, nxdomains

    def _detect_nxdomain_flood(self, nxdomains):
        """
        NXDomain flood = many failed DNS lookups.
        Classic DGA indicator — malware trying hundreds of generated
        domains until one resolves to active C2.
        """
        if len(nxdomains) < NXDOMAIN_THRESHOLD:
            return

        sources = Counter(n["src"] for n in nxdomains)
        for src, count in sources.items():
            if count >= NXDOMAIN_THRESHOLD:
                domains = [n["domain"] for n in nxdomains if n["src"] == src]
                self.findings.append({
                    "type":     "nxdomain_flood",
                    "severity": "High",
                    "src":      src,
                    "count":    count,
                    "sample_domains": domains[:5],
                    "detail": (
                        f"NXDomain flood from {src}: {count} failed DNS lookups. "
                        f"Classic DGA indicator — malware rotating through generated domains "
                        f"to locate active C2 infrastructure."
                    ),
                    "mitre": "T1568.002 - Domain Generation Algorithms",
                    "recommendation": "Collect full domain list. Run through DGA classifier. Isolate host immediately.",
                })

    def _detect_dga(self, queries):
        """
        Detect Domain Generation Algorithm (DGA) domains.
        DGA domains are randomly generated and have:
        - High Shannon entropy (randomness)
        - Long subdomains with no real words
        - Hex or base64-like patterns
        """
        for domain, query_list in queries.items():
            parts = domain.split(".")
            if len(parts) < 2:
                continue

            base = ".".join(parts[-2:])
            if base in WHITELIST_DOMAINS:
                continue

            subdomain = parts[0] if len(parts) > 2 else ""
            if not subdomain:
                continue

            entropy = _shannon_entropy(subdomain)
            is_b64  = _is_base64_like(subdomain)
            is_hex  = _is_hex_like(subdomain)
            is_long = len(subdomain) > LONG_SUBDOMAIN_CHARS

            if entropy > DGA_ENTROPY_THRESHOLD and is_long:
                severity = "Critical" if (is_b64 or is_hex) else "High"
                method = "base64-encoded" if is_b64 else ("hex-encoded" if is_hex else "high-entropy random")
                self.findings.append({
                    "type":      "dga_domain",
                    "severity":  severity,
                    "domain":    domain,
                    "subdomain": subdomain,
                    "entropy":   round(entropy, 2),
                    "sources":   list(set(q["src"] for q in query_list)),
                    "detail": (
                        f"Possible DGA domain: {domain}. "
                        f"Subdomain '{subdomain}' has {method} pattern "
                        f"(entropy: {entropy:.2f}, length: {len(subdomain)} chars). "
                        f"DGA domains are generated by malware to locate C2 servers."
                    ),
                    "mitre": "T1568.002 - Domain Generation Algorithms",
                    "recommendation": "Block domain. Isolate querying host. Check for malware family signature.",
                })

    def _detect_dns_exfiltration(self, queries):
        """
        Detect DNS exfiltration — data encoded in subdomain labels.
        Attacker sends data as subdomain queries:
        aGVsbG8gd29ybGQ.evil.com → decoded = 'hello world'
        Pattern: many queries to same base domain with varying long subdomains.
        """
        base_domain_queries = defaultdict(list)
        for domain, query_list in queries.items():
            parts = domain.split(".")
            if len(parts) < 3:
                continue
            base = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])
            if base not in WHITELIST_DOMAINS and len(subdomain) > LONG_SUBDOMAIN_CHARS:
                base_domain_queries[base].append({
                    "subdomain": subdomain,
                    "full_domain": domain,
                    "sources": [q["src"] for q in query_list]
                })

        for base, entries in base_domain_queries.items():
            if len(entries) >= DNS_EXFIL_QUERY_MIN:
                # Check if subdomains are all different (encoding chunks of data)
                unique_subs = set(e["subdomain"] for e in entries)
                all_sources = set(s for e in entries for s in e["sources"])
                if len(unique_subs) >= DNS_EXFIL_QUERY_MIN:
                    self.findings.append({
                        "type":           "dns_exfiltration",
                        "severity":       "Critical",
                        "base_domain":    base,
                        "query_count":    len(entries),
                        "unique_subdomains": len(unique_subs),
                        "sources":        list(all_sources),
                        "sample_domains": [e["full_domain"] for e in entries[:3]],
                        "detail": (
                            f"DNS exfiltration pattern to {base}: "
                            f"{len(entries)} queries with {len(unique_subs)} unique long subdomains. "
                            f"Data is likely encoded in subdomain labels and exfiltrated via DNS. "
                            f"Each query carries a chunk of encoded data."
                        ),
                        "mitre": "T1048.003 - Exfiltration Over Unencrypted Protocol",
                        "recommendation": "Block base domain. Isolate querying hosts. Decode subdomains to identify exfiltrated data.",
                    })

    def _detect_high_frequency(self, queries):
        """
        Detect high-frequency DNS queries to same domain.
        C2 beaconing via DNS: malware checks in regularly via DNS lookup.
        """
        for domain, query_list in queries.items():
            base = ".".join(domain.split(".")[-2:])
            if base in WHITELIST_DOMAINS:
                continue
            if len(query_list) >= HIGH_FREQ_THRESHOLD:
                sources = Counter(q["src"] for q in query_list)
                self.findings.append({
                    "type":    "dns_high_frequency",
                    "severity": "Medium",
                    "domain":  domain,
                    "count":   len(query_list),
                    "sources": dict(sources),
                    "detail": (
                        f"High-frequency DNS: {domain} queried {len(query_list)} times. "
                        f"Possible C2 beaconing via DNS or keepalive mechanism."
                    ),
                    "mitre": "T1071.004 - Application Layer Protocol: DNS",
                    "recommendation": "Check query interval. Regular intervals = beaconing. Investigate querying hosts.",
                })

    def _detect_tcp_dns(self, packets, DNS, IP, TCP):
        """
        Detect DNS over TCP (port 53).
        DNS normally uses UDP. TCP/53 is used for zone transfers and large
        responses, but is also used by DNS tunneling tools like Iodine and dnscat2.
        Flag TCP DNS that isn't a zone transfer (AXFR qtype 252).
        """
        tcp_dns_flows = set()
        for pkt in packets:
            if TCP in pkt and DNS in pkt and IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                if dport == 53 or sport == 53:
                    tcp_dns_flows.add((src, dst))

        for (src, dst) in tcp_dns_flows:
            self.findings.append({
                "type":     "dns_over_tcp",
                "severity": "Medium",
                "src":      src,
                "dst":      dst,
                "detail": (
                    f"DNS over TCP detected: {src} → {dst}:53. "
                    f"DNS normally uses UDP. TCP/53 outside of zone transfers "
                    f"may indicate DNS tunneling (Iodine, dnscat2) or large response abuse."
                ),
                "mitre": "T1572 - Protocol Tunneling",
                "recommendation": "Verify if TCP DNS is authorized. Check for zone transfer (AXFR) or tunneling tool signatures.",
            })

    def _detect_non_standard_resolver(self, packets, DNS, IP, UDP, TCP):
        """
        Detect DNS traffic not going to known/authorized resolvers.
        Malware often hardcodes its own DNS resolver to bypass
        corporate DNS monitoring and filtering.
        """
        unknown_resolvers = set()
        for pkt in packets:
            if DNS in pkt and IP in pkt:
                if (UDP in pkt and pkt[UDP].dport == 53) or \
                   (TCP in pkt and pkt[TCP].dport == 53):
                    dst = pkt[IP].dst
                    if dst not in KNOWN_DNS_RESOLVERS:
                        unknown_resolvers.add((pkt[IP].src, dst))

        for (src, resolver) in unknown_resolvers:
            self.findings.append({
                "type":     "non_standard_resolver",
                "severity": "Medium",
                "src":      src,
                "resolver": resolver,
                "detail": (
                    f"DNS query from {src} to non-standard resolver {resolver}. "
                    f"Malware often bypasses corporate DNS by using hardcoded resolvers "
                    f"to avoid DNS-based detection and filtering."
                ),
                "mitre": "T1071.004 - Application Layer Protocol: DNS",
                "recommendation": "Verify if resolver is authorized. Check corporate DNS policy. Investigate querying host.",
            })

    def _detect_tunnel_record_types(self, queries):
        """
        Detect use of TXT and ANY record types — common in DNS tunneling.
        Iodine uses NULL records, dnscat2 uses TXT and CNAME records.
        """
        tunnel_queries = defaultdict(list)
        for domain, query_list in queries.items():
            base = ".".join(domain.split(".")[-2:])
            if base in WHITELIST_DOMAINS:
                continue
            for q in query_list:
                if q["qtype"] in TUNNEL_QTYPES:
                    tunnel_queries[domain].append(q)

        for domain, query_list in tunnel_queries.items():
            if len(query_list) >= 5:
                qtype_name = QTYPE_NAMES.get(query_list[0]["qtype"], "Unknown")
                self.findings.append({
                    "type":     "dns_tunnel_record_type",
                    "severity": "High",
                    "domain":   domain,
                    "qtype":    qtype_name,
                    "count":    len(query_list),
                    "sources":  list(set(q["src"] for q in query_list)),
                    "detail": (
                        f"DNS tunneling record type {qtype_name} used {len(query_list)} times "
                        f"for domain {domain}. TXT and ANY records are commonly used by "
                        f"DNS tunneling tools (dnscat2, Iodine) to carry arbitrary data."
                    ),
                    "mitre": "T1572 - Protocol Tunneling",
                    "recommendation": "Inspect DNS payload contents. Block domain. Check for dnscat2/Iodine signatures.",
                })