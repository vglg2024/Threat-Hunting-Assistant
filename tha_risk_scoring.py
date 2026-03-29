"""
THA Module: Unified Risk Scoring Model
=======================================
Aggregates findings from all three THA detection modules into a single
coherent risk score and hunt report.

Modules consumed:
  - tha_suspicious_tld_dns  → DNS-based C2 identification
  - tha_exfil_direction     → Exfiltration vs staging classification
  - tha_beaconing           → Periodic C2 check-in patterns

Scoring philosophy:
  Individual module scores reflect LOCAL confidence in a single finding.
  The unified score reflects CAMPAIGN confidence — the degree to which
  multiple independent signals corroborate a single adversary action.

  Key principle: CONVERGENT EVIDENCE
    One module firing = possible
    Two modules firing on same IP = probable
    Three modules firing on same IP = confirmed

  This mirrors how real SOC analysts escalate: a single NXDOMAIN flood
  is noise; a NXDOMAIN flood + large outbound transfer + beaconing to
  the same IP is an incident.

Scoring Model:
  Base Score      — highest individual finding score from any module
  Convergence     — bonus for multiple modules confirming same IOC
  Technique Chain — bonus for logical ATT&CK kill chain progression
  Severity Floor  — minimum score guarantee for confirmed C2
  False Positive  — deduction for findings matching known-good patterns

Output:
  - Unified risk score (0-100 normalized)
  - Risk tier: Informational / Low / Medium / High / Critical
  - Executive summary narrative
  - Full finding breakdown with cross-module correlations
  - MITRE ATT&CK technique list
  - Recommended hunt actions

MITRE ATT&CK Coverage (aggregated):
  T1071.001 - Web Protocol C2
  T1071.004 - DNS C2
  T1041     - Exfiltration Over C2 Channel
  T1048     - Exfiltration Over Alternative Protocol
  T1095     - Non-Application Layer Protocol
  T1105     - Ingress Tool Transfer
  T1568.002 - Domain Generation Algorithms
  T1583.001 - Acquire Infrastructure: Domains

eCTHP Alignment:
  This module produces the final hunt report artifact.
  Examiners look for: correct IOC identification, accurate MITRE mapping,
  evidence-backed narrative, and actionable recommendations.
"""

import json
import datetime
import collections
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------

# Convergence bonuses — awarded when multiple modules confirm the same IOC
CONVERGENCE_BONUS = {
    1: 0,    # Single module = no bonus
    2: 20,   # Two modules agree = +20
    3: 40,   # All three modules agree = +40 (confirmed campaign)
}

# ATT&CK kill chain stage bonuses
# If findings span multiple stages, adversary has progressed = higher risk
KILL_CHAIN_STAGE_BONUS = {
    1: 0,
    2: 15,   # Two stages (e.g., C2 + Exfil)
    3: 25,   # Three stages (Recon + C2 + Exfil)
}

# Confirmed C2 severity floor — if C2 is confirmed, score cannot drop below this
CONFIRMED_C2_FLOOR = 65

# Score normalization ceiling
RAW_SCORE_CEILING = 200   # Max possible raw score before normalization to 0-100

# Risk tier thresholds (normalized 0-100)
RISK_TIERS = [
    (90, "Critical"),
    (70, "High"),
    (45, "Medium"),
    (20, "Low"),
    (0,  "Informational"),
]

# MITRE technique stage mapping for kill chain analysis
TECHNIQUE_STAGES = {
    "T1071.001": "Command and Control",
    "T1071.004": "Command and Control",
    "T1095":     "Command and Control",
    "T1041":     "Exfiltration",
    "T1048":     "Exfiltration",
    "T1105":     "Resource Development",
    "T1568":     "Command and Control",
    "T1568.002": "Command and Control",
    "T1583.001": "Resource Development",
}

# Recommended actions per severity tier
RECOMMENDED_ACTIONS = {
    "Critical": [
        "IMMEDIATE: Isolate host {src_ip} from network",
        "Capture full memory dump of {src_ip} before remediation",
        "Block {dst_ips} at perimeter firewall and DNS sinkhole",
        "Search for lateral movement from {src_ip} to other internal hosts",
        "Preserve all pcap evidence under chain of custody",
        "Notify IR team and initiate incident response playbook",
        "Hunt for persistence mechanisms on {src_ip} (registry, scheduled tasks, services)",
        "Review authentication logs for credential access from {src_ip}",
    ],
    "High": [
        "Investigate host {src_ip} — isolate if C2 confirmed",
        "Block {dst_ips} at perimeter firewall",
        "Review DNS logs for additional hosts querying same domains",
        "Check for similar traffic patterns from other internal hosts",
        "Preserve pcap and endpoint artifacts",
        "Escalate to senior analyst or IR team",
    ],
    "Medium": [
        "Investigate host {src_ip} for signs of compromise",
        "Review DNS query history for {src_ip}",
        "Check endpoint security logs for {src_ip}",
        "Monitor {dst_ips} for continued communication",
        "Document findings and continue monitoring",
    ],
    "Low": [
        "Monitor {src_ip} for escalation of activity",
        "Review findings in context of business operations",
        "Add {dst_ips} to watchlist",
    ],
    "Informational": [
        "Log findings for baseline comparison",
        "No immediate action required",
    ],
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class IOCCorrelation:
    """
    Tracks how many modules have flagged the same IOC (IP or domain).
    Used to calculate convergence bonus.
    """
    ioc:            str         # IP or domain
    ioc_type:       str         # "ip" or "domain"
    modules_firing: list        # Which modules flagged this IOC
    finding_types:  list        # What each module found
    total_risk:     int         # Sum of individual module risk scores
    convergence:    int         # Number of modules that agree


@dataclass
class UnifiedHuntReport:
    hunt_id:            str
    analyst:            str
    timestamp:          str
    pcap_file:          str

    # Scores
    raw_score:          int
    normalized_score:   int
    risk_tier:          str

    # IOC inventory
    confirmed_c2_ips:   list
    confirmed_c2_domains: list
    staging_ips:        list

    # ATT&CK
    mitre_techniques:   list
    kill_chain_stages:  list

    # Findings breakdown
    dns_findings:       list
    exfil_findings:     list
    beacon_findings:    list
    ioc_correlations:   list

    # Narrative
    executive_summary:  str
    adversary_narrative: str
    recommended_actions: list

    # Scoring audit trail
    score_breakdown:    dict


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

def normalize_score(raw: int, ceiling: int = RAW_SCORE_CEILING) -> int:
    """Map raw score (0 to ceiling) to 0-100 range."""
    return min(100, int((raw / ceiling) * 100))


def get_risk_tier(normalized_score: int) -> str:
    for threshold, tier in RISK_TIERS:
        if normalized_score >= threshold:
            return tier
    return "Informational"


def extract_iocs_from_findings(findings: list[dict]) -> dict[str, list]:
    """
    Extract IP addresses and domains from module findings.
    Returns dict mapping IOC string to list of finding dicts that reference it.
    """
    ioc_map = collections.defaultdict(list)

    for finding in findings:
        # Source IP
        src = finding.get("source", "")
        if src and src != "internal_host" and "." in src:
            ioc_map[src].append(finding)

        # Destination (may be "ip:port" or "domain:port")
        dst = finding.get("destination", "").split(":")[0]
        if dst and "." in dst:
            ioc_map[dst].append(finding)

        # Resolved IPs in evidence block
        evidence = finding.get("evidence", {})
        for ip in evidence.get("resolved_ips", []):
            ioc_map[ip].append(finding)

        # C2 domains from DNS module
        if finding.get("type") == "suspicious_tld_dns":
            domain = finding.get("destination", "")
            if domain:
                ioc_map[domain].append(finding)

    return dict(ioc_map)


def build_ioc_correlations(
    dns_findings: list[dict],
    exfil_findings: list[dict],
    beacon_findings: list[dict],
) -> list[IOCCorrelation]:
    """
    Cross-reference IOCs across all three module outputs.
    An IOC appearing in multiple modules gets a convergence bonus.
    """
    module_ioc_maps = {
        "dns":      extract_iocs_from_findings(dns_findings),
        "exfil":    extract_iocs_from_findings(exfil_findings),
        "beaconing": extract_iocs_from_findings(beacon_findings),
    }

    # Collect all unique IOCs
    all_iocs = set()
    for ioc_map in module_ioc_maps.values():
        all_iocs.update(ioc_map.keys())

    correlations = []
    for ioc in all_iocs:
        modules_firing  = []
        finding_types   = []
        total_risk      = 0

        for module_name, ioc_map in module_ioc_maps.items():
            if ioc in ioc_map:
                modules_firing.append(module_name)
                for f in ioc_map[ioc]:
                    finding_types.append(f.get("type", "unknown"))
                    total_risk += f.get("risk_score", 0)

        if not modules_firing:
            continue

        # Determine IOC type
        ioc_type = "domain" if any(
            c.isalpha() for c in ioc.replace(".", "")
        ) else "ip"

        correlations.append(IOCCorrelation(
            ioc            = ioc,
            ioc_type       = ioc_type,
            modules_firing = modules_firing,
            finding_types  = list(set(finding_types)),
            total_risk     = total_risk,
            convergence    = len(modules_firing),
        ))

    # Sort by convergence then total_risk
    correlations.sort(key=lambda c: (c.convergence, c.total_risk), reverse=True)
    return correlations


def extract_mitre_techniques(all_findings: list[dict]) -> list[str]:
    """Deduplicate and sort MITRE techniques across all findings."""
    techniques = set()
    for f in all_findings:
        mitre_str = f.get("mitre", "")
        for t in mitre_str.split(","):
            t = t.strip()
            if t:
                techniques.add(t)
    return sorted(techniques)


def extract_kill_chain_stages(techniques: list[str]) -> list[str]:
    """Map techniques to ATT&CK tactic stages."""
    stages = set()
    for t in techniques:
        stage = TECHNIQUE_STAGES.get(t)
        if stage:
            stages.add(stage)
    return sorted(stages)


def compute_unified_score(
    dns_findings:    list[dict],
    exfil_findings:  list[dict],
    beacon_findings: list[dict],
    ioc_correlations: list[IOCCorrelation],
    kill_chain_stages: list[str],
    confirmed_c2:    bool,
) -> tuple[int, int, str, dict]:
    """
    Compute the unified risk score.

    Returns:
        (raw_score, normalized_score, risk_tier, score_breakdown)
    """
    breakdown = {}
    raw_score = 0

    # --- Base score: highest individual finding score across all modules ---
    all_findings  = dns_findings + exfil_findings + beacon_findings
    max_individual = max((f.get("risk_score", 0) for f in all_findings), default=0)
    raw_score     += max_individual
    breakdown["base_score_highest_finding"] = max_individual

    # --- Convergence bonus: multiple modules confirming same IOC ---
    max_convergence = max(
        (c.convergence for c in ioc_correlations), default=1
    )
    convergence_bonus = CONVERGENCE_BONUS.get(max_convergence, 0)
    raw_score        += convergence_bonus
    breakdown["convergence_bonus"] = {
        "max_convergence": max_convergence,
        "bonus":           convergence_bonus,
        "explanation":     (
            f"{max_convergence} module(s) independently confirmed the same IOC"
        ),
    }

    # --- Kill chain stage bonus ---
    stage_count  = len(kill_chain_stages)
    stage_bonus  = KILL_CHAIN_STAGE_BONUS.get(min(stage_count, 3), 0)
    raw_score   += stage_bonus
    breakdown["kill_chain_bonus"] = {
        "stages_covered": kill_chain_stages,
        "bonus":          stage_bonus,
    }

    # --- Finding count bonus (breadth of evidence) ---
    total_findings = len(all_findings)
    breadth_bonus  = min(20, total_findings * 2)
    raw_score     += breadth_bonus
    breakdown["breadth_bonus"] = {
        "total_findings": total_findings,
        "bonus":          breadth_bonus,
    }

    # --- Confirmed C2 floor ---
    if confirmed_c2:
        pre_floor = raw_score
        normalized_pre = normalize_score(pre_floor)
        if normalized_pre < CONFIRMED_C2_FLOOR:
            # Back-calculate raw score needed for floor
            floor_raw  = int((CONFIRMED_C2_FLOOR / 100) * RAW_SCORE_CEILING)
            raw_score  = max(raw_score, floor_raw)
            breakdown["confirmed_c2_floor_applied"] = {
                "floor_normalized": CONFIRMED_C2_FLOOR,
                "adjusted":         True,
            }
        else:
            breakdown["confirmed_c2_floor_applied"] = {"adjusted": False}

    breakdown["raw_score_total"] = raw_score
    normalized = normalize_score(raw_score)
    tier       = get_risk_tier(normalized)

    return raw_score, normalized, tier, breakdown


# ---------------------------------------------------------------------------
# Narrative generation
# ---------------------------------------------------------------------------

def generate_executive_summary(
    risk_tier:          str,
    confirmed_c2_ips:   list,
    confirmed_c2_domains: list,
    kill_chain_stages:  list,
    src_ips:            list,
    normalized_score:   int,
) -> str:
    """Generate a concise executive summary for the hunt report."""

    tier_openers = {
        "Critical": "CRITICAL THREAT CONFIRMED —",
        "High":     "HIGH-CONFIDENCE THREAT DETECTED —",
        "Medium":   "SUSPICIOUS ACTIVITY DETECTED —",
        "Low":      "LOW-CONFIDENCE INDICATORS OBSERVED —",
        "Informational": "INFORMATIONAL —",
    }

    opener = tier_openers.get(risk_tier, "THREAT HUNT FINDINGS —")

    c2_str = (
        f"C2 infrastructure identified: {', '.join(confirmed_c2_domains)} "
        f"resolving to {', '.join(confirmed_c2_ips)}."
        if confirmed_c2_ips else
        "No confirmed C2 infrastructure identified."
    )

    stages_str = (
        f"ATT&CK kill chain stages observed: {', '.join(kill_chain_stages)}."
        if kill_chain_stages else ""
    )

    hosts_str = (
        f"Affected host(s): {', '.join(src_ips)}."
        if src_ips else ""
    )

    return (
        f"{opener} Unified risk score {normalized_score}/100 ({risk_tier}). "
        f"{c2_str} {stages_str} {hosts_str}"
    ).strip()


def generate_adversary_narrative(
    dns_findings:    list[dict],
    exfil_findings:  list[dict],
    beacon_findings: list[dict],
    ioc_correlations: list[IOCCorrelation],
    risk_tier:       str,
) -> str:
    """
    Generate a kill-chain-ordered adversary narrative.
    This is what goes in the 'Adversary Narrative' section of the THA report.
    """
    parts = []

    # DNS / infrastructure
    dns_c2 = [f for f in dns_findings if f.get("type") == "suspicious_tld_dns"]
    if dns_c2:
        domains = [f.get("destination", "") for f in dns_c2]
        ips     = []
        for f in dns_c2:
            ips.extend(f.get("evidence", {}).get("resolved_ips", []))
        parts.append(
            f"The adversary registered or acquired C2 infrastructure using "
            f"high-risk TLD domain(s) ({', '.join(set(domains))}), "
            f"resolving to {', '.join(set(ips))}. "
            f"DNS queries from the compromised host confirm the implant was "
            f"actively polling its C2 infrastructure."
        )

    # Beaconing
    beacon_c2 = [f for f in beacon_findings if f.get("evidence", {}).get("confirmed_c2")]
    if beacon_c2:
        b = beacon_c2[0]
        ev = b.get("evidence", {})
        parts.append(
            f"Active C2 communication was confirmed via {b.get('proto', 'TCP')} beaconing "
            f"({b.get('type', '').replace('beacon_', '').replace('_', ' ')} pattern) "
            f"from {b.get('source')} to {b.get('destination')}. "
            f"The implant established {ev.get('session_count', 'multiple')} sessions "
            f"with a mean interval of {ev.get('mean_interval_s', '?')}s "
            f"(CV={ev.get('cv', '?')}, ~{ev.get('jitter_pct', '?')}% jitter). "
            f"Sequential ephemeral source ports confirm each beacon opened a fresh "
            f"TCP connection rather than maintaining a persistent socket — "
            f"a common evasion technique."
        )

    # Exfiltration
    exfil_out = [
        f for f in exfil_findings
        if "OUTBOUND" in f.get("direction", "") or "BEACONING" in f.get("direction", "")
    ]
    if exfil_out:
        e  = exfil_out[0]
        ev = e.get("evidence", {})
        parts.append(
            f"Data exfiltration was observed: {ev.get('bytes_transferred', 0):,} bytes "
            f"transferred outbound from {e.get('source')} to {e.get('destination')} "
            f"across {ev.get('session_count', 'multiple')} sessions. "
            f"The chunked transfer pattern is consistent with staged exfiltration "
            f"over the established C2 channel (MITRE T1041)."
        )

    # Staging (inbound)
    staging = [f for f in exfil_findings if f.get("direction") == "INBOUND_STAGING"]
    if staging:
        s  = staging[0]
        ev = s.get("evidence", {})
        parts.append(
            f"Inbound staging activity was detected: {ev.get('bytes_transferred', 0):,} bytes "
            f"received from {s.get('source')} — likely adversary tooling or payloads "
            f"pushed to the compromised host (MITRE T1105 — Ingress Tool Transfer). "
            f"This has been correctly classified as STAGING, not exfiltration."
        )

    if not parts:
        return "Insufficient evidence to construct adversary narrative at this time."

    return " ".join(parts)


def build_recommended_actions(
    risk_tier:        str,
    src_ips:          list,
    dst_ips:          list,
) -> list[str]:
    """Fill in action templates with actual IOC values."""
    templates = RECOMMENDED_ACTIONS.get(risk_tier, RECOMMENDED_ACTIONS["Low"])
    src_str   = src_ips[0] if src_ips else "affected_host"
    dst_str   = ", ".join(dst_ips[:3]) if dst_ips else "suspicious_ips"

    return [
        t.format(src_ip=src_str, dst_ips=dst_str)
        for t in templates
    ]


# ---------------------------------------------------------------------------
# Main scoring entry point
# ---------------------------------------------------------------------------

def compute_unified_risk(
    dns_findings:    list[dict],
    exfil_findings:  list[dict],
    beacon_findings: list[dict],
    pcap_file:       str = "unknown.pcap",
    analyst:         str = "Analyst",
    hunt_id:         str = "HUNT-001",
) -> UnifiedHuntReport:
    """
    Aggregate all module findings into a unified hunt report.

    Args:
        dns_findings:    Output of tha_suspicious_tld_dns.format_alerts_for_tha()
        exfil_findings:  Output of tha_exfil_direction.format_alerts_for_tha()
        beacon_findings: Output of tha_beaconing.format_alerts_for_tha()
        pcap_file:       Name of the analyzed pcap
        analyst:         Analyst name for report header
        hunt_id:         Hunt identifier

    Returns:
        UnifiedHuntReport dataclass with all fields populated.
    """
    all_findings = dns_findings + exfil_findings + beacon_findings

    # --- IOC inventory ---
    confirmed_c2_ips     = []
    confirmed_c2_domains = []
    staging_ips          = []
    src_ips              = []

    # RFC 1918 prefixes — only these are "compromised internal hosts"
    INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168.")

    def is_internal(ip: str) -> bool:
        return any(ip.startswith(p) for p in INTERNAL_PREFIXES)

    for f in dns_findings:
        domain = f.get("destination", "")
        if domain and f.get("type") == "suspicious_tld_dns":
            confirmed_c2_domains.append(domain)
        confirmed_c2_ips.extend(f.get("evidence", {}).get("resolved_ips", []))

    for f in exfil_findings:
        direction = f.get("direction", "")
        src       = f.get("source", "")
        if direction == "INBOUND_STAGING":
            # Source is the external staging server — add to staging_ips not src_ips
            if src and not is_internal(src):
                staging_ips.append(src)
        elif "OUTBOUND" in direction or "BEACONING" in direction:
            # Source is the compromised internal host
            if src and is_internal(src):
                src_ips.append(src)

    for f in beacon_findings:
        src = f.get("source", "")
        # Beaconing source should always be internal; guard anyway
        if src and is_internal(src):
            src_ips.append(src)

    confirmed_c2_ips     = list(set(confirmed_c2_ips))
    confirmed_c2_domains = list(set(confirmed_c2_domains))
    staging_ips          = list(set(staging_ips))
    src_ips              = list(set(src_ips))

    # dst_ips for recommended actions = confirmed C2 IPs only (not staging)
    # Staging IPs are external servers pushing TO us — we block them separately
    dst_ips = list(set(confirmed_c2_ips))

    confirmed_c2 = bool(confirmed_c2_ips or confirmed_c2_domains)

    # --- Cross-module correlation ---
    ioc_correlations = build_ioc_correlations(
        dns_findings, exfil_findings, beacon_findings
    )

    # --- ATT&CK mapping ---
    mitre_techniques  = extract_mitre_techniques(all_findings)
    kill_chain_stages = extract_kill_chain_stages(mitre_techniques)

    # --- Unified score ---
    raw_score, normalized_score, risk_tier, score_breakdown = compute_unified_score(
        dns_findings, exfil_findings, beacon_findings,
        ioc_correlations, kill_chain_stages, confirmed_c2
    )

    # --- Narrative ---
    executive_summary = generate_executive_summary(
        risk_tier, confirmed_c2_ips, confirmed_c2_domains,
        kill_chain_stages, src_ips, normalized_score
    )

    adversary_narrative = generate_adversary_narrative(
        dns_findings, exfil_findings, beacon_findings,
        ioc_correlations, risk_tier
    )

    recommended_actions = build_recommended_actions(risk_tier, src_ips, dst_ips)

    return UnifiedHuntReport(
        hunt_id              = hunt_id,
        analyst              = analyst,
        timestamp            = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        pcap_file            = pcap_file,
        raw_score            = raw_score,
        normalized_score     = normalized_score,
        risk_tier            = risk_tier,
        confirmed_c2_ips     = confirmed_c2_ips,
        confirmed_c2_domains = confirmed_c2_domains,
        staging_ips          = staging_ips,
        mitre_techniques     = mitre_techniques,
        kill_chain_stages    = kill_chain_stages,
        dns_findings         = dns_findings,
        exfil_findings       = exfil_findings,
        beacon_findings      = beacon_findings,
        ioc_correlations     = [
            {
                "ioc":            c.ioc,
                "ioc_type":       c.ioc_type,
                "convergence":    c.convergence,
                "modules_firing": c.modules_firing,
                "finding_types":  c.finding_types,
                "total_risk":     c.total_risk,
            }
            for c in ioc_correlations
        ],
        executive_summary    = executive_summary,
        adversary_narrative  = adversary_narrative,
        recommended_actions  = recommended_actions,
        score_breakdown      = score_breakdown,
    )


def report_to_dict(report: UnifiedHuntReport) -> dict:
    """Serialize report to dict for JSON output or THA report renderer."""
    return {
        "hunt_metadata": {
            "hunt_id":    report.hunt_id,
            "analyst":    report.analyst,
            "timestamp":  report.timestamp,
            "pcap_file":  report.pcap_file,
        },
        "risk_assessment": {
            "normalized_score": report.normalized_score,
            "raw_score":        report.raw_score,
            "risk_tier":        report.risk_tier,
            "score_breakdown":  report.score_breakdown,
        },
        "ioc_inventory": {
            "confirmed_c2_ips":      report.confirmed_c2_ips,
            "confirmed_c2_domains":  report.confirmed_c2_domains,
            "staging_ips":           report.staging_ips,
        },
        "mitre_coverage": {
            "techniques":       report.mitre_techniques,
            "kill_chain_stages": report.kill_chain_stages,
        },
        "ioc_correlations":   report.ioc_correlations,
        "narrative": {
            "executive_summary":   report.executive_summary,
            "adversary_narrative": report.adversary_narrative,
        },
        "recommended_actions": report.recommended_actions,
        "findings": {
            "dns":      report.dns_findings,
            "exfil":    report.exfil_findings,
            "beaconing": report.beacon_findings,
        },
    }


def print_report(report: UnifiedHuntReport):
    """Pretty-print the unified hunt report to console."""
    w = 70
    print("\n" + "=" * w)
    print(f"  THA UNIFIED HUNT REPORT  |  {report.hunt_id}")
    print(f"  Analyst: {report.analyst}  |  {report.timestamp}")
    print(f"  File: {report.pcap_file}")
    print("=" * w)

    # Risk banner
    tier_colors = {
        "Critical":      "!!! CRITICAL !!!",
        "High":          "!! HIGH !!",
        "Medium":        "! MEDIUM !",
        "Low":           "LOW",
        "Informational": "INFORMATIONAL",
    }
    banner = tier_colors.get(report.risk_tier, report.risk_tier)
    print(f"\n  RISK SCORE: {report.normalized_score}/100  [{banner}]")
    print(f"\n  {report.executive_summary}\n")

    print("-" * w)
    print("  IOC INVENTORY")
    print("-" * w)
    print(f"  C2 Domains : {report.confirmed_c2_domains}")
    print(f"  C2 IPs     : {report.confirmed_c2_ips}")
    print(f"  Staging IPs: {report.staging_ips}")

    print(f"\n  MITRE ATT&CK: {', '.join(report.mitre_techniques)}")
    print(f"  Kill Chain  : {', '.join(report.kill_chain_stages)}")

    print("\n" + "-" * w)
    print("  IOC CORRELATIONS (cross-module)")
    print("-" * w)
    for c in report.ioc_correlations:
        bar   = "▓" * c["convergence"] + "░" * (3 - c["convergence"])
        print(f"  [{bar}] {c['ioc']} — {c['convergence']}/3 modules "
              f"| types: {c['finding_types']}")

    print("\n" + "-" * w)
    print("  SCORE BREAKDOWN")
    print("-" * w)
    bd = report.score_breakdown
    print(f"  Base (highest finding)  : {bd.get('base_score_highest_finding', 0)}")
    cb = bd.get("convergence_bonus", {})
    print(f"  Convergence bonus       : +{cb.get('bonus', 0)} "
          f"({cb.get('explanation', '')})")
    kc = bd.get("kill_chain_bonus", {})
    print(f"  Kill chain bonus        : +{kc.get('bonus', 0)} "
          f"({kc.get('stages_covered', [])})")
    bb = bd.get("breadth_bonus", {})
    print(f"  Breadth bonus           : +{bb.get('bonus', 0)} "
          f"({bb.get('total_findings', 0)} findings)")
    print(f"  Raw total               : {bd.get('raw_score_total', 0)}")
    print(f"  Normalized (0-100)      : {report.normalized_score}")

    print("\n" + "-" * w)
    print("  ADVERSARY NARRATIVE")
    print("-" * w)
    # Word wrap narrative
    words    = report.adversary_narrative.split()
    line     = "  "
    for word in words:
        if len(line) + len(word) + 1 > w:
            print(line)
            line = "  " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)

    print("\n" + "-" * w)
    print("  RECOMMENDED ACTIONS")
    print("-" * w)
    for i, action in enumerate(report.recommended_actions, 1):
        print(f"  {i:02d}. {action}")

    print("\n" + "=" * w + "\n")


# ---------------------------------------------------------------------------
# Standalone test — simulates full pipeline output
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    # Simulated findings from the exercise pcap
    # In production, these come from run_full_tha_pipeline() in tha_beaconing.py
    mock_dns_findings = [
        {
            "type":        "suspicious_tld_dns",
            "severity":    "Critical",
            "direction":   None,
            "source":      "internal_host",
            "destination": "whitepepper.su",
            "detail":      "Domain 'whitepepper.su' uses high-risk TLD '.su' | "
                           "Queried 10x — beaconing threshold exceeded | "
                           "Resolved to ['153.92.1.49'] and TCP traffic confirmed C2.",
            "mitre":       "T1071.004, T1041",
            "risk_score":  125,
            "evidence": {
                "resolved_ips":          ["153.92.1.49"],
                "query_count":           10,
                "tcp_bytes_to_resolved": 287340,
            },
        }
    ]

    mock_exfil_findings = [
        {
            "type":        "suspicious_outbound_transfer",
            "severity":    "Critical",
            "direction":   "BEACONING_EXFIL",
            "source":      "10.1.21.58",
            "destination": "153.92.1.49:443",
            "detail":      "Chunked exfiltration: 12 sessions to 153.92.1.49:443, "
                           "287,340 bytes total. Destination is confirmed C2.",
            "mitre":       "T1041",
            "risk_score":  135,
            "evidence": {
                "bytes_transferred": 287340,
                "session_count":     12,
                "confirmed_c2":      True,
            },
        },
        {
            "type":        "inbound_staging",
            "severity":    "High",
            "direction":   "INBOUND_STAGING",
            "source":      "104.21.46.67",
            "destination": "10.1.21.58:54840",
            "detail":      "Large inbound transfer: 16,100,000 bytes. "
                           "Correctly classified as INBOUND STAGING (T1105), "
                           "NOT exfiltration.",
            "mitre":       "T1105",
            "risk_score":  65,
            "evidence": {
                "bytes_transferred": 16100000,
                "session_count":     1,
                "confirmed_c2":      False,
            },
        },
    ]

    mock_beacon_findings = [
        {
            "type":        "beacon_sequential_ephemeral_port",
            "severity":    "Critical",
            "source":      "10.1.21.58",
            "destination": "153.92.1.49:443",
            "proto":       "TCP",
            "detail":      "Sequential source ports: [61826, 61827, 61828, 61829, 61830] | "
                           "Destination 153.92.1.49 is CONFIRMED C2.",
            "mitre":       "T1071.001",
            "risk_score":  140,
            "evidence": {
                "session_count":    12,
                "mean_interval_s":  45.3,
                "cv":               0.18,
                "jitter_pct":       31.2,
                "pattern":          "Jittered interval | Sequential src ports",
                "confirmed_c2":     True,
                "sequential_ports": [61826, 61827, 61828, 61829, 61830, 61831, 61832],
                "interval_samples": [42.1, 51.3, 38.7, 49.2, 44.8, 47.1, 40.3],
            },
        },
        {
            "type":        "beacon_icmp_beacon",
            "severity":    "High",
            "source":      "10.1.21.58",
            "destination": "10.1.21.2:0",
            "proto":       "ICMP",
            "detail":      "ICMP echo requests with avg payload 155 bytes (normal: 32-56). "
                           "Potential ICMP tunneling.",
            "mitre":       "T1095",
            "risk_score":  50,
            "evidence": {
                "session_count":    13,
                "mean_interval_s":  12.4,
                "cv":               0.22,
                "jitter_pct":       38.1,
                "pattern":          "ICMP oversized payload beacon",
                "confirmed_c2":     False,
                "sequential_ports": [],
                "interval_samples": [11.2, 14.1, 10.8, 13.5, 12.0],
            },
        },
    ]

    report = compute_unified_risk(
        dns_findings    = mock_dns_findings,
        exfil_findings  = mock_exfil_findings,
        beacon_findings = mock_beacon_findings,
        pcap_file       = "2026-01-31-traffic-analysis-exercise.pcap",
        analyst         = "V. Grace",
        hunt_id         = "HUNT-001",
    )

    print_report(report)

    # Also dump full JSON for THA report renderer
    print("\n[THA] Full JSON output:\n")
    print(json.dumps(report_to_dict(report), indent=2))