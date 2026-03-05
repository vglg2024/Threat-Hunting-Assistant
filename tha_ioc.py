"""
THA IOC Correlation Engine
Matches extracted artifacts against threat-intel feeds (local or API-based).
eCTHP-aligned: Hunt Step 3 — Indicator Correlation & Threat Intel Enrichment
"""

import os
import re
import csv
import json
import logging
import hashlib
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("THA.ioc")

# ─────────────────────────────────────────────
# IOC Type Patterns
# ─────────────────────────────────────────────
IOC_PATTERNS = {
    "ipv4":   re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b"),
    "md5":    re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1":   re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url":    re.compile(r"https?://[^\s\"'<>]+"),
    "email":  re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "cve":    re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
}

# Private IP ranges to ignore
PRIVATE_IP_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
]

BENIGN_DOMAINS = {
    "google.com", "microsoft.com", "windows.com", "apple.com",
    "cloudflare.com", "amazonaws.com", "akamai.com", "office365.com",
    "windowsupdate.com", "bing.com", "youtube.com"
}


class IOCDatabase:
    """In-memory IOC database loaded from CSV or JSON threat intel files."""

    def __init__(self):
        self.iocs: dict[str, list[dict]] = {
            "ipv4": [], "domain": [], "md5": [], "sha1": [], "sha256": [],
            "url": [], "email": [], "cve": []
        }

    def load_csv(self, path: str):
        """Load IOCs from CSV. Expected columns: type, value, description, severity, source"""
        if not os.path.exists(path):
            logger.warning(f"IOC CSV not found: {path}")
            return 0
        count = 0
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ioc_type = row.get("type", "").strip().lower()
                value = row.get("value", "").strip()
                if ioc_type in self.iocs and value:
                    self.iocs[ioc_type].append({
                        "value": value.lower(),
                        "description": row.get("description", ""),
                        "severity": row.get("severity", "Medium"),
                        "source": row.get("source", "local"),
                        "tags": row.get("tags", ""),
                    })
                    count += 1
        logger.info(f"Loaded {count} IOCs from {path}")
        return count

    def load_json(self, path: str):
        """Load IOCs from JSON array or MISP-style format."""
        if not os.path.exists(path):
            logger.warning(f"IOC JSON not found: {path}")
            return 0
        count = 0
        with open(path) as f:
            data = json.load(f)
        entries = data if isinstance(data, list) else data.get("iocs", data.get("attributes", []))
        for entry in entries:
            ioc_type = entry.get("type", "").strip().lower()
            value = entry.get("value", entry.get("indicator", "")).strip()
            if ioc_type in self.iocs and value:
                self.iocs[ioc_type].append({
                    "value": value.lower(),
                    "description": entry.get("description", entry.get("comment", "")),
                    "severity": entry.get("severity", entry.get("threat_level", "Medium")),
                    "source": entry.get("source", entry.get("category", "json_feed")),
                    "tags": ",".join(entry.get("tags", [])) if isinstance(entry.get("tags"), list) else entry.get("tags", ""),
                })
                count += 1
        logger.info(f"Loaded {count} IOCs from {path}")
        return count

    def add_manual(self, ioc_type: str, value: str, description: str = "", severity: str = "Medium"):
        if ioc_type in self.iocs:
            self.iocs[ioc_type].append({
                "value": value.lower(),
                "description": description,
                "severity": severity,
                "source": "manual",
                "tags": "",
            })

    def total(self) -> int:
        return sum(len(v) for v in self.iocs.values())


class IOCCorrelator:
    """
    Extracts IOC artifacts from findings/text and cross-references against
    a loaded threat-intel database.
    """

    def __init__(self, database: IOCDatabase):
        self.db = database
        self.matches: list[dict] = []
        self.extracted_artifacts: dict[str, set] = {k: set() for k in IOC_PATTERNS}

    def extract_from_text(self, text: str):
        """Extract observable IOC artifacts from any text blob."""
        for ioc_type, pattern in IOC_PATTERNS.items():
            for match in pattern.findall(text):
                value = match.strip().lower()
                # Filter private IPs
                if ioc_type == "ipv4":
                    if any(p.match(value) for p in PRIVATE_IP_RANGES):
                        continue
                # Filter benign domains
                if ioc_type == "domain":
                    base = ".".join(value.split(".")[-2:])
                    if base in BENIGN_DOMAINS:
                        continue
                self.extracted_artifacts[ioc_type].add(value)

    def extract_from_findings(self, findings: list[dict]):
        """Pull observable values out of analyzer findings."""
        for finding in findings:
            text = json.dumps(finding)
            self.extract_from_text(text)

    def correlate(self) -> list[dict]:
        """Match extracted artifacts against the IOC database."""
        self.matches = []
        for ioc_type, artifacts in self.extracted_artifacts.items():
            for artifact in artifacts:
                for ioc in self.db.iocs.get(ioc_type, []):
                    if artifact == ioc["value"] or (len(artifact) > 5 and ioc["value"] in artifact):
                        self.matches.append({
                            "type": "ioc_match",
                            "ioc_type": ioc_type,
                            "value": artifact,
                            "severity": ioc["severity"],
                            "source": ioc["source"],
                            "description": ioc["description"],
                            "tags": ioc["tags"],
                            "matched_at": datetime.utcnow().isoformat(),
                        })
        logger.info(f"IOC correlation complete: {len(self.matches)} matches")
        return self.matches

    def get_summary(self) -> dict:
        return {
            "ioc_db_total": self.db.total(),
            "extracted_artifacts": {k: len(v) for k, v in self.extracted_artifacts.items()},
            "matches": self.matches,
            "match_count": len(self.matches),
        }
