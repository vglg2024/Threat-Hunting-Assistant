"""
Threat Hunting Assistant (THA) — Core Orchestration Engine
eCTHP-aligned | Blue Team Suite
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("THA.core")


class THASession:
    """Represents a single hunt session, tracking all evidence, findings, and hypotheses."""

    def __init__(self, analyst_name: str = "Analyst", hunt_name: str = "Unnamed Hunt"):
        self.analyst_name = analyst_name
        self.hunt_name = hunt_name
        self.created_at = datetime.utcnow().isoformat()
        self.evidence_files: list[dict] = []
        self.pcap_findings: list[dict] = []
        self.log_findings: list[dict] = []
        self.ioc_matches: list[dict] = []
        self.hypotheses: list[dict] = []
        self.mitre_mappings: list[dict] = []
        self.analyst_notes: str = ""
        self.severity: str = "Low"  # Low | Medium | High | Critical

    def add_evidence(self, file_path: str, evidence_type: str):
        self.evidence_files.append({
            "path": file_path,
            "type": evidence_type,
            "loaded_at": datetime.utcnow().isoformat()
        })

    def to_dict(self) -> dict:
        return {
            "hunt_name": self.hunt_name,
            "analyst": self.analyst_name,
            "created_at": self.created_at,
            "severity": self.severity,
            "evidence_files": self.evidence_files,
            "pcap_findings": self.pcap_findings,
            "log_findings": self.log_findings,
            "ioc_matches": self.ioc_matches,
            "hypotheses": self.hypotheses,
            "mitre_mappings": self.mitre_mappings,
            "analyst_notes": self.analyst_notes,
        }

    def save(self, output_dir: str = "output"):
        Path(output_dir).mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = self.hunt_name.replace(" ", "_")
        path = os.path.join(output_dir, f"session_{safe_name}_{ts}.json")
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info(f"Session saved → {path}")
        return path

    @classmethod
    def load(cls, path: str) -> "THASession":
        with open(path) as f:
            data = json.load(f)
        session = cls(data.get("analyst", ""), data.get("hunt_name", ""))
        session.__dict__.update(data)
        return session


def determine_severity(ioc_count: int, critical_findings: int) -> str:
    if critical_findings >= 3 or ioc_count >= 10:
        return "Critical"
    elif critical_findings >= 1 or ioc_count >= 5:
        return "High"
    elif ioc_count >= 2:
        return "Medium"
    return "Low"
