"""
THA v1.6 - Suspicious Listener Hunt Module
=========================================
Threat Hunting Assistant - Network Listener Analysis
eCTHP-aligned | MITRE ATT&CK: T1049, T1090, T1572, T1219

Author: Vincent Grace | Blue Team Suite
GitHub: github.com/vglg2024

Workflow:
  netstat -ano output → PID resolution → port baseline check →
  executable path extraction → SHA256 hash → VirusTotal enrichment →
  final disposition report

Usage:
  # Feed live netstat output:
  python tha_listener_hunt.py --live

  # Feed saved netstat output file:
  python tha_listener_hunt.py --file netstat_output.txt

  # Single PID investigation:
  python tha_listener_hunt.py --pid 22652

  # Full hunt with VT enrichment:
  python tha_listener_hunt.py --live --vt-api-key <key>
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ── MITRE ATT&CK Context ─────────────────────────────────────────────────────
MITRE_CONTEXT = {
    "T1049":  "System Network Connections Discovery",
    "T1090":  "Proxy - Connection Proxy",
    "T1572":  "Protocol Tunneling",
    "T1219":  "Remote Access Software",
    "T1055":  "Process Injection",
    "T1569":  "System Services - Service Execution",
}

# ── Known-Good Port Baseline (Windows) ───────────────────────────────────────
KNOWN_GOOD_PORTS = {
    80:    "HTTP",
    135:   "RPC Endpoint Mapper",
    139:   "NetBIOS Session",
    443:   "HTTPS",
    445:   "SMB",
    902:   "VMware",
    912:   "VMware",
    1433:  "MSSQL",
    3389:  "RDP",
    5040:  "Windows DAX API",
    5357:  "WS-Discovery / HTTPAPI",
    7680:  "Windows Update Delivery Optimization",
    9993:  "ZeroTier / Acer QuickPanel (verify)",  # flagged for review
    49664: "Windows RPC (svchost)",
    49665: "Windows RPC (svchost)",
    49666: "Windows RPC (svchost)",
    49667: "Windows RPC (svchost)",
    49668: "Windows RPC (svchost)",
    49669: "Windows RPC (svchost)",
    49670: "Windows RPC (svchost)",
    49671: "Windows RPC (svchost)",
    49672: "Windows RPC (svchost)",
}

# ── Known Bloatware Process Signatures ───────────────────────────────────────
KNOWN_BLOATWARE = {
    "acerccagent.exe":        "Acer Care Center Agent",
    "acerdiagent.exe":        "Acer Device Intelligence Agent",
    "acerqaagent.exe":        "Acer QA/Telemetry Agent",
    "acersysmonitorservice.exe": "Acer System Monitor",
    "quickpanel.exe":         "Acer Quick Panel (ULICTek)",
    "mcupdateservice.exe":    "McAfee Update",
    "hpnetworkcommservice.exe": "HP Network Comm Service",
    "hptelemetryservice.exe": "HP Telemetry",
    "delloptimizeragent.exe": "Dell Optimizer",
    "iastordatasvc.exe":      "Intel Storage Data Service",
}

# ── Known Suspicious / RAT Indicators ────────────────────────────────────────
SUSPICIOUS_PROCESS_NAMES = [
    "zerotier", "ngrok", "frp", "chisel", "plink", "putty",
    "netcat", "nc.exe", "ncat", "socat", "meterpreter",
    "cobaltstr", "beacon", "teamviewer", "anydesk", "radmin",
    "screenconnect", "connectwise", "rustdesk",
]

SUSPICIOUS_PORTS = {
    4444:  "Metasploit default listener",
    1337:  "Common C2 / leet port",
    31337: "Back Orifice / leet port",
    8888:  "Common C2 port",
    9001:  "Tor relay default",
    9050:  "Tor SOCKS proxy",
    9150:  "Tor Browser",
    6667:  "IRC (possible C2)",
    6666:  "IRC (possible C2)",
}

# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════╗
║        THA v1.6 — Suspicious Listener Hunt Module        ║
║     Threat Hunting Assistant | Blue Team Suite           ║
║     MITRE: T1049 · T1090 · T1572 · T1219                ║
╚══════════════════════════════════════════════════════════╝
{C.RESET}""")

# ── Netstat Parser ────────────────────────────────────────────────────────────
def parse_netstat(raw_output: str) -> list[dict]:
    """Parse netstat -ano output into structured listener records."""
    listeners = []
    seen_pids = set()

    for line in raw_output.splitlines():
        line = line.strip()
        if not line.startswith("TCP"):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        state = parts[3] if len(parts) > 3 else ""
        if state != "LISTENING":
            continue

        local = parts[1]
        pid   = parts[4]

        # Parse address and port
        if local.startswith("["):
            # IPv6
            match = re.match(r'\[.*\]:(\d+)', local)
            port = int(match.group(1)) if match else 0
            bind = "0.0.0.0" if "::" in local else local
        else:
            parts2 = local.rsplit(":", 1)
            port   = int(parts2[1]) if len(parts2) == 2 else 0
            bind   = parts2[0]

        # Deduplicate by PID+port (IPv4/IPv6 often both listed)
        key = f"{pid}:{port}"
        if key in seen_pids:
            continue
        seen_pids.add(key)

        listeners.append({
            "pid":  pid,
            "port": port,
            "bind": bind,
            "state": state,
        })

    return sorted(listeners, key=lambda x: x["port"])

# ── PID → Process Info ────────────────────────────────────────────────────────
def resolve_pid(pid: str) -> dict:
    """Resolve PID to process name, path, and start time via PowerShell."""
    info = {"name": "UNKNOWN", "path": "", "cmdline": "", "start_time": ""}

    try:
        cmd = (
            f'powershell -NoProfile -Command "'
            f'$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; '
            f'if ($p) {{ '
            f'$wmi = Get-WmiObject Win32_Process -Filter \\"ProcessId={pid}\\" -ErrorAction SilentlyContinue; '
            f'[PSCustomObject]@{{ '
            f'Name=$p.ProcessName; '
            f'Path=$p.Path; '
            f'StartTime=$p.StartTime; '
            f'CommandLine=if($wmi){{$wmi.CommandLine}}else{{\'\'}} '
            f'}} | ConvertTo-Json }}"'
        )
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout.strip())
            info["name"]       = data.get("Name", "UNKNOWN") or "UNKNOWN"
            info["path"]       = data.get("Path", "") or ""
            info["cmdline"]    = data.get("CommandLine", "") or ""
            info["start_time"] = str(data.get("StartTime", "")) or ""
    except Exception as e:
        info["error"] = str(e)

    return info

# ── File Hasher ───────────────────────────────────────────────────────────────
def hash_file(filepath: str) -> str | None:
    """SHA256 hash a file. Returns hex string or None."""
    try:
        p = Path(filepath)
        if not p.exists():
            return None
        sha256 = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None

# ── VirusTotal Lookup ─────────────────────────────────────────────────────────
def vt_lookup(sha256: str, api_key: str) -> dict:
    """Query VirusTotal for a SHA256 hash."""
    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed"}
    if not api_key:
        return {"error": "No API key provided"}

    url     = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data  = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            names = data["data"]["attributes"].get("names", [])
            sig   = data["data"]["attributes"].get("signature_info", {})
            return {
                "malicious":   stats.get("malicious", 0),
                "suspicious":  stats.get("suspicious", 0),
                "undetected":  stats.get("undetected", 0),
                "total":       sum(stats.values()),
                "names":       names[:3],
                "signer":      sig.get("signers", "Unknown"),
                "verified":    sig.get("verified", "Unknown"),
            }
        elif resp.status_code == 404:
            return {"error": "Hash not found in VT database"}
        elif resp.status_code == 429:
            return {"error": "VT rate limit hit — wait 60s"}
        else:
            return {"error": f"VT HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ── Risk Scorer ───────────────────────────────────────────────────────────────
def score_listener(port: int, proc_name: str, proc_path: str) -> tuple[str, list[str]]:
    """
    Returns (disposition, [reasons])
    Disposition: BENIGN | REVIEW | SUSPICIOUS | MALICIOUS
    """
    reasons   = []
    score     = 0
    proc_lower = proc_name.lower()
    path_lower = proc_path.lower()

    # Known suspicious ports
    if port in SUSPICIOUS_PORTS:
        reasons.append(f"Port {port} → {SUSPICIOUS_PORTS[port]}")
        score += 40

    # Known suspicious process names
    for keyword in SUSPICIOUS_PROCESS_NAMES:
        if keyword in proc_lower or keyword in path_lower:
            reasons.append(f"Process name matches RAT/C2 keyword: '{keyword}'")
            score += 50

    # Non-standard high port with unknown process
    if port > 1024 and port not in KNOWN_GOOD_PORTS and proc_name == "UNKNOWN":
        reasons.append("Non-standard port with unresolved process")
        score += 30

    # Running from temp/appdata/unusual path
    suspicious_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
                        "\\downloads\\", "\\public\\", "\\recycle"]
    for sp in suspicious_paths:
        if sp in path_lower:
            reasons.append(f"Executable in suspicious path: {sp}")
            score += 35

    # Known bloatware — benign but noisy
    if proc_lower in KNOWN_BLOATWARE:
        reasons.append(f"Known bloatware: {KNOWN_BLOATWARE[proc_lower]}")
        score = max(score - 20, 0)

    # Known good port
    if port in KNOWN_GOOD_PORTS and score == 0:
        reasons.append(f"Port {port} → {KNOWN_GOOD_PORTS[port]} (expected)")

    # WindowsApps is signed MS store path — reduce suspicion
    if "windowsapps" in path_lower:
        reasons.append("Executable in WindowsApps (Microsoft Store signed path)")
        score = max(score - 15, 0)

    # Disposition
    if score >= 50:
        disposition = "MALICIOUS"
    elif score >= 30:
        disposition = "SUSPICIOUS"
    elif score >= 10:
        disposition = "REVIEW"
    else:
        disposition = "BENIGN"

    if not reasons:
        reasons.append("No indicators detected")

    return disposition, reasons

# ── Report Printer ────────────────────────────────────────────────────────────
DISP_COLORS = {
    "BENIGN":    C.GREEN,
    "REVIEW":    C.YELLOW,
    "SUSPICIOUS": C.RED,
    "MALICIOUS": C.RED + C.BOLD,
}

def print_finding(entry: dict):
    disp  = entry["disposition"]
    color = DISP_COLORS.get(disp, C.RESET)

    print(f"\n{C.BOLD}{'─'*60}{C.RESET}")
    print(f"  Port    : {C.CYAN}{entry['port']}{C.RESET}  |  PID: {entry['pid']}")
    print(f"  Process : {entry['proc_name']}")
    if entry.get("proc_path"):
        print(f"  Path    : {C.DIM}{entry['proc_path']}{C.RESET}")
    if entry.get("start_time"):
        print(f"  Started : {entry['start_time']}")
    print(f"  Verdict : {color}{C.BOLD}{disp}{C.RESET}")
    for r in entry["reasons"]:
        print(f"            • {r}")

    # Hash + VT results
    if entry.get("sha256"):
        print(f"  SHA256  : {entry['sha256']}")
    if entry.get("vt"):
        vt = entry["vt"]
        if "error" in vt:
            print(f"  VT      : {C.YELLOW}{vt['error']}{C.RESET}")
        else:
            mal = vt.get("malicious", 0)
            tot = vt.get("total", 70)
            vt_color = C.RED if mal > 0 else C.GREEN
            print(f"  VT      : {vt_color}{mal}/{tot} detections{C.RESET} | Signer: {vt.get('signer','?')}")

    # MITRE mapping
    if disp in ("SUSPICIOUS", "MALICIOUS"):
        print(f"  MITRE   : T1219 (Remote Access Software), T1572 (Protocol Tunneling)")

def print_summary(findings: list[dict], scan_time: str):
    counts = {"BENIGN": 0, "REVIEW": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}
    for f in findings:
        counts[f["disposition"]] = counts.get(f["disposition"], 0) + 1

    print(f"\n\n{C.BOLD}{'═'*60}")
    print(f"  THA LISTENER HUNT — SUMMARY REPORT")
    print(f"  Scan Time : {scan_time}")
    print(f"  Listeners : {len(findings)} unique")
    print(f"{'═'*60}{C.RESET}")
    print(f"  {C.GREEN}BENIGN    : {counts['BENIGN']}{C.RESET}")
    print(f"  {C.YELLOW}REVIEW    : {counts['REVIEW']}{C.RESET}")
    print(f"  {C.RED}SUSPICIOUS: {counts['SUSPICIOUS']}{C.RESET}")
    print(f"  {C.RED}{C.BOLD}MALICIOUS : {counts['MALICIOUS']}{C.RESET}")

    if counts["SUSPICIOUS"] + counts["MALICIOUS"] > 0:
        print(f"\n  {C.RED}⚠  ACTION REQUIRED — Review flagged listeners above{C.RESET}")
        print(f"  Recommended: Hash binaries → VirusTotal → Isolate if confirmed")
    else:
        print(f"\n  {C.GREEN}✓  No high-risk listeners detected{C.RESET}")

# ── Main Hunt Logic ───────────────────────────────────────────────────────────
def run_live_netstat() -> str:
    """Execute netstat -ano and return output."""
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception as e:
        print(f"{C.RED}Error running netstat: {e}{C.RESET}")
        sys.exit(1)

def hunt(netstat_raw: str, vt_api_key: str = "", hash_files: bool = True,
         min_disposition: str = "BENIGN") -> list[dict]:
    """
    Main hunt function.
    Returns list of finding dicts.
    """
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{C.DIM}[*] Parsing netstat output...{C.RESET}")

    listeners = parse_netstat(netstat_raw)
    print(f"[*] Found {len(listeners)} unique listening ports")
    print(f"[*] Resolving PIDs to process names...\n")

    findings = []
    for entry in listeners:
        pid  = entry["pid"]
        port = entry["port"]

        # Resolve PID
        proc = resolve_pid(pid)
        proc_name = proc.get("name", "UNKNOWN")
        proc_path = proc.get("path", "")

        # Score
        disposition, reasons = score_listener(port, proc_name, proc_path)

        finding = {
            "pid":         pid,
            "port":        port,
            "bind":        entry["bind"],
            "proc_name":   proc_name,
            "proc_path":   proc_path,
            "start_time":  proc.get("start_time", ""),
            "disposition": disposition,
            "reasons":     reasons,
            "sha256":      None,
            "vt":          None,
        }

        # Hash binary if path available and disposition warrants it
        if proc_path and hash_files and disposition in ("REVIEW", "SUSPICIOUS", "MALICIOUS"):
            print(f"  [+] Hashing {proc_name} (PID {pid}, port {port})...")
            sha256 = hash_file(proc_path)
            finding["sha256"] = sha256

            # VT lookup
            if sha256 and vt_api_key:
                print(f"  [+] VirusTotal lookup for {sha256[:16]}...")
                vt_result = vt_lookup(sha256, vt_api_key)
                finding["vt"] = vt_result
                time.sleep(0.5)  # VT rate limit courtesy

        findings.append(finding)

    # Filter by minimum disposition for display
    disp_order = ["BENIGN", "REVIEW", "SUSPICIOUS", "MALICIOUS"]
    min_idx    = disp_order.index(min_disposition)
    display    = [f for f in findings if disp_order.index(f["disposition"]) >= min_idx]

    # Print findings
    for f in sorted(display, key=lambda x: disp_order.index(x["disposition"]), reverse=True):
        print_finding(f)

    print_summary(findings, scan_time)
    return findings

# ── CLI Entry Point ───────────────────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="THA v1.6 - Suspicious Listener Hunt Module"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--live",   action="store_true",
                       help="Run live netstat -ano on this system")
    group.add_argument("--file",   metavar="FILE",
                       help="Path to saved netstat -ano output file")
    group.add_argument("--pid",    metavar="PID",
                       help="Investigate a single PID")

    parser.add_argument("--vt-api-key", metavar="KEY", default="",
                        help="VirusTotal API key for hash enrichment")
    parser.add_argument("--no-hash", action="store_true",
                        help="Skip file hashing (faster, no VT lookup)")
    parser.add_argument("--show",   default="BENIGN",
                        choices=["BENIGN", "REVIEW", "SUSPICIOUS", "MALICIOUS"],
                        help="Minimum disposition level to display (default: BENIGN = show all)")
    parser.add_argument("--output", metavar="FILE",
                        help="Save JSON findings to file")

    args = parser.parse_args()

    # Get netstat data
    if args.live:
        print(f"{C.DIM}[*] Running live netstat -ano...{C.RESET}")
        raw = run_live_netstat()
    elif args.file:
        with open(args.file, "r") as f:
            raw = f.read()
    elif args.pid:
        # Single PID mode
        print(f"[*] Investigating PID {args.pid}...")
        proc = resolve_pid(args.pid)
        print(json.dumps(proc, indent=2, default=str))
        if proc.get("path") and not args.no_hash:
            sha256 = hash_file(proc["path"])
            print(f"\nSHA256: {sha256}")
            if args.vt_api_key and sha256:
                vt = vt_lookup(sha256, args.vt_api_key)
                print(f"VT Result: {json.dumps(vt, indent=2)}")
        return

    # Run hunt
    findings = hunt(
        netstat_raw   = raw,
        vt_api_key    = args.vt_api_key,
        hash_files    = not args.no_hash,
        min_disposition = args.show,
    )

    # Save JSON output
    if args.output:
        with open(args.output, "w") as f:
            json.dump(findings, f, indent=2, default=str)
        print(f"\n[+] Findings saved to {args.output}")


if __name__ == "__main__":
    main()