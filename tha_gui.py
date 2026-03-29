"""
Threat Hunting Assistant (THA) — Main GUI
eCTHP-aligned | Blue Team Suite
Run: python tha_gui.py
"""

import os
import sys
import json
import logging
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
from pathlib import Path

# ─── THA Modules ───
from tha_core import THASession, determine_severity
from tha_pcap import PCAPAnalyzer
from tha_logs import LogAnalyzer
from tha_ioc import IOCDatabase, IOCCorrelator
from tha_hypothesis import HypothesisGenerator
from tha_report import ReportBuilder

# ─── THA v1.7 Enhanced Detection Modules ───
try:
    from tha_suspicious_tld_dns import (
        analyze_suspicious_tld_dns,
        format_alerts_for_tha as fmt_dns_alerts,
    )
    from tha_exfil_direction import (
        analyze_exfiltration_direction,
        format_alerts_for_tha as fmt_exfil_alerts,
    )
    from tha_beaconing import (
        analyze_beaconing,
        format_alerts_for_tha as fmt_beacon_alerts,
    )
    from tha_risk_scoring import (
        compute_unified_risk,
        report_to_dict,
    )
    ENHANCED_MODULES_AVAILABLE = True
except ImportError as _e:
    logging.getLogger("THA.gui").warning(
        f"Enhanced detection modules not found — running v1.0 baseline. ({_e})"
    )
    ENHANCED_MODULES_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("THA.gui")

# ─── Theme Colors ───
DARK_BG     = "#0f1117"
SURFACE     = "#1a1d27"
BORDER      = "#2d3047"
ACCENT      = "#38bdf8"
TEXT        = "#e2e8f0"
MUTED       = "#64748b"
CRITICAL    = "#dc2626"
HIGH        = "#ea580c"
MEDIUM      = "#d97706"
LOW         = "#16a34a"
SUCCESS     = "#22c55e"


class THAApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Threat Hunting Assistant (THA) — eCTHP Aligned")
        self.geometry("1200x800")
        self.configure(bg=DARK_BG)
        self.resizable(True, True)

        # Application state
        self.session = THASession()
        self.ioc_db = IOCDatabase()
        self.all_findings: list[dict] = []
        self.hyp_summary: dict = {}
        self.ioc_summary: dict = {}

        # v1.7 Enhanced module state
        self.enhanced_dns_findings:    list[dict] = []
        self.enhanced_exfil_findings:  list[dict] = []
        self.enhanced_beacon_findings: list[dict] = []
        self.unified_report:           dict = {}
        self.unified_risk_score:       int  = 0
        self.unified_risk_tier:        str  = "Informational"

        self._build_ui()
        self._log("THA initialized. Load evidence files to begin your hunt.")

    # ──────────────────────────────────────────────
    # UI Construction
    # ──────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        self._build_main()
        self._build_statusbar()

    def _build_header(self):
        header = tk.Frame(self, bg=SURFACE, pady=0)
        header.pack(fill="x")

        # Left: Logo + title
        left = tk.Frame(header, bg=SURFACE, padx=20, pady=12)
        left.pack(side="left")
        tk.Label(left, text="🛡", font=("", 22), bg=SURFACE, fg=ACCENT).pack(side="left", padx=(0, 8))
        tk.Label(left, text="Threat Hunting Assistant", font=("JetBrains Mono", 14, "bold"),
                 bg=SURFACE, fg=TEXT).pack(side="left")
        tk.Label(left, text="  eCTHP Aligned", font=("", 9), bg=SURFACE, fg=MUTED).pack(side="left")

        # Right: session info
        right = tk.Frame(header, bg=SURFACE, padx=20)
        right.pack(side="right")
        self.session_label = tk.Label(right, text="No active session",
                                      font=("JetBrains Mono", 9), bg=SURFACE, fg=MUTED)
        self.session_label.pack()

        # Separator
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    def _build_main(self):
        main = tk.Frame(self, bg=DARK_BG)
        main.pack(fill="both", expand=True)

        # Left panel: controls
        left = tk.Frame(main, bg=SURFACE, width=300)
        left.pack(side="left", fill="y", padx=0, pady=0)
        left.pack_propagate(False)
        self._build_control_panel(left)

        # Divider
        tk.Frame(main, bg=BORDER, width=1).pack(side="left", fill="y")

        # Right: notebook tabs
        right = tk.Frame(main, bg=DARK_BG)
        right.pack(side="left", fill="both", expand=True)
        self._build_notebook(right)

    def _build_control_panel(self, parent):
        style = {"bg": SURFACE, "fg": TEXT, "font": ("", 9, "bold")}
        pad = {"padx": 16, "pady": 4}

        tk.Label(parent, text="HUNT SESSION", font=("JetBrains Mono", 9, "bold"),
                 bg=SURFACE, fg=ACCENT, anchor="w").pack(fill="x", padx=16, pady=(16, 4))

        tk.Label(parent, text="Hunt Name:", **style).pack(fill="x", **pad)
        self.hunt_name_var = tk.StringVar(value="Hunt-001")
        tk.Entry(parent, textvariable=self.hunt_name_var, bg=DARK_BG, fg=TEXT,
                 insertbackground=TEXT, relief="flat", font=("JetBrains Mono", 10)
                 ).pack(fill="x", padx=16, pady=2)

        tk.Label(parent, text="Analyst Name:", **style).pack(fill="x", **pad)
        self.analyst_name_var = tk.StringVar(value="Analyst")
        tk.Entry(parent, textvariable=self.analyst_name_var, bg=DARK_BG, fg=TEXT,
                 insertbackground=TEXT, relief="flat", font=("JetBrains Mono", 10)
                 ).pack(fill="x", padx=16, pady=2)

        self._separator(parent)
        tk.Label(parent, text="EVIDENCE", font=("JetBrains Mono", 9, "bold"),
                 bg=SURFACE, fg=ACCENT, anchor="w").pack(fill="x", padx=16, pady=(8, 4))

        self._btn(parent, "📦  Load PCAP File", self._load_pcap)
        self._btn(parent, "📋  Load Log File", self._load_log)
        self._btn(parent, "🔍  Load IOC Database", self._load_ioc_db)

        self._separator(parent)
        tk.Label(parent, text="ANALYSIS", font=("JetBrains Mono", 9, "bold"),
                 bg=SURFACE, fg=ACCENT, anchor="w").pack(fill="x", padx=16, pady=(8, 4))

        self._btn(parent, "▶  Run Full Analysis", self._run_full_analysis, accent=True)
        self._btn(parent, "💡  Generate Hypotheses", self._generate_hypotheses)

        self._separator(parent)
        tk.Label(parent, text="REPORTING", font=("JetBrains Mono", 9, "bold"),
                 bg=SURFACE, fg=ACCENT, anchor="w").pack(fill="x", padx=16, pady=(8, 4))

        self._btn(parent, "📄  Export HTML Report", self._export_html)
        self._btn(parent, "📑  Export PDF Report", self._export_pdf)
        self._btn(parent, "💾  Save Session", self._save_session)

        self._separator(parent)
        # Evidence list
        tk.Label(parent, text="LOADED EVIDENCE", font=("JetBrains Mono", 9, "bold"),
                 bg=SURFACE, fg=ACCENT, anchor="w").pack(fill="x", padx=16, pady=(8, 4))
        self.evidence_listbox = tk.Listbox(parent, bg=DARK_BG, fg=MUTED,
                                           font=("JetBrains Mono", 8),
                                           selectbackground=ACCENT, relief="flat",
                                           height=8)
        self.evidence_listbox.pack(fill="x", padx=16, pady=4)

    def _build_notebook(self, parent):
        nb_style = ttk.Style()
        nb_style.theme_use("default")
        nb_style.configure("TNotebook", background=DARK_BG, borderwidth=0)
        nb_style.configure("TNotebook.Tab", background=SURFACE, foreground=MUTED,
                            padding=(16, 8), font=("JetBrains Mono", 9))
        nb_style.map("TNotebook.Tab",
                     background=[("selected", DARK_BG)],
                     foreground=[("selected", ACCENT)])

        self.nb = ttk.Notebook(parent)
        self.nb.pack(fill="both", expand=True, padx=16, pady=16)

        # Tab: Overview
        self.overview_frame = tk.Frame(self.nb, bg=DARK_BG)
        self.nb.add(self.overview_frame, text="📊 Overview")
        self._build_overview_tab(self.overview_frame)

        # Tab: Hypotheses
        self.hyp_frame = tk.Frame(self.nb, bg=DARK_BG)
        self.nb.add(self.hyp_frame, text="💡 Hypotheses")
        self._build_text_tab(self.hyp_frame, "hyp_text")

        # Tab: PCAP Findings
        self.pcap_frame = tk.Frame(self.nb, bg=DARK_BG)
        self.nb.add(self.pcap_frame, text="🌐 Network")
        self._build_text_tab(self.pcap_frame, "pcap_text")

        # Tab: Log Findings
        self.log_frame = tk.Frame(self.nb, bg=DARK_BG)
        self.nb.add(self.log_frame, text="📋 Logs")
        self._build_text_tab(self.log_frame, "log_text")

        # Tab: IOC Matches
        self.ioc_frame = tk.Frame(self.nb, bg=DARK_BG)
        self.nb.add(self.ioc_frame, text="🔍 IOCs")
        self._build_text_tab(self.ioc_frame, "ioc_text")

        # Tab: Threat Intel (v1.7 Enhanced Modules)
        self.intel_frame = tk.Frame(self.nb, bg=DARK_BG)
        self.nb.add(self.intel_frame, text="🎯 Threat Intel")
        self._build_intel_tab(self.intel_frame)

        # Tab: Console
        self.console_frame = tk.Frame(self.nb, bg=DARK_BG)
        self.nb.add(self.console_frame, text="🖥 Console")
        self._build_console_tab(self.console_frame)

    def _build_overview_tab(self, parent):
        tk.Label(parent, text="HUNT OVERVIEW",
                 font=("JetBrains Mono", 10, "bold"), bg=DARK_BG, fg=ACCENT,
                 anchor="w").pack(fill="x", padx=16, pady=(16, 4))

        stats_frame = tk.Frame(parent, bg=DARK_BG)
        stats_frame.pack(fill="x", padx=16, pady=8)

        self.stat_widgets = {}
        stat_defs = [
            ("findings", "Findings", HIGH),
            ("hypotheses", "Hypotheses", ACCENT),
            ("ioc_matches", "IOC Matches", CRITICAL),
            ("mitre", "MITRE TTPs", MEDIUM),
        ]
        for key, label, color in stat_defs:
            card = tk.Frame(stats_frame, bg=SURFACE, width=120, height=80)
            card.pack(side="left", padx=8, pady=4)
            card.pack_propagate(False)
            num = tk.Label(card, text="0", font=("JetBrains Mono", 28, "bold"),
                           bg=SURFACE, fg=color)
            num.pack(pady=(8, 0))
            tk.Label(card, text=label.upper(), font=("JetBrains Mono", 8),
                     bg=SURFACE, fg=MUTED).pack()
            self.stat_widgets[key] = num

        # Narrative
        tk.Label(parent, text="ADVERSARY NARRATIVE",
                 font=("JetBrains Mono", 10, "bold"), bg=DARK_BG, fg=ACCENT,
                 anchor="w").pack(fill="x", padx=16, pady=(16, 4))
        self.narrative_text = scrolledtext.ScrolledText(parent, height=5, bg=SURFACE, fg=TEXT,
                                                         font=("", 10), relief="flat", wrap="word",
                                                         state="disabled")
        self.narrative_text.pack(fill="x", padx=16, pady=4)

        # Severity bar
        tk.Label(parent, text="SEVERITY BREAKDOWN",
                 font=("JetBrains Mono", 10, "bold"), bg=DARK_BG, fg=ACCENT,
                 anchor="w").pack(fill="x", padx=16, pady=(16, 4))
        self.severity_frame = tk.Frame(parent, bg=DARK_BG)
        self.severity_frame.pack(fill="x", padx=16, pady=4)
        self.sev_labels = {}
        for sev, color in [("Critical", CRITICAL), ("High", HIGH), ("Medium", MEDIUM), ("Low", LOW)]:
            f = tk.Frame(self.severity_frame, bg=DARK_BG)
            f.pack(side="left", padx=8)
            lbl = tk.Label(f, text=f"◆ {sev}: 0", font=("JetBrains Mono", 9),
                           bg=DARK_BG, fg=color)
            lbl.pack()
            self.sev_labels[sev] = lbl

    def _build_text_tab(self, parent, attr_name):
        txt = scrolledtext.ScrolledText(parent, bg=SURFACE, fg=TEXT,
                                        font=("JetBrains Mono", 9), relief="flat",
                                        state="disabled", wrap="word")
        txt.pack(fill="both", expand=True, padx=16, pady=16)
        setattr(self, attr_name, txt)

    def _build_intel_tab(self, parent):
        """
        Threat Intel tab — surfaces v1.7 enhanced module findings:
        unified risk score, C2 IOCs, convergence table, and per-module results.
        Falls back gracefully if enhanced modules are not installed.
        """
        # Risk score banner row
        banner_frame = tk.Frame(parent, bg=DARK_BG)
        banner_frame.pack(fill="x", padx=16, pady=(16, 4))

        tk.Label(banner_frame, text="UNIFIED RISK SCORE",
                 font=("JetBrains Mono", 9, "bold"), bg=DARK_BG, fg=ACCENT,
                 anchor="w").pack(side="left")

        self.risk_score_label = tk.Label(
            banner_frame, text="—/100",
            font=("JetBrains Mono", 22, "bold"), bg=DARK_BG, fg=MUTED
        )
        self.risk_score_label.pack(side="left", padx=16)

        self.risk_tier_label = tk.Label(
            banner_frame, text="[ Run Analysis ]",
            font=("JetBrains Mono", 11, "bold"), bg=DARK_BG, fg=MUTED
        )
        self.risk_tier_label.pack(side="left")

        # Module status badges
        badge_frame = tk.Frame(parent, bg=DARK_BG)
        badge_frame.pack(fill="x", padx=16, pady=4)

        self.module_badges = {}
        for mod_name in ["TLD DNS", "Exfil Direction", "Beaconing"]:
            f   = tk.Frame(badge_frame, bg=SURFACE, padx=8, pady=4)
            f.pack(side="left", padx=4)
            lbl = tk.Label(f, text=f"{'●'} {mod_name}: —",
                           font=("JetBrains Mono", 8), bg=SURFACE, fg=MUTED)
            lbl.pack()
            self.module_badges[mod_name] = lbl

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=16, pady=8)

        # IOC inventory
        tk.Label(parent, text="CONFIRMED IOCs",
                 font=("JetBrains Mono", 9, "bold"), bg=DARK_BG, fg=ACCENT,
                 anchor="w").pack(fill="x", padx=16, pady=(0, 4))

        self.ioc_inventory_text = scrolledtext.ScrolledText(
            parent, height=3, bg=SURFACE, fg=SUCCESS,
            font=("JetBrains Mono", 9), relief="flat",
            state="disabled", wrap="word"
        )
        self.ioc_inventory_text.pack(fill="x", padx=16, pady=4)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=16, pady=8)

        # Full detail output
        tk.Label(parent, text="DETAILED FINDINGS (DNS | EXFIL | BEACONING)",
                 font=("JetBrains Mono", 9, "bold"), bg=DARK_BG, fg=ACCENT,
                 anchor="w").pack(fill="x", padx=16, pady=(0, 4))

        self.intel_detail_text = scrolledtext.ScrolledText(
            parent, bg=SURFACE, fg=TEXT,
            font=("JetBrains Mono", 8), relief="flat",
            state="disabled", wrap="word"
        )
        self.intel_detail_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        # Unavailable notice (shown when modules not installed)
        if not ENHANCED_MODULES_AVAILABLE:
            self._write_to_tab(
                self.intel_detail_text,
                "Enhanced detection modules (tha_suspicious_tld_dns, tha_exfil_direction,\n"
                "tha_beaconing, tha_risk_scoring) are not installed.\n\n"
                "Place the four module files in the same directory as tha_gui.py\n"
                "and restart THA to enable v1.7 enhanced detection."
            )

    def _build_console_tab(self, parent):
        self.console = scrolledtext.ScrolledText(parent, bg="#030712", fg="#4ade80",
                                                  font=("JetBrains Mono", 9), relief="flat",
                                                  state="disabled", wrap="word")
        self.console.pack(fill="both", expand=True, padx=16, pady=16)

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=SURFACE, pady=4)
        bar.pack(fill="x", side="bottom")
        tk.Frame(bar, bg=BORDER, height=1).pack(fill="x")
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(bar, textvariable=self.status_var, font=("JetBrains Mono", 8),
                 bg=SURFACE, fg=MUTED).pack(side="left", padx=16)

    # ──────────────────────────────────────────────
    # UI Helpers
    # ──────────────────────────────────────────────
    def _btn(self, parent, text, cmd, accent=False):
        fg = DARK_BG if accent else TEXT
        bg = ACCENT if accent else SURFACE
        btn = tk.Button(parent, text=text, command=cmd,
                        bg=bg, fg=fg, activebackground=bg,
                        font=("JetBrains Mono", 9), relief="flat",
                        cursor="hand2", anchor="w", padx=12, pady=6)
        btn.pack(fill="x", padx=16, pady=2)
        return btn

    def _separator(self, parent):
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=16, pady=8)

    def _log(self, msg: str, level: str = "INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
        self.console.configure(state="normal")
        self.console.insert("end", line)
        self.console.see("end")
        self.console.configure(state="disabled")
        self.status_var.set(msg[:80])
        logger.info(msg)

    def _write_to_tab(self, widget, content: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", content)
        widget.configure(state="disabled")

    def _update_stats(self):
        from collections import Counter
        sev_counts = Counter(f.get("severity", "info") for f in self.all_findings)
        self.stat_widgets["findings"].config(text=str(len(self.all_findings)))
        self.stat_widgets["hypotheses"].config(text=str(self.hyp_summary.get("total_hypotheses", 0)))
        self.stat_widgets["ioc_matches"].config(text=str(self.ioc_summary.get("match_count", 0)))
        self.stat_widgets["mitre"].config(text=str(self.hyp_summary.get("mitre_techniques_covered", 0)))

        for sev, lbl in self.sev_labels.items():
            count = sev_counts.get(sev, 0)
            lbl.config(text=f"◆ {sev}: {count}")

        # Narrative
        narrative = self.hyp_summary.get("adversary_narrative", "Run analysis to generate narrative.")
        self.narrative_text.configure(state="normal")
        self.narrative_text.delete("1.0", "end")
        self.narrative_text.insert("end", narrative)
        self.narrative_text.configure(state="disabled")

    # ──────────────────────────────────────────────
    # Evidence Loading
    # ──────────────────────────────────────────────
    def _load_pcap(self):
        path = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if path:
            self.session.add_evidence(path, "pcap")
            self.evidence_listbox.insert("end", f"[PCAP] {os.path.basename(path)}")
            self._log(f"Loaded PCAP: {path}")

    def _load_log(self):
        path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", "*.json *.csv *.xml *.log *.txt *.evtx"), ("All files", "*.*")]
        )
        if path:
            self.session.add_evidence(path, "log")
            self.evidence_listbox.insert("end", f"[LOG]  {os.path.basename(path)}")
            self._log(f"Loaded log: {path}")

    def _load_ioc_db(self):
        path = filedialog.askopenfilename(
            title="Select IOC Database",
            filetypes=[("IOC files", "*.csv *.json"), ("All files", "*.*")]
        )
        if path:
            if path.endswith(".csv"):
                count = self.ioc_db.load_csv(path)
            else:
                count = self.ioc_db.load_json(path)
            self.evidence_listbox.insert("end", f"[IOC]  {os.path.basename(path)} ({count} IOCs)")
            self._log(f"Loaded IOC database: {count} indicators from {path}")

    # ──────────────────────────────────────────────
    # Analysis Pipeline
    # ──────────────────────────────────────────────
    def _run_full_analysis(self):
        self.session.hunt_name = self.hunt_name_var.get()
        self.session.analyst_name = self.analyst_name_var.get()
        self.session_label.config(text=f"Session: {self.session.hunt_name}")
        self.all_findings = []

        # Reset v1.7 state
        self.enhanced_dns_findings    = []
        self.enhanced_exfil_findings  = []
        self.enhanced_beacon_findings = []
        self.unified_report           = {}

        if not self.session.evidence_files:
            messagebox.showwarning("No Evidence", "Please load at least one evidence file first.")
            return

        self._log("Starting full analysis pipeline...")

        # ── Stage 1: Baseline evidence analysis ──────────────────────────
        pcap_paths = []
        for evidence in self.session.evidence_files:
            path  = evidence["path"]
            etype = evidence["type"]

            if etype == "pcap":
                self._log(f"Running PCAP analysis: {os.path.basename(path)}")
                try:
                    analyzer = PCAPAnalyzer(path)
                    findings = analyzer.analyze()
                    self.session.pcap_findings.extend(findings)
                    self.all_findings.extend(findings)
                    self._log(f"PCAP: {len(findings)} findings")
                    self._write_to_tab(self.pcap_text, json.dumps(findings, indent=2, default=str))
                    pcap_paths.append(path)
                except Exception as e:
                    self._log(f"PCAP error: {e}")

            elif etype == "log":
                self._log(f"Running log analysis: {os.path.basename(path)}")
                try:
                    analyzer = LogAnalyzer(path)
                    findings = analyzer.analyze()
                    self.session.log_findings.extend(findings)
                    self.all_findings.extend(findings)
                    self._log(f"Logs: {len(findings)} findings")
                    self._write_to_tab(self.log_text, json.dumps(findings, indent=2, default=str))
                except Exception as e:
                    self._log(f"Log error: {e}")

        # ── Stage 2: v1.7 Enhanced detection (runs on every loaded PCAP) ─
        if ENHANCED_MODULES_AVAILABLE and pcap_paths:
            for pcap_path in pcap_paths:
                self._run_enhanced_detection(pcap_path)
        else:
            if not ENHANCED_MODULES_AVAILABLE:
                self._log("Enhanced modules not available — skipping TLD/Exfil/Beaconing analysis.")

        # ── Stage 3: IOC Correlation ──────────────────────────────────────
        self._log("Running IOC correlation...")
        correlator = IOCCorrelator(self.ioc_db)
        correlator.extract_from_findings(self.all_findings)
        ioc_matches = correlator.correlate()
        self.session.ioc_matches = ioc_matches
        self.all_findings.extend(ioc_matches)
        self.ioc_summary = correlator.get_summary()
        self._log(f"IOC: {len(ioc_matches)} matches")
        self._write_to_tab(self.ioc_text, json.dumps(self.ioc_summary, indent=2, default=str))

        # ── Stage 4: Severity — unified score takes priority ──────────────
        if self.unified_risk_tier and self.unified_risk_tier != "Informational":
            # v1.7 unified score overrides the baseline determine_severity()
            self.session.severity = self.unified_risk_tier
            self._log(f"Severity set by unified risk model: {self.unified_risk_tier} "
                      f"({self.unified_risk_score}/100)")
        else:
            # Fallback to original logic if enhanced modules weren't available
            crit = sum(1 for f in self.all_findings if f.get("severity") == "Critical")
            ioc_count = len(ioc_matches)
            self.session.severity = determine_severity(ioc_count, crit)
            self._log(f"Severity set by baseline model: {self.session.severity}")

        # ── Stage 5: Hypotheses ───────────────────────────────────────────
        self._generate_hypotheses()
        self._update_stats()
        self._log(
            f"Analysis complete! {len(self.all_findings)} total findings. "
            f"Severity: {self.session.severity}"
        )

    def _run_enhanced_detection(self, pcap_path: str):
        """
        v1.7 enhanced detection pipeline:
          1. Suspicious TLD DNS  → finds C2 domains/IPs
          2. Exfil Direction     → corrects inbound vs outbound classification
          3. Beaconing           → detects periodic C2 check-in patterns
          4. Unified Risk Score  → aggregates all three into a single score

        Results are stored in instance state and rendered into the
        Threat Intel tab. High-severity findings are also injected
        into all_findings so they appear in the main finding count
        and hypothesis generator.
        """
        self._log(f"[v1.7] Running enhanced detection on {os.path.basename(pcap_path)}...")

        try:
            # ── TLD DNS ──────────────────────────────────────────────────
            self._log("[v1.7] Stage 1/3 — Suspicious TLD DNS analysis...")
            dns_alerts       = analyze_suspicious_tld_dns(pcap_path)
            dns_findings     = fmt_dns_alerts(dns_alerts)
            known_c2_ips     = {ip for a in dns_alerts for ip in a.resolved_ips}
            known_c2_domains = {a.domain for a in dns_alerts}
            self.enhanced_dns_findings.extend(dns_findings)
            self._log(
                f"[v1.7] TLD DNS: {len(dns_findings)} suspicious domain(s) found. "
                f"C2 IPs: {known_c2_ips or 'none'}"
            )
            self._update_module_badge("TLD DNS", len(dns_findings))

            # ── Exfil Direction ──────────────────────────────────────────
            self._log("[v1.7] Stage 2/3 — Exfiltration direction analysis...")
            exfil_alerts   = analyze_exfiltration_direction(pcap_path, known_c2_ips)
            exfil_findings = fmt_exfil_alerts(exfil_alerts)
            self.enhanced_exfil_findings.extend(exfil_findings)
            outbound = sum(
                1 for f in exfil_findings
                if "OUTBOUND" in f.get("direction", "") or "BEACONING" in f.get("direction", "")
            )
            staging  = sum(1 for f in exfil_findings if f.get("direction") == "INBOUND_STAGING")
            self._log(
                f"[v1.7] Exfil Direction: {outbound} outbound exfil, "
                f"{staging} inbound staging (correctly labeled)"
            )
            self._update_module_badge("Exfil Direction", len(exfil_findings))

            # ── Beaconing ────────────────────────────────────────────────
            self._log("[v1.7] Stage 3/3 — Beaconing detection...")
            beacon_alerts   = analyze_beaconing(pcap_path, known_c2_ips, known_c2_domains)
            beacon_findings = fmt_beacon_alerts(beacon_alerts)
            self.enhanced_beacon_findings.extend(beacon_findings)
            self._log(
                f"[v1.7] Beaconing: {len(beacon_findings)} beacon pattern(s) detected"
            )
            self._update_module_badge("Beaconing", len(beacon_findings))

            # ── Unified Risk Score ────────────────────────────────────────
            self._log("[v1.7] Computing unified risk score...")
            unified = compute_unified_risk(
                dns_findings    = dns_findings,
                exfil_findings  = exfil_findings,
                beacon_findings = beacon_findings,
                pcap_file       = os.path.basename(pcap_path),
                analyst         = self.analyst_name_var.get(),
                hunt_id         = self.hunt_name_var.get(),
            )
            self.unified_report     = report_to_dict(unified)
            self.unified_risk_score = unified.normalized_score
            self.unified_risk_tier  = unified.risk_tier

            self._log(
                f"[v1.7] Unified risk score: {self.unified_risk_score}/100 "
                f"({self.unified_risk_tier})"
            )

            # ── Inject high-confidence findings into main finding list ────
            # This ensures the hypothesis generator and report see them
            for f in dns_findings + exfil_findings + beacon_findings:
                if f.get("severity") in ("Critical", "High"):
                    # Tag as enhanced so baseline modules don't double-count
                    f["source_module"] = "tha_v17_enhanced"
                    self.all_findings.append(f)

            # ── Render Threat Intel tab ───────────────────────────────────
            self._render_intel_tab(unified)

        except Exception as e:
            self._log(f"[v1.7] Enhanced detection error: {e}")
            import traceback
            self._log(traceback.format_exc())

    def _update_module_badge(self, module_name: str, finding_count: int):
        """Update the status badge for an enhanced module in the Threat Intel tab."""
        badge = self.module_badges.get(module_name)
        if not badge:
            return
        if finding_count == 0:
            badge.config(text=f"● {module_name}: Clean", fg=SUCCESS)
        elif finding_count == 1:
            badge.config(text=f"● {module_name}: {finding_count} finding", fg=HIGH)
        else:
            badge.config(text=f"● {module_name}: {finding_count} findings", fg=CRITICAL)

    def _render_intel_tab(self, unified_report):
        """
        Populate the Threat Intel tab with unified risk score,
        IOC inventory, and per-module finding detail.
        """
        # Risk score banner
        score = unified_report.normalized_score
        tier  = unified_report.risk_tier
        tier_colors = {
            "Critical":      CRITICAL,
            "High":          HIGH,
            "Medium":        MEDIUM,
            "Low":           LOW,
            "Informational": MUTED,
        }
        color = tier_colors.get(tier, MUTED)
        self.risk_score_label.config(text=f"{score}/100", fg=color)
        self.risk_tier_label.config(text=f"[ {tier.upper()} ]", fg=color)

        # IOC inventory
        ioc_lines = []
        if unified_report.confirmed_c2_domains:
            ioc_lines.append(f"C2 Domains : {', '.join(unified_report.confirmed_c2_domains)}")
        if unified_report.confirmed_c2_ips:
            ioc_lines.append(f"C2 IPs     : {', '.join(unified_report.confirmed_c2_ips)}")
        if unified_report.staging_ips:
            ioc_lines.append(f"Staging IPs: {', '.join(unified_report.staging_ips)}")
        if not ioc_lines:
            ioc_lines.append("No confirmed C2 IOCs identified.")

        self._write_to_tab(self.ioc_inventory_text, "\n".join(ioc_lines))

        # Full detail output — organized by module
        report_dict = report_to_dict(unified_report)
        detail_lines = []

        # Score breakdown
        bd = report_dict.get("risk_assessment", {}).get("score_breakdown", {})
        detail_lines += [
            "═" * 60,
            "SCORE BREAKDOWN",
            "═" * 60,
            f"  Base (highest finding) : {bd.get('base_score_highest_finding', 0)}",
        ]
        cb = bd.get("convergence_bonus", {})
        detail_lines.append(
            f"  Convergence bonus      : +{cb.get('bonus', 0)}  "
            f"({cb.get('explanation', '')})"
        )
        kc = bd.get("kill_chain_bonus", {})
        detail_lines.append(
            f"  Kill chain bonus       : +{kc.get('bonus', 0)}  "
            f"Stages: {kc.get('stages_covered', [])}"
        )
        bb = bd.get("breadth_bonus", {})
        detail_lines.append(
            f"  Breadth bonus          : +{bb.get('bonus', 0)}  "
            f"({bb.get('total_findings', 0)} findings)"
        )
        detail_lines.append(f"  Raw total              : {bd.get('raw_score_total', 0)}")
        detail_lines.append(f"  Normalized (0-100)     : {report_dict['risk_assessment']['normalized_score']}")

        # MITRE coverage
        mitre = report_dict.get("mitre_coverage", {})
        detail_lines += [
            "",
            "═" * 60,
            "MITRE ATT&CK",
            "═" * 60,
            f"  Techniques   : {', '.join(mitre.get('techniques', []))}",
            f"  Kill Chain   : {', '.join(mitre.get('kill_chain_stages', []))}",
        ]

        # IOC correlations
        correlations = report_dict.get("ioc_correlations", [])
        if correlations:
            detail_lines += ["", "═" * 60, "IOC CONVERGENCE (cross-module)", "═" * 60]
            for c in correlations:
                bar = "▓" * c["convergence"] + "░" * (3 - c["convergence"])
                detail_lines.append(
                    f"  [{bar}] {c['ioc']}  —  {c['convergence']}/3 modules  "
                    f"| {c['finding_types']}"
                )

        # Per-module findings
        findings_by_module = report_dict.get("findings", {})
        module_labels = {
            "dns":       "TLD DNS FINDINGS",
            "exfil":     "EXFILTRATION DIRECTION FINDINGS",
            "beaconing": "BEACONING FINDINGS",
        }
        for key, label in module_labels.items():
            module_findings = findings_by_module.get(key, [])
            detail_lines += ["", "═" * 60, label, "═" * 60]
            if not module_findings:
                detail_lines.append("  No findings.")
            for f in module_findings:
                detail_lines += [
                    f"  TYPE     : {f.get('type', '')}",
                    f"  SEVERITY : {f.get('severity', '')}  |  RISK: {f.get('risk_score', 0)}",
                    f"  SOURCE   : {f.get('source', '')} → {f.get('destination', '')}",
                    f"  MITRE    : {f.get('mitre', '')}",
                    f"  DETAIL   : {f.get('detail', '')}",
                    "",
                ]

        # Adversary narrative
        narrative = report_dict.get("narrative", {})
        detail_lines += [
            "═" * 60,
            "ADVERSARY NARRATIVE",
            "═" * 60,
            f"  {narrative.get('adversary_narrative', '')}",
            "",
            "═" * 60,
            "RECOMMENDED ACTIONS",
            "═" * 60,
        ]
        for i, action in enumerate(report_dict.get("recommended_actions", []), 1):
            detail_lines.append(f"  {i:02d}. {action}")

        self._write_to_tab(self.intel_detail_text, "\n".join(detail_lines))

    def _generate_hypotheses(self):
        if not self.all_findings:
            messagebox.showinfo("No Findings", "Run full analysis first to generate hypotheses.")
            return
        self._log("Generating hunt hypotheses...")
        gen = HypothesisGenerator()
        hypotheses = gen.generate(self.all_findings)
        self.hyp_summary = gen.get_summary()

        # Format for display
        output_lines = []
        for h in hypotheses:
            output_lines.append(f"{'='*70}")
            output_lines.append(f"{h['id']} [{h['severity']}]")
            output_lines.append(f"{h['hypothesis']}")
            if h.get("mitre_technique_id"):
                output_lines.append(f"MITRE: {h['mitre_technique_id']} — {h.get('mitre_technique_name', '')}")
                output_lines.append(f"Tactic: {h.get('mitre_tactic', '')}")
            output_lines.append("")

        output_lines.append(f"{'='*70}")
        output_lines.append(f"ADVERSARY NARRATIVE:\n{self.hyp_summary.get('adversary_narrative', '')}")

        self._write_to_tab(self.hyp_text, "\n".join(output_lines))
        self._update_stats()
        self._log(f"Generated {len(hypotheses)} hypotheses covering {self.hyp_summary.get('mitre_techniques_covered', 0)} MITRE techniques")

    # ──────────────────────────────────────────────
    # Reporting
    # ──────────────────────────────────────────────
    def _export_html(self):
        path = filedialog.asksaveasfilename(
            title="Save HTML Report",
            defaultextension=".html",
            filetypes=[("HTML", "*.html")]
        )
        if path:
            builder = ReportBuilder(
                self.session,
                self.hyp_summary,
                self.ioc_summary,
                unified_report     = self.unified_report,
                unified_risk_score = self.unified_risk_score,
                unified_risk_tier  = self.unified_risk_tier,
                total_findings     = len(self.all_findings),
            )
            builder.build_html(path)
            self._log(f"HTML report saved → {path}")
            messagebox.showinfo("Report Saved", f"HTML report exported to:\n{path}")

    def _export_pdf(self):
        path = filedialog.asksaveasfilename(
            title="Save PDF Report",
            defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf")]
        )
        if path:
            builder = ReportBuilder(
                self.session,
                self.hyp_summary,
                self.ioc_summary,
                unified_report     = self.unified_report,
                unified_risk_score = self.unified_risk_score,
                unified_risk_tier  = self.unified_risk_tier,
                total_findings     = len(self.all_findings),
            )
            success = builder.build_pdf(path)
            if success:
                self._log(f"PDF report saved → {path}")
                messagebox.showinfo("Report Saved", f"PDF report exported to:\n{path}")
            else:
                html_path = path.replace(".pdf", ".html")
                self._log(f"PDF generation failed. HTML saved → {html_path}")
                messagebox.showwarning("PDF Failed", f"WeasyPrint unavailable. HTML report saved:\n{html_path}")

    def _save_session(self):
        path = self.session.save("output")
        self._log(f"Session saved → {path}")
        messagebox.showinfo("Session Saved", f"Session saved to:\n{path}")


if __name__ == "__main__":
    app = THAApp()
    app.mainloop()