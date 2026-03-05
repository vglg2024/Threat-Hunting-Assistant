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

        if not self.session.evidence_files:
            messagebox.showwarning("No Evidence", "Please load at least one evidence file first.")
            return

        self._log("Starting full analysis pipeline...")

        # Analyze each evidence file
        for evidence in self.session.evidence_files:
            path = evidence["path"]
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

        # IOC Correlation
        self._log("Running IOC correlation...")
        correlator = IOCCorrelator(self.ioc_db)
        correlator.extract_from_findings(self.all_findings)
        ioc_matches = correlator.correlate()
        self.session.ioc_matches = ioc_matches
        self.all_findings.extend(ioc_matches)
        self.ioc_summary = correlator.get_summary()
        self._log(f"IOC: {len(ioc_matches)} matches")
        self._write_to_tab(self.ioc_text, json.dumps(self.ioc_summary, indent=2, default=str))

        # Update severity
        crit = sum(1 for f in self.all_findings if f.get("severity") == "Critical")
        ioc_count = len(ioc_matches)
        self.session.severity = determine_severity(ioc_count, crit)

        # Generate Hypotheses
        self._generate_hypotheses()
        self._update_stats()
        self._log(f"Analysis complete! {len(self.all_findings)} total findings. Severity: {self.session.severity}")

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
            builder = ReportBuilder(self.session, self.hyp_summary, self.ioc_summary)
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
            builder = ReportBuilder(self.session, self.hyp_summary, self.ioc_summary)
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
