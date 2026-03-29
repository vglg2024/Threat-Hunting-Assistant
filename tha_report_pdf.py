"""
tha_report_pdf.py
=================
Drop-in PDF report builder for the Threat Hunting Assistant (THA).
Fixes all table clipping, wrapping, and contrast issues from v1.0.

INTEGRATION — two options:

Option A (recommended — minimal changes to tha_report.py):
    In tha_report.py, replace the build_pdf() method body with:

        from tha_report_pdf import build_pdf_report
        return build_pdf_report(self, path)

Option B (full replacement):
    Import and call build_pdf_report() directly anywhere you need
    a PDF from a ReportBuilder (or equivalent dict) object.

REQUIRES: reportlab  (pip install reportlab)
"""

from __future__ import annotations
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime

# ── page geometry ─────────────────────────────────────────────────────────────
PW, PH   = letter
LM = RM  = 0.55 * inch
TM = BM  = 0.60 * inch
TW        = PW - LM - RM          # 7.4"

# ── colour palette ────────────────────────────────────────────────────────────
C_NAVY    = colors.HexColor("#0d1b2a")
C_BLUE    = colors.HexColor("#023e8a")
C_GREEN   = colors.HexColor("#1b4332")
C_RED     = colors.HexColor("#c0392b")
C_ORANGE  = colors.HexColor("#e67e22")
C_YELLOW  = colors.HexColor("#f39c12")
C_TEAL    = colors.HexColor("#0097a7")
C_WHITE   = colors.white
C_BLACK   = colors.black
C_DARK    = colors.HexColor("#1a1a1a")
C_MID     = colors.HexColor("#444444")
C_LIGHT   = colors.HexColor("#888888")
C_ROW_ALT = colors.HexColor("#f0f6ff")
C_ROW_WH  = colors.white
C_GOLD    = colors.HexColor("#e9c46a")
C_LTGRN   = colors.HexColor("#e8f5e9")
C_LTRED   = colors.HexColor("#fde8e8")
C_LTYEL   = colors.HexColor("#fff8e1")
C_LTBLUE  = colors.HexColor("#e3f2fd")

SEVERITY_COLORS = {
    "Critical":      (colors.HexColor("#7b0000"), C_WHITE),
    "High":          (colors.HexColor("#c0392b"), C_WHITE),
    "Medium":        (colors.HexColor("#e67e22"), C_WHITE),   # white on orange — readable
    "Low":           (colors.HexColor("#27ae60"), C_WHITE),
    "Informational": (colors.HexColor("#2980b9"), C_WHITE),
}

RISK_TIER_COLORS = {
    "Critical":      C_RED,
    "High":          C_ORANGE,
    "Medium":        C_YELLOW,
    "Low":           colors.HexColor("#27ae60"),
    "Informational": C_TEAL,
}

# ── style factory ─────────────────────────────────────────────────────────────
_sid = [0]
def _S(**kw) -> ParagraphStyle:
    _sid[0] += 1
    return ParagraphStyle(f"_s{_sid[0]}", **kw)

# text styles
sH1   = _S(fontName="Helvetica-Bold", fontSize=13, textColor=C_WHITE,
           leading=17, spaceBefore=10, spaceAfter=5)
sH2   = _S(fontName="Helvetica-Bold", fontSize=10, textColor=C_BLUE,
           leading=13, spaceBefore=8,  spaceAfter=4)
sH3   = _S(fontName="Helvetica-Bold", fontSize=9,  textColor=C_GREEN,
           leading=12, spaceBefore=6,  spaceAfter=3)
sBODY = _S(fontName="Helvetica",      fontSize=8,  textColor=C_DARK,
           leading=11, spaceAfter=2)
sBOLDb= _S(fontName="Helvetica-Bold", fontSize=8,  textColor=C_BLACK,
           leading=11, spaceAfter=2)
sMONO = _S(fontName="Courier",        fontSize=7.5,textColor=C_DARK,
           leading=10, spaceAfter=2, wordWrap="CJK")
sMONOg= _S(fontName="Courier",        fontSize=7.5,textColor=C_GREEN,
           leading=10, spaceAfter=2, wordWrap="CJK")

# table cell styles — ALL with wordWrap="CJK" so text never clips
sCELL  = _S(fontName="Helvetica",      fontSize=8,   textColor=C_DARK,
            leading=11, wordWrap="CJK")
sCELLb = _S(fontName="Helvetica-Bold", fontSize=8,   textColor=C_BLACK,
            leading=11, wordWrap="CJK")
sHDR   = _S(fontName="Helvetica-Bold", fontSize=8,   textColor=C_WHITE,
            leading=11, wordWrap="CJK")
sCODE  = _S(fontName="Courier",        fontSize=7,   textColor=C_DARK,
            leading=9,  wordWrap="CJK")
sSEV   = _S(fontName="Helvetica-Bold", fontSize=7.5, textColor=C_WHITE,
            leading=10, alignment=TA_CENTER, wordWrap="CJK")

# cover / title styles
sCOVER_TITLE = _S(fontName="Helvetica-Bold", fontSize=26, textColor=C_WHITE,
                  alignment=TA_CENTER, leading=32)
sCOVER_SUB   = _S(fontName="Helvetica",      fontSize=11, textColor=C_GOLD,
                  alignment=TA_CENTER, spaceAfter=4)
sCOVER_META  = _S(fontName="Helvetica",      fontSize=9,  textColor=C_LIGHT,
                  alignment=TA_CENTER, spaceAfter=3)

# info-box text
sWARN  = _S(fontName="Helvetica", fontSize=8, textColor=colors.HexColor("#5d3a00"),
            leading=11, leftIndent=4)
sALERT = _S(fontName="Helvetica-Bold", fontSize=8, textColor=C_RED,
            leading=11, leftIndent=4)
sTIP   = _S(fontName="Helvetica", fontSize=8, textColor=C_GREEN,
            leading=11, leftIndent=4)

# narrative
sNARR  = _S(fontName="Helvetica-Oblique", fontSize=9, textColor=C_DARK,
            leading=13, spaceAfter=4, leftIndent=8)


# ── helpers ───────────────────────────────────────────────────────────────────

def sp(n: int = 4) -> Spacer:
    return Spacer(1, n)

def hr(color=C_MID) -> HRFlowable:
    return HRFlowable(width="100%", thickness=0.4, color=color,
                      spaceAfter=3, spaceBefore=3)

def _esc(s: str) -> str:
    """Escape XML special chars for ReportLab Paragraph."""
    if not isinstance(s, str):
        s = str(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def P(txt, style=sBODY) -> Paragraph:
    safe = txt if any(x in txt for x in ["<b>", "<font", "&amp;", "&lt;"]) \
           else _esc(txt)
    return Paragraph(safe, style)

def hbar(txt: str, bg=C_NAVY) -> Table:
    """Full-width coloured header bar."""
    t = Table([[P(txt, sH1)]], colWidths=[TW])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), bg),
        ("TOPPADDING",    (0,0),(-1,-1), 7),
        ("BOTTOMPADDING", (0,0),(-1,-1), 7),
        ("LEFTPADDING",   (0,0),(-1,-1), 10),
    ]))
    return t

def secbar(txt: str, bg=C_BLUE) -> Table:
    return hbar(txt, bg)

def _cell(v) -> Paragraph:
    """Convert anything to a wrapping Paragraph table cell."""
    if isinstance(v, Paragraph):
        return v
    return Paragraph(_esc(str(v)), sCELL)

def _hcell(v) -> Paragraph:
    """Bold white header cell."""
    if isinstance(v, Paragraph):
        return v
    return Paragraph(f"<b>{_esc(str(v))}</b>", sHDR)

def severity_badge(level: str) -> Paragraph:
    """Coloured severity badge — white text on coloured bg, always readable."""
    bg, fg = SEVERITY_COLORS.get(level, SEVERITY_COLORS["Informational"])
    st = _S(fontName="Helvetica-Bold", fontSize=7, textColor=fg,
            backColor=bg, alignment=TA_CENTER, leading=9,
            borderPadding=(2, 5, 2, 5), wordWrap="CJK")
    return Paragraph(level.upper(), st)

def tbl(rows, widths, hdr=True) -> Table:
    """
    Build a table where EVERY cell wraps properly.
    rows: list of lists — plain strings or Paragraph objects.
    """
    data = []
    for i, row in enumerate(rows):
        if i == 0 and hdr:
            data.append([_hcell(c) for c in row])
        else:
            data.append([_cell(c) for c in row])
    t = Table(data, colWidths=widths)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_BLUE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_ROW_WH, C_ROW_ALT]),
        ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 5),
        ("RIGHTPADDING",  (0,0), (-1,-1), 5),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    return t

def box(paras, bg=C_LTYEL) -> Table:
    """Info box with coloured background."""
    inner = Table([[p] for p in paras], colWidths=[TW - 0.2*inch])
    inner.setStyle(TableStyle([
        ("TOPPADDING",    (0,0),(-1,-1), 2),
        ("BOTTOMPADDING", (0,0),(-1,-1), 2),
        ("LEFTPADDING",   (0,0),(-1,-1), 4),
    ]))
    outer = Table([[inner]], colWidths=[TW])
    outer.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), bg),
        ("BOX",           (0,0),(-1,-1), 0.5, C_MID),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
    ]))
    return outer

def alert_box(txt, lbl="🚨 CRITICAL") -> Table:
    return box([P(f"<b>{lbl}:</b>  {_esc(txt)}", sALERT)], C_LTRED)
def warn_box(txt, lbl="⚠  WARNING") -> Table:
    return box([P(f"<b>{lbl}:</b>  {_esc(txt)}", sWARN)],  C_LTYEL)
def tip_box(txt, lbl="✔  NOTE") -> Table:
    return box([P(f"<b>{lbl}:</b>  {_esc(txt)}", sTIP)],   C_LTGRN)


# ── column width presets (7.4" total) ─────────────────────────────────────────
# Network Analysis findings (Type | Severity | Source | Destination | Detail)
W_NETWORK = [1.5*inch, 0.72*inch, 0.9*inch, 1.0*inch, 3.18*inch]

# Exfiltration table (Direction | Severity | Risk | Src→Dst | Bytes | MITRE | Detail)
W_EXFIL   = [0.90*inch, 0.65*inch, 0.40*inch, 1.28*inch, 0.90*inch, 0.54*inch, 2.73*inch]

# Beaconing table (Pattern/Stats | Proto | Severity | Risk | Src→Dst | MITRE/C2)
W_BEACON  = [1.55*inch, 0.42*inch, 0.65*inch, 0.38*inch, 1.3*inch, 3.1*inch]

# IOC convergence table (IOC | Modules | Finding Types | Detail)
W_IOC_CONV = [1.4*inch, 0.85*inch, 1.15*inch, 4.0*inch]

# Hypotheses table (ID | Severity | MITRE | Tactic | Hypothesis)
W_HYP = [0.55*inch, 0.72*inch, 0.85*inch, 1.1*inch, 4.18*inch]

# MITRE coverage table (Technique ID | Name | Tactic | Source)
W_MITRE = [0.85*inch, 2.0*inch, 1.35*inch, 3.2*inch]


# ── section builders ──────────────────────────────────────────────────────────

def _cover_page(report: dict, story: list):
    """Page 1 — cover with hunt metadata and risk score."""
    meta    = report.get("hunt_metadata", {})
    risk    = report.get("risk_assessment", {})
    score   = risk.get("normalized_score", 0)
    tier    = risk.get("risk_tier", "Informational")
    tier_c  = RISK_TIER_COLORS.get(tier, C_TEAL)

    # Title bar
    cover_bar = Table(
        [[P("THA  Threat Hunt Report", sCOVER_TITLE)]],
        colWidths=[TW]
    )
    cover_bar.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), C_NAVY),
        ("TOPPADDING",    (0,0),(-1,-1), 22),
        ("BOTTOMPADDING", (0,0),(-1,-1), 22),
    ]))
    story += [cover_bar, sp(6)]

    # Hunt ID + analyst row
    hunt_id  = meta.get("hunt_id",  "Hunt-001")
    analyst  = meta.get("analyst",  "Analyst")
    gen_time = meta.get("generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    story += [
        P(f"<b>{hunt_id}</b>", sCOVER_SUB),
        P(f"Analyst: {analyst}  ·  Generated: {gen_time}  ·  Tool: THA", sCOVER_META),
        sp(8),
    ]

    # Risk score banner
    risk_bar_data = [[
        Paragraph(f"<b>{score}/100</b>",
                  _S(fontName="Helvetica-Bold", fontSize=28,
                     textColor=tier_c, alignment=TA_CENTER, leading=34)),
        Paragraph(f"<b>[ {tier.upper()} RISK ]</b>",
                  _S(fontName="Helvetica-Bold", fontSize=16,
                     textColor=tier_c, alignment=TA_CENTER, leading=22)),
    ]]
    risk_bar = Table(risk_bar_data, colWidths=[TW * 0.35, TW * 0.65])
    risk_bar.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), C_NAVY),
        ("TOPPADDING",    (0,0),(-1,-1), 14),
        ("BOTTOMPADDING", (0,0),(-1,-1), 14),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
    ]))
    story += [risk_bar, sp(8)]

    # Summary stats row
    summary = report.get("summary", {})
    stats = [
        ("Findings",         str(summary.get("total_findings",      0)), C_ORANGE),
        ("Hypotheses",       str(summary.get("total_hypotheses",    0)), C_TEAL),
        ("IOC Matches",      str(summary.get("ioc_match_count",     0)), C_RED),
        ("MITRE TTPs",       str(summary.get("mitre_count",         0)), C_ORANGE),
    ]
    stat_cells = []
    for label, value, color in stats:
        cell_table = Table([
            [Paragraph(f"<b>{value}</b>",
                       _S(fontName="Helvetica-Bold", fontSize=26,
                          textColor=color, alignment=TA_CENTER, leading=32))],
            [Paragraph(label.upper(),
                       _S(fontName="Helvetica-Bold", fontSize=7,
                          textColor=C_LIGHT, alignment=TA_CENTER, leading=10))],
        ], colWidths=[TW / 4 - 0.1*inch])
        cell_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), C_NAVY),
            ("TOPPADDING",    (0,0),(-1,-1), 10),
            ("BOTTOMPADDING", (0,0),(-1,-1), 10),
        ]))
        stat_cells.append(cell_table)
    stats_row = Table([stat_cells], colWidths=[TW/4]*4)
    stats_row.setStyle(TableStyle([
        ("GRID",       (0,0),(-1,-1), 0.5, colors.HexColor("#2d3047")),
        ("TOPPADDING", (0,0),(-1,-1), 0),
        ("BOTTOMPADDING",(0,0),(-1,-1), 0),
    ]))
    story += [stats_row, sp(10)]

    # Adversary narrative
    narrative = report.get("narrative", {}).get("adversary_narrative", "")
    if narrative:
        story += [
            P("ADVERSARY NARRATIVE", sH2), hr(),
            P(narrative, sNARR),
            sp(8),
        ]

    # MITRE techniques on cover
    mitre = report.get("mitre_coverage", {})
    techniques = mitre.get("techniques", [])
    kill_chain  = mitre.get("kill_chain_stages", [])
    if techniques:
        story += [
            tbl(
                [["MITRE ATT&CK Techniques", "Kill Chain Stages"]] +
                [[" · ".join(techniques), " · ".join(kill_chain)]],
                [TW * 0.5, TW * 0.5]
            ),
            sp(6),
        ]


def _score_breakdown(report: dict, story: list):
    """Score breakdown section."""
    bd = report.get("risk_assessment", {}).get("score_breakdown", {})
    if not bd:
        return
    story += [secbar("UNIFIED RISK SCORE — Score Breakdown"), sp(6)]

    rows = [["Component", "Value", "Detail"]]
    base = bd.get("base_score_highest_finding", 0)
    rows.append(["Base (highest finding)", str(base), "Highest individual finding risk score"])

    cb = bd.get("convergence_bonus", {})
    rows.append(["Convergence bonus",
                 f"+{cb.get('bonus', 0)}",
                 cb.get("explanation", "")])

    kc = bd.get("kill_chain_bonus", {})
    rows.append(["Kill chain bonus",
                 f"+{kc.get('bonus', 0)}",
                 f"Stages: {', '.join(kc.get('stages_covered', []))}"])

    bb = bd.get("breadth_bonus", {})
    rows.append(["Breadth bonus",
                 f"+{bb.get('bonus', 0)}",
                 f"{bb.get('total_findings', 0)} total findings across modules"])

    raw   = bd.get("raw_score_total", 0)
    norm  = report.get("risk_assessment", {}).get("normalized_score", 0)
    tier  = report.get("risk_assessment", {}).get("risk_tier", "")
    rows.append(["Raw → Normalized", f"{raw} → {norm}/100", f"Tier: {tier}"])

    story += [tbl(rows, [1.8*inch, 1.0*inch, TW-2.8*inch]), sp(8)]


def _ioc_convergence(report: dict, story: list):
    """IOC convergence cross-module table."""
    correlations = report.get("ioc_correlations", [])
    if not correlations:
        return
    story += [secbar("IOC CONVERGENCE — Cross-Module Correlation"), sp(6)]

    rows = [["IOC", "Modules", "Finding Types", "Detail"]]
    for c in correlations:
        conv  = int(c.get("convergence", 0))
        bar   = "[" + "X" * conv + "-" * (3 - conv) + "]"
        # Replace underscores with spaces so text wraps at word boundaries
        ft_raw = c.get("finding_types", "")
        ft     = ft_raw.replace("_", " ") if isinstance(ft_raw, str) else ft_raw
        rows.append([
            c.get("ioc", ""),
            f"{bar} {conv}/3",
            ft,
            c.get("detail", ""),
        ])
    story += [tbl(rows, W_IOC_CONV), sp(8)]


def _network_findings(report: dict, story: list):
    """Network analysis findings — the table that was clipping Detail."""
    net_findings = report.get("network_findings", [])
    if not net_findings:
        return
    story += [secbar("NETWORK ANALYSIS FINDINGS"), sp(6)]

    rows = [["TYPE", "SEVERITY", "SOURCE", "DESTINATION", "DETAIL"]]
    for f in net_findings:
        rows.append([
            f.get("type", "").replace("_", " "),
            severity_badge(f.get("severity", "Informational")),
            f.get("source", "—"),
            f.get("destination", "—"),
            f.get("detail", ""),
        ])

    # Build table manually so severity_badge() cells work
    data = [[_hcell(c) for c in rows[0]]]
    for i, row in enumerate(rows[1:]):
        data.append([
            _cell(row[0]),
            row[1],          # already a Paragraph (severity_badge)
            _cell(row[2]),
            _cell(row[3]),
            _cell(row[4]),   # Detail — now has full 3.38" so it wraps
        ])

    t = Table(data, colWidths=W_NETWORK)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_BLUE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_ROW_WH, C_ROW_ALT]),
        ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 5),
        ("RIGHTPADDING",  (0,0), (-1,-1), 5),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story += [t, sp(8)]


def _fmt_bytes(f: dict) -> str:
    """Extract byte count from a finding — handles top-level or nested in f.evidence."""
    b = f.get("bytes") or f.get("size")
    if b is None:
        ev = f.get("evidence") or {}
        b  = ev.get("bytes_transferred") or ev.get("bytes")
    if b is None:
        return ""
    try:
        return f"{int(b):,}"
    except (ValueError, TypeError):
        return str(b)


def _exfil_findings(report: dict, story: list):
    """Exfiltration direction findings."""
    findings = report.get("findings", {}).get("exfil", [])
    if not findings:
        return
    story += [secbar("EXFILTRATION DIRECTION FINDINGS"), sp(6)]

    data = [[_hcell(c) for c in
             ["DIRECTION", "SEV", "R", "SOURCE → DEST", "BYTES", "MITRE", "DETAIL"]]]
    for i, f in enumerate(findings):
        direction = f.get("direction", f.get("type", ""))
        src  = f.get("source", "")
        dst  = f.get("destination", "")
        src_dst = f"{src} → {dst}" if src and dst else src or dst
        data.append([
            _cell(direction.replace("_", " ")),
            severity_badge(f.get("severity", "Informational")),
            _cell(str(f.get("risk_score", ""))),
            _cell(src_dst),
            _cell(_fmt_bytes(f)),
            _cell(f.get("mitre", "")),
            _cell(f.get("detail", "")),
        ])

    t = Table(data, colWidths=W_EXFIL)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_BLUE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_ROW_WH, C_ROW_ALT]),
        ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 5),
        ("RIGHTPADDING",  (0,0), (-1,-1), 5),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story += [t, sp(8)]


def _beacon_findings(report: dict, story: list):
    """Beaconing detection findings — Pattern/Stats column was too narrow."""
    findings = report.get("findings", {}).get("beaconing", [])
    if not findings:
        return
    story += [secbar("BEACONING DETECTION FINDINGS"), sp(6)]

    data = [[_hcell(c) for c in
             ["PATTERN / STATS", "PROTO", "SEV", "R", "SOURCE → DEST", "MITRE / C2 NOTE"]]]
    for f in findings:
        # Stats live at top level OR inside f.evidence (from tha_beaconing module)
        ev    = f.get("evidence", {}) or {}
        ptype = f.get("pattern_type", f.get("type", ""))
        stats_parts = [ptype.replace("_", " ").title()]
        sessions = f.get("sessions") or ev.get("session_count")
        interval = f.get("interval") or ev.get("mean_interval_s")
        cv       = f.get("cv")       or ev.get("cv")
        jitter   = f.get("jitter")   or ev.get("jitter_pct")
        if sessions: stats_parts.append(f"Sessions: {sessions}")
        if interval: stats_parts.append(f"Interval: {interval}s")
        if cv:       stats_parts.append(f"CV: {cv}")
        if jitter:   stats_parts.append(f"Jitter: ~{jitter}%")
        stats_text = "\n".join(stats_parts) if len(stats_parts) > 1 else ptype

        src = f.get("source", "")
        dst = f.get("destination", "")
        src_dst = f"{src} → {dst}" if src and dst else src or dst

        mitre_note = f.get("mitre", "")
        if not f.get("confirmed", True):
            mitre_note += " — suspected, pending process correlation"

        data.append([
            _cell(stats_text),
            _cell(f.get("protocol", f.get("proto", "TCP"))),
            severity_badge(f.get("severity", "Informational")),
            _cell(str(f.get("risk_score", ""))),
            _cell(src_dst),
            _cell(mitre_note),
        ])

    t = Table(data, colWidths=W_BEACON)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_BLUE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_ROW_WH, C_ROW_ALT]),
        ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 5),
        ("RIGHTPADDING",  (0,0), (-1,-1), 5),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story += [t, sp(8)]


def _dns_findings(report: dict, story: list):
    """Suspicious TLD / DNS findings."""
    findings = report.get("findings", {}).get("dns", [])
    if not findings:
        return
    story += [secbar("SUSPICIOUS TLD / DNS FINDINGS"), sp(6)]

    rows = [["TYPE", "SEVERITY", "DOMAIN / IOC", "MITRE", "DETAIL"]]
    for f in findings:
        rows.append([
            f.get("type", ""),
            severity_badge(f.get("severity", "Informational")),
            f.get("domain", f.get("source", f.get("ioc", ""))),
            f.get("mitre", ""),
            f.get("detail", ""),
        ])

    data = [[_hcell(c) for c in rows[0]]]
    for row in rows[1:]:
        data.append([_cell(row[0]), row[1], _cell(row[2]), _cell(row[3]), _cell(row[4])])

    t = Table(data, colWidths=[1.2*inch, 0.72*inch, 1.5*inch, 0.5*inch,
                                TW - 1.2*inch - 0.72*inch - 1.5*inch - 0.5*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_BLUE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_ROW_WH, C_ROW_ALT]),
        ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 5),
        ("RIGHTPADDING",  (0,0), (-1,-1), 5),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story += [t, sp(8)]


def _hypotheses_section(report: dict, story: list):
    """Hunt hypotheses."""
    hypotheses = report.get("hypotheses", [])
    if not hypotheses:
        return
    story += [secbar("HUNT HYPOTHESES"), sp(6)]

    rows = [["ID", "SEVERITY", "MITRE", "TACTIC", "HYPOTHESIS"]]
    for h in hypotheses:
        rows.append([
            h.get("id", ""),
            severity_badge(h.get("severity", "Informational")),
            h.get("mitre_technique_id", ""),
            h.get("mitre_tactic", ""),
            h.get("hypothesis", ""),
        ])

    data = [[_hcell(c) for c in rows[0]]]
    for row in rows[1:]:
        data.append([_cell(row[0]), row[1], _cell(row[2]), _cell(row[3]), _cell(row[4])])

    t = Table(data, colWidths=W_HYP)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_BLUE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_ROW_WH, C_ROW_ALT]),
        ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 5),
        ("RIGHTPADDING",  (0,0), (-1,-1), 5),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story += [t, sp(8)]


def _mitre_coverage(report: dict, story: list):
    """MITRE ATT&CK coverage table."""
    mitre = report.get("mitre_coverage", {})
    detail = mitre.get("technique_detail", [])
    if not detail:
        # fall back to simple list
        techniques = mitre.get("techniques", [])
        kill_chain  = mitre.get("kill_chain_stages", [])
        if techniques:
            story += [
                secbar("MITRE ATT&CK COVERAGE"), sp(6),
                tbl(
                    [["Technique IDs", "Kill Chain Stages"]] +
                    [[" · ".join(techniques), " · ".join(kill_chain)]],
                    [TW * 0.5, TW * 0.5]
                ),
                sp(8),
            ]
        return

    story += [secbar("MITRE ATT&CK COVERAGE"), sp(6)]
    rows = [["Technique ID", "Name", "Tactic", "Source / Finding"]]
    for td in detail:
        rows.append([
            td.get("id", ""),
            td.get("name", ""),
            td.get("tactic", ""),
            td.get("source", ""),
        ])
    story += [tbl(rows, W_MITRE), sp(8)]


def _recommended_actions(report: dict, story: list):
    """Recommended actions list."""
    actions = report.get("recommended_actions", [])
    if not actions:
        return
    story += [secbar("RECOMMENDED ACTIONS"), sp(6)]
    rows = [["#", "Action"]]
    for i, action in enumerate(actions, 1):
        rows.append([str(i).zfill(2), action])
    story += [tbl(rows, [0.4*inch, TW - 0.4*inch]), sp(8)]


def _evidence_files(report: dict, story: list):
    """Evidence files analyzed."""
    files = report.get("evidence_files", [])
    if not files:
        return
    story += [secbar("EVIDENCE FILES ANALYZED"), sp(6)]
    rows = [["File", "Type", "Loaded"]]
    for ef in files:
        rows.append([
            ef.get("path", ef.get("file", "")),
            ef.get("type", "pcap"),
            ef.get("loaded", ef.get("timestamp", "")),
        ])
    story += [tbl(rows, [4.2*inch, 0.7*inch, 2.5*inch]), sp(8)]


def _footer_page(report: dict, story: list):
    """Final page footer."""
    meta    = report.get("hunt_metadata", {})
    analyst = meta.get("analyst", "Analyst")
    gen     = meta.get("generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    story += [
        hr(C_BLUE),
        P(f"Threat Hunting Assistant (THA) — eCTHP Aligned  |  "
          f"Generated: {gen}  |  Analyst: {analyst}",
          _S(fontName="Helvetica", fontSize=7, textColor=C_LIGHT,
             alignment=TA_CENTER, leading=10)),
    ]


# ── public API ────────────────────────────────────────────────────────────────

def build_pdf_report(report_source, output_path: str) -> bool:
    """
    Build a fully-wrapped, high-contrast THA PDF report.

    Args:
        report_source:  Either a dict (from report_to_dict()) OR a
                        ReportBuilder instance that has a .to_dict() method
                        OR any object — we'll try .to_dict(), then vars(),
                        then treat as raw dict.
        output_path:    Full path for the output .pdf file.

    Returns:
        True on success, False on failure (caller should fall back to HTML).
    """
    try:
        # Normalise the report source to a plain dict
        if isinstance(report_source, dict):
            report = report_source
        elif hasattr(report_source, "to_dict"):
            report = report_source.to_dict()
        elif hasattr(report_source, "__dict__"):
            report = vars(report_source)
        else:
            report = dict(report_source)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=LM, rightMargin=RM,
            topMargin=TM,  bottomMargin=BM,
            title=f"THA Report — {report.get('hunt_metadata', {}).get('hunt_id', 'Hunt')}",
            author=report.get("hunt_metadata", {}).get("analyst", "THA"),
        )

        story = []

        # ── Cover page ────────────────────────────────────────────────────
        _cover_page(report, story)
        story.append(PageBreak())

        # ── Score breakdown ───────────────────────────────────────────────
        _score_breakdown(report, story)

        # ── IOC convergence ───────────────────────────────────────────────
        _ioc_convergence(report, story)

        # ── Enhanced detection tables (the ones that were clipping) ───────
        _dns_findings(report, story)
        _exfil_findings(report, story)
        _beacon_findings(report, story)

        # ── Network analysis findings ─────────────────────────────────────
        _network_findings(report, story)

        story.append(PageBreak())

        # ── Hypotheses ────────────────────────────────────────────────────
        _hypotheses_section(report, story)

        # ── MITRE coverage ────────────────────────────────────────────────
        _mitre_coverage(report, story)

        # ── Recommended actions ───────────────────────────────────────────
        _recommended_actions(report, story)

        # ── Evidence files ────────────────────────────────────────────────
        _evidence_files(report, story)

        # ── Footer ────────────────────────────────────────────────────────
        _footer_page(report, story)

        doc.build(story)
        return True

    except Exception as exc:
        import traceback
        traceback.print_exc()
        return False


# ── integration shim ──────────────────────────────────────────────────────────
# Paste this into tha_report.py to replace the existing build_pdf() method:
#
#   def build_pdf(self, path: str) -> bool:
#       from tha_report_pdf import build_pdf_report
#       return build_pdf_report(self._build_report_dict(), path)
#
# Where _build_report_dict() is whatever method you use to serialise the
# session into a dict (report_to_dict, to_dict, get_summary, etc.).
# If your ReportBuilder already produces a dict via report_to_dict(),
# just pass that directly:
#
#   def build_pdf(self, path: str) -> bool:
#       from tha_report_pdf import build_pdf_report
#       report_dict = report_to_dict(self.unified_report)
#       return build_pdf_report(report_dict, path)
#


if __name__ == "__main__":
    """Smoke-test with a synthetic report dict."""
    sample = {
        "hunt_metadata": {
            "hunt_id":   "Hunt-001",
            "analyst":   "Vincent Grace",
            "generated": "2026-03-28 20:29 UTC",
        },
        "risk_assessment": {
            "normalized_score": 58,
            "risk_tier":        "Medium",
            "score_breakdown": {
                "base_score_highest_finding": 70,
                "convergence_bonus": {"bonus": 20, "explanation": "2 modules confirmed same IOC"},
                "kill_chain_bonus":  {"bonus": 15, "stages_covered": ["Command and Control", "Resource Development"]},
                "breadth_bonus":     {"bonus": 12, "total_findings": 6},
                "raw_score_total":   117,
            },
        },
        "summary": {"total_findings": 7, "total_hypotheses": 3, "mitre_count": 3, "ioc_match_count": 0, "evidence_file_count": 1},
        "narrative": {"adversary_narrative":
            "Inbound staging activity detected: 1,193,163 bytes received from 104.21.37.143 — "
            "likely adversary tooling or payloads pushed to the compromised host (T1105). "
            "Beaconing from 10.1.5.131 to internal host 10.1.5.5 on port 135 suggests "
            "possible lateral movement or RPC-based C2."},
        "mitre_coverage": {
            "techniques":      ["T1071.001", "T1071.004", "T1105"],
            "kill_chain_stages": ["Command and Control", "Resource Development"],
        },
        "ioc_correlations": [
            {"ioc": "10.1.5.131", "convergence": 2, "finding_types": "exfil, beaconing",
             "detail": "Confirmed across 2 modules — primary suspect host"},
            {"ioc": "10.1.5.5",   "convergence": 1, "finding_types": "beaconing",
             "detail": "Internal destination — may be lateral movement target"},
        ],
        "findings": {
            "dns": [
                {"type": "dga_domain", "severity": "High",
                 "domain": "combining-space-correction.trycloudflare.com",
                 "mitre": "T1071.004",
                 "detail": "Possible DGA domain — high-entropy subdomain using Cloudflare tunnel. "
                            "Commonly abused for free C2 infrastructure."},
            ],
            "exfil": [
                {"type": "inbound_staging", "direction": "INBOUND_STAGING",
                 "severity": "Medium", "risk_score": 35,
                 "source": "104.21.37.143", "destination": "10.1.5.131:49431",
                 "bytes": "1,193,163", "mitre": "T1105",
                 "detail": "Large inbound transfer: 1,193,163 bytes from 104.21.37.143 → "
                            "10.1.5.131:49431. Classified as INBOUND STAGING — adversary "
                            "pushing tooling or payloads to compromised host."},
                {"type": "inbound_staging", "direction": "INBOUND_STAGING",
                 "severity": "Medium", "risk_score": 35,
                 "source": "144.31.221.71", "destination": "10.1.5.131:56441",
                 "bytes": "25,698,925", "mitre": "T1105",
                 "detail": "Large inbound transfer: 25,698,925 bytes from 144.31.221.71 → "
                            "10.1.5.131:56441. Second staging source detected."},
            ],
            "beaconing": [
                {"type": "beacon_jittered_interval", "severity": "Medium", "risk_score": 70,
                 "sessions": 7, "interval": 124.44, "cv": 0.3874, "jitter": 67.1,
                 "protocol": "TCP", "source": "10.1.5.131", "destination": "10.1.5.5:135",
                 "mitre": "T1071.001", "confirmed": False},
                {"type": "beacon_dns_beacon", "severity": "Medium", "risk_score": 45,
                 "sessions": 10, "interval": 106.66, "cv": 1.1846, "jitter": 100.0,
                 "protocol": "DNS", "source": "10.1.5.131",
                 "destination": "wpad.furtheringthemagic.com:53",
                 "mitre": "T1071.004", "confirmed": False},
            ],
        },
        "network_findings": [
            {"type": "potential_lateral_movement", "severity": "High",
             "source": "10.1.5.131", "destination": "10.1.5.5",
             "detail": "Internal-to-internal connection: 10.1.5.131 → 10.1.5.5:135. "
                        "Anomalous use of RPC port between internal hosts — possible lateral "
                        "movement via DCOM or WMI."},
            {"type": "icmp_large_payload", "severity": "High",
             "source": "10.1.5.131", "destination": "10.1.5.5",
             "detail": "ICMP packet with oversized payload detected. Normal ICMP is 32-56 bytes. "
                        "Oversized ICMP can indicate tunneling or covert C2 channel."},
            {"type": "suspicious_user_agent", "severity": "High",
             "source": "10.1.5.131", "destination": "144.31.221.60",
             "detail": "User-Agent 'curl/8.16.0' detected from workstation — not expected from "
                        "a standard user browser. Commonly seen in C2 scripts and automated tooling."},
            {"type": "suspicious_port", "severity": "High",
             "source": "10.1.5.131", "destination": "103.27.157.146",
             "detail": "Connection to Metasploit default listener port. Strong indicator of "
                        "active post-exploitation framework communication."},
            {"type": "non_standard_resolver", "severity": "Medium",
             "source": "10.1.5.131", "destination": "—",
             "detail": "DNS query sent to non-standard resolver 10.1.5.5. Malware frequently "
                        "uses custom resolvers to bypass corporate DNS filtering and monitoring."},
        ],
        "hypotheses": [
            {"id": "H-001", "severity": "High",
             "mitre_technique_id": "T1095", "mitre_tactic": "Command and Control",
             "hypothesis": "ICMP packets with oversized payloads between 10.1.5.131 and "
                           "10.1.5.5 indicate potential ICMP tunneling to covertly exfiltrate "
                           "data or establish C2."},
            {"id": "H-002", "severity": "High",
             "mitre_technique_id": "T1571", "mitre_tactic": "Command and Control",
             "hypothesis": "Non-standard port (4444) C2 communication from 10.1.5.131 to "
                           "103.27.157.146 — Metasploit default listener. Host may be compromised."},
            {"id": "H-003", "severity": "High",
             "mitre_technique_id": "T1041", "mitre_tactic": "Exfiltration",
             "hypothesis": "Significant outbound data transfer (26.7 MB) may indicate staged "
                           "exfiltration via the established C2 channel."},
        ],
        "recommended_actions": [
            "Investigate host 10.1.5.131 for signs of compromise",
            "Review DNS query history for 10.1.5.131",
            "Check endpoint security logs for 10.1.5.131",
            "Monitor suspicious IPs for continued communication",
            "Document findings and continue monitoring",
        ],
        "evidence_files": [
            {"path": "C:/Users/efmb2/OneDrive/Desktop/2026-01-08-KongTuke-activity-part-1-of-2.pcap",
             "type": "pcap", "loaded": "2026-03-28T20:25:59 UTC"},
        ],
    }

    out = "/mnt/user-data/outputs/THA_Report_Fixed.pdf"
    ok  = build_pdf_report(sample, out)
    print(f"{'OK' if ok else 'FAILED'} → {out}")
