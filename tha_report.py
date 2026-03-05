"""
THA Report Builder
Generates polished, SOC-ready HTML → PDF hunt reports.
eCTHP-aligned: Hunt Step 5 — Documentation & Reporting
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, BaseLoader

logger = logging.getLogger("THA.report")

SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High":     "#ea580c",
    "Medium":   "#d97706",
    "Low":      "#16a34a",
    "info":     "#6b7280",
}

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>THA Hunt Report — {{ session.hunt_name }}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap');

  :root {
    --bg:        #0f1117;
    --surface:   #1a1d27;
    --border:    #2d3047;
    --text:      #e2e8f0;
    --muted:     #64748b;
    --accent:    #38bdf8;
    --critical:  #dc2626;
    --high:      #ea580c;
    --medium:    #d97706;
    --low:       #16a34a;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Inter', sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 0;
  }

  .cover {
    background: linear-gradient(135deg, #0f1117 0%, #1a1d27 50%, #0c1929 100%);
    border-bottom: 3px solid var(--accent);
    padding: 60px 48px 40px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }

  .cover-title {
    font-size: 36px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.5px;
  }

  .cover-subtitle {
    font-size: 16px;
    color: var(--muted);
    margin-top: 4px;
    font-family: 'JetBrains Mono', monospace;
  }

  .cover-meta {
    text-align: right;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--muted);
    line-height: 2;
  }

  .severity-badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 13px;
    letter-spacing: 0.5px;
    font-family: 'JetBrains Mono', monospace;
  }

  .sev-Critical { background: #7f1d1d; color: #fca5a5; border: 1px solid var(--critical); }
  .sev-High     { background: #7c2d12; color: #fdba74; border: 1px solid var(--high); }
  .sev-Medium   { background: #78350f; color: #fde68a; border: 1px solid var(--medium); }
  .sev-Low      { background: #14532d; color: #86efac; border: 1px solid var(--low); }
  .sev-info     { background: #1e293b; color: #94a3b8; border: 1px solid var(--muted); }

  .container { max-width: 1100px; margin: 0 auto; padding: 48px 48px; }

  .section { margin-bottom: 48px; }

  .section-title {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--accent);
    margin-bottom: 20px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 16px;
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 12px;
    gap: 12px;
  }

  .card-id {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--muted);
    flex-shrink: 0;
  }

  .hypothesis-text {
    font-size: 15px;
    line-height: 1.7;
    color: var(--text);
    flex: 1;
  }

  .mitre-tag {
    display: inline-block;
    background: #1e3a5f;
    border: 1px solid #2563eb;
    color: #93c5fd;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
    margin-top: 8px;
    margin-right: 4px;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 32px;
  }

  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    text-align: center;
  }

  .stat-number {
    font-size: 36px;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    color: var(--accent);
    line-height: 1;
  }

  .stat-label {
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 6px;
  }

  .narrative-box {
    background: #0c1929;
    border-left: 4px solid var(--accent);
    border-radius: 0 8px 8px 0;
    padding: 20px 24px;
    font-size: 15px;
    line-height: 1.8;
    color: #cbd5e1;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  th {
    text-align: left;
    padding: 10px 14px;
    background: #1e2235;
    color: var(--muted);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 11px;
    border-bottom: 2px solid var(--border);
  }

  td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #94a3b8;
    vertical-align: top;
  }

  tr:hover td { background: #1a1d27; }

  .mitre-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
  }

  .mitre-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px;
  }

  .mitre-id {
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    color: #60a5fa;
    font-weight: 700;
  }

  .mitre-name {
    font-size: 12px;
    color: var(--text);
    margin-top: 4px;
  }

  .mitre-tactic {
    font-size: 10px;
    color: var(--muted);
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .footer {
    border-top: 1px solid var(--border);
    padding: 24px 48px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 11px;
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
  }

  @media print {
    body { background: white; color: black; }
    .cover { background: #1a1d27; -webkit-print-color-adjust: exact; }
  }
</style>
</head>
<body>

<!-- COVER -->
<div class="cover">
  <div>
    <div class="cover-title">🛡 Threat Hunt Report</div>
    <div class="cover-subtitle">{{ session.hunt_name }}</div>
    <div style="margin-top: 20px;">
      <span class="severity-badge sev-{{ session.severity }}">{{ session.severity }} RISK</span>
    </div>
  </div>
  <div class="cover-meta">
    <div><strong>ANALYST</strong> {{ session.analyst_name }}</div>
    <div><strong>DATE</strong> {{ report_date }}</div>
    <div><strong>TOOL</strong> THA v1.0</div>
    <div><strong>eCTHP ALIGNED</strong></div>
  </div>
</div>

<div class="container">

<!-- STATS OVERVIEW -->
<div class="section">
  <div class="section-title">Hunt Summary</div>
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-number">{{ stats.total_hypotheses }}</div>
      <div class="stat-label">Hypotheses</div>
    </div>
    <div class="stat-card">
      <div class="stat-number">{{ stats.mitre_techniques }}</div>
      <div class="stat-label">MITRE Techniques</div>
    </div>
    <div class="stat-card">
      <div class="stat-number">{{ stats.ioc_matches }}</div>
      <div class="stat-label">IOC Matches</div>
    </div>
    <div class="stat-card">
      <div class="stat-number">{{ stats.evidence_files }}</div>
      <div class="stat-label">Evidence Files</div>
    </div>
  </div>
</div>

<!-- ADVERSARY NARRATIVE -->
{% if narrative %}
<div class="section">
  <div class="section-title">Adversary Narrative</div>
  <div class="narrative-box">{{ narrative }}</div>
</div>
{% endif %}

<!-- HYPOTHESES -->
{% if hypotheses %}
<div class="section">
  <div class="section-title">Hunt Hypotheses ({{ hypotheses|length }})</div>
  {% for h in hypotheses %}
  <div class="card">
    <div class="card-header">
      <div>
        <div class="hypothesis-text">{{ h.hypothesis }}</div>
        {% if h.mitre_technique_id %}
        <span class="mitre-tag">{{ h.mitre_technique_id }}</span>
        {% endif %}
        {% if h.mitre_tactic %}
        <span class="mitre-tag" style="border-color: #7c3aed; color: #c4b5fd; background: #2e1065;">{{ h.mitre_tactic }}</span>
        {% endif %}
      </div>
      <div style="display:flex; gap:8px; flex-direction:column; align-items:flex-end; flex-shrink:0;">
        <span class="severity-badge sev-{{ h.severity }}">{{ h.severity }}</span>
        <span class="card-id">{{ h.id }}</span>
      </div>
    </div>
  </div>
  {% endfor %}
</div>
{% endif %}

<!-- MITRE ATT&CK COVERAGE -->
{% if mitre_coverage %}
<div class="section">
  <div class="section-title">MITRE ATT&CK Coverage</div>
  <div class="mitre-grid">
    {% for tid, data in mitre_coverage.items() %}
    <div class="mitre-card">
      <div class="mitre-id">{{ tid }}</div>
      <div class="mitre-name">{{ data.technique }}</div>
      <div class="mitre-tactic">{{ data.tactic }}</div>
    </div>
    {% endfor %}
  </div>
</div>
{% endif %}

<!-- IOC MATCHES -->
{% if ioc_matches %}
<div class="section">
  <div class="section-title">IOC Matches ({{ ioc_matches|length }})</div>
  <table>
    <tr>
      <th>Type</th><th>Indicator</th><th>Severity</th><th>Source</th><th>Description</th>
    </tr>
    {% for m in ioc_matches %}
    <tr>
      <td>{{ m.ioc_type }}</td>
      <td>{{ m.value }}</td>
      <td><span class="severity-badge sev-{{ m.severity }}">{{ m.severity }}</span></td>
      <td>{{ m.source }}</td>
      <td>{{ m.description[:80] }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endif %}

<!-- PCAP FINDINGS -->
{% if pcap_findings %}
<div class="section">
  <div class="section-title">Network Analysis Findings</div>
  <table>
    <tr><th>Type</th><th>Severity</th><th>Source</th><th>Destination</th><th>Detail</th></tr>
    {% for f in pcap_findings %}
    <tr>
      <td>{{ f.type }}</td>
      <td><span class="severity-badge sev-{{ f.severity }}">{{ f.severity }}</span></td>
      <td>{{ f.get('src', '—') }}</td>
      <td>{{ f.get('dst', '—') }}</td>
      <td>{{ f.detail[:100] }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endif %}

<!-- LOG FINDINGS -->
{% if log_findings %}
<div class="section">
  <div class="section-title">Log Analysis Findings</div>
  <table>
    <tr><th>Type</th><th>Severity</th><th>MITRE</th><th>Detail</th></tr>
    {% for f in log_findings %}
    <tr>
      <td>{{ f.type }}</td>
      <td><span class="severity-badge sev-{{ f.severity }}">{{ f.severity }}</span></td>
      <td>{{ f.get('mitre', '—') }}</td>
      <td>{{ f.detail[:120] }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endif %}

<!-- ANALYST NOTES -->
{% if analyst_notes %}
<div class="section">
  <div class="section-title">Analyst Notes</div>
  <div class="narrative-box" style="border-color: #7c3aed;">{{ analyst_notes }}</div>
</div>
{% endif %}

<!-- EVIDENCE FILES -->
{% if evidence_files %}
<div class="section">
  <div class="section-title">Evidence Files Analyzed</div>
  <table>
    <tr><th>File</th><th>Type</th><th>Loaded</th></tr>
    {% for e in evidence_files %}
    <tr>
      <td>{{ e.path }}</td>
      <td>{{ e.type }}</td>
      <td>{{ e.loaded_at }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endif %}

</div>

<div class="footer">
  <span>Threat Hunting Assistant (THA) — eCTHP Aligned</span>
  <span>Generated: {{ report_date }} | {{ session.analyst_name }}</span>
</div>

</body>
</html>
"""


class ReportBuilder:
    """Generates SOC-ready HTML hunt reports from a THA session."""

    def __init__(self, session, hypothesis_summary: dict = None, ioc_summary: dict = None):
        self.session = session
        self.hyp_summary = hypothesis_summary or {}
        self.ioc_summary = ioc_summary or {}

    def build_html(self, output_path: str = None) -> str:
        env = Environment(loader=BaseLoader())
        env.globals["enumerate"] = enumerate
        template = env.from_string(REPORT_TEMPLATE)

        stats = {
            "total_hypotheses": len(self.hyp_summary.get("hypotheses", [])),
            "mitre_techniques": len(self.hyp_summary.get("mitre_coverage", {})),
            "ioc_matches": self.ioc_summary.get("match_count", 0),
            "evidence_files": len(self.session.evidence_files),
        }

        html = template.render(
            session=self.session,
            report_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            stats=stats,
            narrative=self.hyp_summary.get("adversary_narrative", ""),
            hypotheses=self.hyp_summary.get("hypotheses", []),
            mitre_coverage=self.hyp_summary.get("mitre_coverage", {}),
            ioc_matches=self.ioc_summary.get("matches", []),
            pcap_findings=self.session.pcap_findings,
            log_findings=self.session.log_findings,
            analyst_notes=self.session.analyst_notes,
            evidence_files=self.session.evidence_files,
        )

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)
            logger.info(f"HTML report → {output_path}")

        return html

    def build_pdf(self, output_path: str) -> bool:
        """Convert HTML report to PDF using weasyprint."""
        try:
            from weasyprint import HTML as WHTML
            html_content = self.build_html()
            WHTML(string=html_content).write_pdf(output_path)
            logger.info(f"PDF report → {output_path}")
            return True
        except ImportError:
            logger.warning("WeasyPrint not installed. Run: pip install weasyprint")
            # Fallback: save HTML
            html_path = output_path.replace(".pdf", ".html")
            self.build_html(html_path)
            logger.info(f"Saved HTML fallback → {html_path}")
            return False
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            html_path = output_path.replace(".pdf", ".html")
            self.build_html(html_path)
            return False
