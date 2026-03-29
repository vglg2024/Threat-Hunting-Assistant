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
    color: #e2e8f0;
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
    color: #64748b;
    margin-top: 4px;
    font-family: 'JetBrains Mono', monospace;
  }

  .cover-meta {
    text-align: right;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #64748b;
    line-height: 2;
  }

  .severity-badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0;
    font-family: 'JetBrains Mono', monospace;
    white-space: nowrap;
  }

  .sev-Critical { background: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626; }
  .sev-High     { background: #7c2d12; color: #fdba74; border: 1px solid #ea580c; }
  .sev-Medium   { background: #78350f; color: #fde68a; border: 1px solid #d97706; }
  .sev-Low      { background: #14532d; color: #86efac; border: 1px solid #16a34a; }
  .sev-info     { background: #1e293b; color: #94a3b8; border: 1px solid #64748b; }

  /* In table cells, badges must never exceed column width */
  td .severity-badge {
    display: block;
    text-align: center;
    font-size: 10px;
    padding: 2px 4px;
    width: 100%;
    box-sizing: border-box;
  }

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
    background: #1a1d27;
    border: 1px solid #2d3047;
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
    color: #64748b;
    flex-shrink: 0;
  }

  .hypothesis-text {
    font-size: 15px;
    line-height: 1.7;
    color: #e2e8f0;
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
    background: #1a1d27;
    border: 1px solid #2d3047;
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
    color: #64748b;
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
    color: #64748b;
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
    background: #1a1d27;
    border: 1px solid #2d3047;
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
    color: #e2e8f0;
    margin-top: 4px;
  }

  .mitre-tactic {
    font-size: 10px;
    color: #64748b;
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .footer {
    border-top: 1px solid #2d3047;
    padding: 24px 48px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 11px;
    color: #64748b;
    font-family: 'JetBrains Mono', monospace;
  }

  @media print {
    body { background: white; color: black; }
    .cover { background: #1a1d27; -webkit-print-color-adjust: exact; }
  }

  /* v1.7 Enhanced sections */
  .risk-banner {
    background: #1a1d27;
    border: 1px solid #2d3047;
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 16px;
  }

  .risk-banner-top {
    display: table;
    width: 100%;
    margin-bottom: 12px;
  }

  .risk-banner-score {
    display: table-cell;
    vertical-align: middle;
    width: 160px;
  }

  .risk-banner-tier {
    display: table-cell;
    vertical-align: middle;
    padding-left: 20px;
  }

  .risk-score-number {
    font-family: 'JetBrains Mono', monospace;
    font-size: 42px;
    font-weight: 700;
    line-height: 1;
  }

  .risk-score-label {
    font-size: 10px;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-family: 'JetBrains Mono', monospace;
    margin-bottom: 4px;
  }

  .risk-tier-badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 16px;
    font-weight: 700;
    padding: 6px 16px;
    border-radius: 4px;
    letter-spacing: 1px;
    display: inline-block;
  }

  .score-breakdown-grid {
    display: table;
    width: 100%;
    border-top: 1px solid #2d3047;
    padding-top: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #64748b;
    line-height: 1.8;
  }

  .score-breakdown-row {
    display: table-row;
  }

  .score-breakdown-label {
    display: table-cell;
    color: #64748b;
    padding-right: 16px;
    white-space: nowrap;
    width: 200px;
  }

  .score-breakdown-value {
    display: table-cell;
    color: #e2e8f0;
  }

  .ioc-inventory {
    background: #0a1f0a;
    border: 1px solid #16a34a;
    border-radius: 8px;
    padding: 16px 20px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    line-height: 2;
    margin-bottom: 16px;
    word-break: break-word;
  }

  .ioc-domain { color: #4ade80; }
  .ioc-ip     { color: #86efac; }
  .ioc-label  { color: #64748b; min-width: 120px; display: inline-block; }

  .convergence-bar {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    letter-spacing: 0;
    color: #38bdf8;
  }

  .action-list {
    list-style: none;
    padding: 0;
  }

  .action-list li {
    border-left: 3px solid #38bdf8;
    padding: 8px 12px;
    margin-bottom: 6px;
    font-size: 13px;
    color: #e2e8f0;
    display: block;
    word-break: break-word;
  }

  .action-num {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #38bdf8;
    margin-right: 8px;
    font-weight: 700;
  }

  .action-text {
    color: #e2e8f0;
  }

  .module-badge {
    display: inline-block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    padding: 1px 5px;
    border-radius: 3px;
    background: #1e3a5f;
    color: #93c5fd;
    border: 1px solid #2563eb;
    margin-right: 4px;
    vertical-align: middle;
  }

  /* PDF-safe table fixes */
  td { word-break: break-word; }
  td.detail-col { max-width: 280px; font-size: 11px; }
  td.mono { font-family: 'JetBrains Mono', monospace; font-size: 11px; }
</style>
</head>
<body>

<!-- COVER -->
<div class="cover">
  <div>
    <div class="cover-title">🛡 Threat Hunt Report</div>
    <div class="cover-subtitle">{{ session.hunt_name }}</div>
    <div style="margin-top: 20px;">
      <span class="severity-badge sev-{{ effective_severity }}">{{ effective_severity }} RISK</span>
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

<!-- V1.7 UNIFIED RISK SCORE -->
{% if unified_risk_score %}
<div class="section">
  <div class="section-title">Unified Risk Score — v1.7 Enhanced Detection</div>

  <!-- Risk banner -->
  <div class="risk-banner">
    <div class="risk-banner-top">
      <div class="risk-banner-score">
        <div class="risk-score-label">Unified Score</div>
        <div class="risk-score-number" style="color:
          {% if unified_risk_tier == 'Critical' %}#dc2626
          {% elif unified_risk_tier == 'High' %}#ea580c
          {% elif unified_risk_tier == 'Medium' %}#d97706
          {% else %}#16a34a{% endif %};">
          {{ unified_risk_score }}/100
        </div>
      </div>
      <div class="risk-banner-tier">
        <span class="risk-tier-badge sev-{{ unified_risk_tier }}">
          [ {{ unified_risk_tier|upper }} ]
        </span>
      </div>
    </div>
    {% if score_breakdown %}
    <div class="score-breakdown-grid">
      <div class="score-breakdown-row">
        <div class="score-breakdown-label">Base finding score</div>
        <div class="score-breakdown-value">{{ score_breakdown.get('base_score_highest_finding', 0) }}</div>
      </div>
      <div class="score-breakdown-row">
        <div class="score-breakdown-label">Convergence bonus</div>
        <div class="score-breakdown-value">+{{ score_breakdown.get('convergence_bonus', {}).get('bonus', 0) }}
          — {{ score_breakdown.get('convergence_bonus', {}).get('explanation', '') }}</div>
      </div>
      <div class="score-breakdown-row">
        <div class="score-breakdown-label">Kill chain bonus</div>
        <div class="score-breakdown-value">+{{ score_breakdown.get('kill_chain_bonus', {}).get('bonus', 0) }}</div>
      </div>
      <div class="score-breakdown-row">
        <div class="score-breakdown-label">Breadth bonus</div>
        <div class="score-breakdown-value">+{{ score_breakdown.get('breadth_bonus', {}).get('bonus', 0) }}
          ({{ score_breakdown.get('breadth_bonus', {}).get('total_findings', 0) }} findings)</div>
      </div>
      <div class="score-breakdown-row">
        <div class="score-breakdown-label">Raw / Normalized</div>
        <div class="score-breakdown-value">{{ score_breakdown.get('raw_score_total', 0) }} → {{ unified_risk_score }}/100</div>
      </div>
    </div>
    {% endif %}
  </div>

  <!-- Confirmed IOC inventory -->
  {% if confirmed_c2_domains or confirmed_c2_ips %}
  <div class="ioc-inventory">
    {% if confirmed_c2_domains %}
    <div>
      <span class="ioc-label">C2 Domains &nbsp;: </span>
      {% for d in confirmed_c2_domains %}
      <span class="ioc-domain">{{ d }}</span>{% if not loop.last %}, {% endif %}
      {% endfor %}
    </div>
    {% endif %}
    {% if confirmed_c2_ips %}
    <div>
      <span class="ioc-label">C2 IPs &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: </span>
      {% for ip in confirmed_c2_ips %}
      <span class="ioc-ip">{{ ip }}</span>{% if not loop.last %}, {% endif %}
      {% endfor %}
    </div>
    {% endif %}
    {% if staging_ips %}
    <div>
      <span class="ioc-label">Staging IPs : </span>
      {% for ip in staging_ips %}
      <span class="ioc-ip">{{ ip }}</span>{% if not loop.last %}, {% endif %}
      {% endfor %}
    </div>
    {% endif %}
  </div>
  {% endif %}

  <!-- IOC convergence table -->
  {% if ioc_correlations %}
  <table style="margin-bottom:16px;">
    <tr>
      <th>IOC</th><th>Convergence</th><th>Modules</th><th>Finding Types</th>
    </tr>
    {% for c in ioc_correlations %}
    <tr>
      <td class="mono">{{ c.ioc }}</td>
      <td class="mono">
        <span class="convergence-bar">[{{ '■' * c.convergence }}{{ '□' * (3 - c.convergence) }}]</span>
        {{ c.convergence }}/3
      </td>
      <td class="mono">{{ c.modules_firing | join(', ') }}</td>
      <td class="detail-col">{{ c.finding_types | join(', ') }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  <!-- Enhanced: ATT&CK techniques -->
  {% if enhanced_techniques %}
  <div style="margin-bottom:8px;">
    <span style="font-size:11px;color:#64748b;font-family:'JetBrains Mono',monospace;
                 text-transform:uppercase;letter-spacing:1px;">MITRE Techniques (v1.7)</span>
    &nbsp;&nbsp;
    {% for t in enhanced_techniques %}
    <span class="mitre-tag">{{ t }}</span>
    {% endfor %}
  </div>
  <div style="margin-bottom:16px;">
    <span style="font-size:11px;color:#64748b;font-family:'JetBrains Mono',monospace;
                 text-transform:uppercase;letter-spacing:1px;">Kill Chain Stages</span>
    &nbsp;&nbsp;
    {% for s in kill_chain_stages %}
    <span class="mitre-tag" style="border-color:#7c3aed;color:#c4b5fd;background:#2e1065;">{{ s }}</span>
    {% endfor %}
  </div>
  {% endif %}
</div>
{% endif %}

<!-- V1.7 ENHANCED FINDINGS -->
{% if enhanced_dns or enhanced_exfil or enhanced_beaconing %}
<div class="section">
  <div class="section-title">Enhanced Detection Findings — TLD DNS / Exfil / Beaconing</div>

  <!-- DNS findings -->
  {% if enhanced_dns %}
  <div style="margin-bottom:8px;font-size:11px;color:#64748b;
              font-family:'JetBrains Mono',monospace;text-transform:uppercase;
              letter-spacing:1px;">TLD DNS Findings</div>
  <table style="margin-bottom:24px;table-layout:fixed;width:100%;">
    <colgroup>
      <col style="width:14%"><col style="width:10%"><col style="width:6%">
      <col style="width:20%"><col style="width:12%"><col style="width:38%">
    </colgroup>
    <tr><th>Type</th><th>Severity</th><th>Risk</th><th>Destination</th><th>MITRE</th><th>Detail</th></tr>
    {% for f in enhanced_dns %}
    <tr>
      <td class="mono"><span class="module-badge">DNS</span>{{ f.type }}</td>
      <td><span class="severity-badge sev-{{ f.severity }}">{{ f.severity }}</span></td>
      <td class="mono">{{ f.risk_score }}</td>
      <td class="mono">{{ f.destination }}</td>
      <td class="mono">{{ f.mitre }}</td>
      <td class="detail-col">{{ f.detail[:150] }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  <!-- Exfil findings -->
  {% if enhanced_exfil %}
  <div style="margin-bottom:8px;font-size:11px;color:#64748b;
              font-family:'JetBrains Mono',monospace;text-transform:uppercase;
              letter-spacing:1px;">Exfiltration Direction Findings</div>
  <table style="margin-bottom:24px;table-layout:fixed;width:100%;">
    <colgroup>
      <col style="width:14%"><col style="width:9%"><col style="width:5%">
      <col style="width:18%"><col style="width:10%"><col style="width:8%">
      <col style="width:36%">
    </colgroup>
    <tr><th>Direction</th><th>Severity</th><th>Risk</th><th>Source → Dest</th><th>Bytes</th><th>MITRE</th><th>Detail</th></tr>
    {% for f in enhanced_exfil %}
    <tr>
      <td>
        <span class="module-badge"
          style="{% if 'OUTBOUND' in f.direction or 'BEACONING' in f.direction %}
                   border-color:#dc2626;color:#fca5a5;background:#7f1d1d;
                 {% else %}
                   border-color:#2563eb;color:#93c5fd;background:#1e3a5f;
                 {% endif %}font-size:9px;">
          {{ f.direction | replace('_', ' ') }}
        </span>
      </td>
      <td><span class="severity-badge sev-{{ f.severity }}">{{ f.severity }}</span></td>
      <td class="mono">{{ f.risk_score }}</td>
      <td class="mono">{{ f.source }}<br>→ {{ f.destination }}</td>
      <td class="mono">{{ "{:,}".format(f.evidence.bytes_transferred) if f.evidence else '—' }}</td>
      <td class="mono">{{ f.mitre }}</td>
      <td class="detail-col">{{ f.detail[:130] }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  <!-- Beaconing findings -->
  {% if enhanced_beaconing %}
  <div style="margin-bottom:8px;font-size:11px;color:#64748b;
              font-family:'JetBrains Mono',monospace;text-transform:uppercase;
              letter-spacing:1px;">Beaconing Detection Findings</div>
  <table style="margin-bottom:24px;table-layout:fixed;width:100%;">
    <colgroup>
      <col style="width:22%"><col style="width:7%"><col style="width:11%">
      <col style="width:6%"><col style="width:30%"><col style="width:24%">
    </colgroup>
    <tr>
      <th>Pattern / Stats</th><th>Proto</th><th>Severity</th>
      <th>Risk</th><th>Source → Destination</th><th>MITRE / C2</th>
    </tr>
    {% for f in enhanced_beaconing %}
    <tr>
      <td style="font-family:'JetBrains Mono',monospace;font-size:10px;
                 color:#94a3b8;vertical-align:top;">
        <span style="color:#e2e8f0;font-weight:700;">
          {{ f.type | replace('beacon_','') | replace('_',' ') | title }}
        </span>
        {% if f.evidence %}
        <br>
        <span style="color:#64748b;font-size:9px;">
          Sessions: {{ f.evidence.session_count }}
          &nbsp;|&nbsp;
          Interval: {{ f.evidence.mean_interval_s }}s
        </span>
        <br>
        <span style="color:#64748b;font-size:9px;">
          CV: {{ f.evidence.cv }}
          &nbsp;|&nbsp;
          Jitter: ~{{ f.evidence.jitter_pct }}%
        </span>
        {% endif %}
      </td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;
                 color:#94a3b8;vertical-align:top;">{{ f.proto }}</td>
      <td style="vertical-align:top;">
        <span class="severity-badge sev-{{ f.severity }}">{{ f.severity }}</span>
      </td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;
                 color:#94a3b8;vertical-align:top;">{{ f.risk_score }}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:10px;
                 color:#94a3b8;vertical-align:top;word-break:break-all;">
        {{ f.source }}<br>
        <span style="color:#64748b;">→</span> {{ f.destination }}
      </td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:10px;
                 color:#94a3b8;vertical-align:top;">
        {{ f.mitre }}<br>
        {% if f.evidence and f.evidence.confirmed_c2 %}
        <span style="color:#4ade80;font-size:9px;font-weight:700;">✓ C2 CONFIRMED</span>
        {% else %}
        <span style="color:#64748b;font-size:9px;">— not confirmed</span>
        {% endif %}
      </td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}
</div>
{% endif %}

<!-- V1.7 RECOMMENDED ACTIONS -->
{% if recommended_actions %}
<div class="section">
  <div class="section-title">Recommended Actions</div>
  <ul class="action-list">
    {% for action in recommended_actions %}
    <li style="border-left:3px solid #38bdf8;padding:8px 12px;margin-bottom:6px;
               font-size:13px;color:#e2e8f0;display:block;word-break:break-word;
               list-style:none;">
      <span style="font-family:'JetBrains Mono',monospace;font-size:11px;
                   color:#38bdf8;font-weight:700;margin-right:8px;">
        {{ "%02d"|format(loop.index) }}.
      </span>
      <span style="color:#e2e8f0;">{{ action }}</span>
    </li>
    {% endfor %}
  </ul>
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

    def __init__(
        self,
        session,
        hypothesis_summary: dict = None,
        ioc_summary: dict = None,
        unified_report: dict = None,
        unified_risk_score: int = 0,
        unified_risk_tier: str = None,
        total_findings: int = None,
    ):
        self.session            = session
        self.hyp_summary        = hypothesis_summary or {}
        self.ioc_summary        = ioc_summary or {}
        # v1.7 enhanced module data — optional, report degrades gracefully if absent
        self.unified_report     = unified_report or {}
        self.unified_risk_score = unified_risk_score
        self.unified_risk_tier  = unified_risk_tier
        self._total_findings    = total_findings  # passed from GUI all_findings count

    def build_html(self, output_path: str = None) -> str:
        env = Environment(loader=BaseLoader())
        env.globals["enumerate"] = enumerate
        template = env.from_string(REPORT_TEMPLATE)

        # Use unified risk tier if available, else fall back to session severity
        effective_severity = self.unified_risk_tier or self.session.severity

        stats = {
            "total_hypotheses": len(self.hyp_summary.get("hypotheses", [])),
            "mitre_techniques": len(self.hyp_summary.get("mitre_coverage", {})),
            "ioc_matches": self.ioc_summary.get("match_count", 0),
            "evidence_files": len(self.session.evidence_files),
        }

        # Pull enhanced findings from unified report if available
        ur_findings   = self.unified_report.get("findings", {})
        ur_narrative  = self.unified_report.get("narrative", {})
        ur_ioc_inv    = self.unified_report.get("ioc_inventory", {})
        ur_mitre      = self.unified_report.get("mitre_coverage", {})
        ur_corr       = self.unified_report.get("ioc_correlations", [])
        ur_actions    = self.unified_report.get("recommended_actions", [])
        ur_risk       = self.unified_report.get("risk_assessment", {})

        # Build enhanced narrative — prefer the richer v1.7 adversary narrative
        effective_narrative = (
            ur_narrative.get("adversary_narrative")
            or self.hyp_summary.get("adversary_narrative", "")
        )

        html = template.render(
            session              = self.session,
            effective_severity   = effective_severity,
            report_date          = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            stats                = stats,
            narrative            = effective_narrative,
            hypotheses           = self.hyp_summary.get("hypotheses", []),
            mitre_coverage       = self.hyp_summary.get("mitre_coverage", {}),
            ioc_matches          = self.ioc_summary.get("matches", []),
            pcap_findings        = self.session.pcap_findings,
            log_findings         = self.session.log_findings,
            analyst_notes        = self.session.analyst_notes,
            evidence_files       = self.session.evidence_files,
            # v1.7 enhanced data
            unified_risk_score   = self.unified_risk_score,
            unified_risk_tier    = effective_severity,
            enhanced_dns         = ur_findings.get("dns", []),
            enhanced_exfil       = ur_findings.get("exfil", []),
            enhanced_beaconing   = ur_findings.get("beaconing", []),
            confirmed_c2_ips     = ur_ioc_inv.get("confirmed_c2_ips", []),
            confirmed_c2_domains = ur_ioc_inv.get("confirmed_c2_domains", []),
            staging_ips          = ur_ioc_inv.get("staging_ips", []),
            ioc_correlations     = ur_corr,
            enhanced_techniques  = ur_mitre.get("techniques", []),
            kill_chain_stages    = ur_mitre.get("kill_chain_stages", []),
            recommended_actions  = ur_actions,
            score_breakdown      = ur_risk.get("score_breakdown", {}),
        )

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)
            logger.info(f"HTML report → {output_path}")

        return html

    def build_pdf(self, output_path: str) -> bool:
        """
        Generate PDF using ReportLab (tha_report_pdf.py).
        Replaces WeasyPrint — produces correctly-wrapped, high-contrast tables.
        Falls back to HTML if tha_report_pdf.py is not found.
        """
        try:
            from tha_report_pdf import build_pdf_report
            report_dict = self._build_report_dict()
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            ok = build_pdf_report(report_dict, output_path)
            if ok:
                logger.info(f"PDF report -> {output_path}")
            else:
                logger.error("tha_report_pdf.build_pdf_report() returned False")
            return ok
        except ImportError:
            import sys as _sys, os as _os
            _tha_dir = _os.path.dirname(_os.path.abspath(__file__))
            # Auto-add this file's directory to sys.path and retry once
            if _tha_dir not in _sys.path:
                _sys.path.insert(0, _tha_dir)
                try:
                    from tha_report_pdf import build_pdf_report as _bpr
                    _rd = self._build_report_dict()
                    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                    _ok = _bpr(_rd, output_path)
                    if _ok:
                        logger.info(f"PDF report -> {output_path}")
                        return _ok
                except ImportError:
                    pass
            logger.warning(
                f"tha_report_pdf.py not found. "
                f"Copy it to: {_tha_dir}"
            )
            html_path = output_path.replace(".pdf", ".html")
            self.build_html(html_path)
            return False
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            html_path = output_path.replace(".pdf", ".html")
            self.build_html(html_path)
            return False

    def _build_report_dict(self) -> dict:
        """
        Translate ReportBuilder state into the normalised dict format
        expected by tha_report_pdf.build_pdf_report().
        """
        ur           = self.unified_report
        ur_findings  = ur.get("findings", {})
        ur_narrative = ur.get("narrative", {})
        ur_ioc_inv   = ur.get("ioc_inventory", {})
        ur_mitre     = ur.get("mitre_coverage", {})
        ur_risk      = ur.get("risk_assessment", {})

        effective_severity = self.unified_risk_tier or self.session.severity

        evidence_files = [
            {
                "path":   e.get("path", ""),
                "type":   e.get("type", "pcap"),
                "loaded": e.get("loaded_at", e.get("loaded", "")),
            }
            for e in self.session.evidence_files
        ]

        hypotheses  = self.hyp_summary.get("hypotheses", [])
        mitre_dict  = self.hyp_summary.get("mitre_coverage", {})
        mitre_detail = [
            {
                "id":     tid,
                "name":   data.get("technique", ""),
                "tactic": data.get("tactic", ""),
                "source": "hypothesis_generator",
            }
            for tid, data in mitre_dict.items()
        ]

        # Deduplicate pcap_findings — enhanced module findings injected into
        # session.pcap_findings can create duplicates. Use (type, source, dest) as key.
        seen = set()
        network_findings = []
        for f in self.session.pcap_findings:
            # Skip findings injected by enhanced modules (already in ur_findings)
            if f.get("source_module") == "tha_v17_enhanced":
                continue
            key = (f.get("type",""), f.get("src", f.get("source","")),
                   f.get("dst", f.get("destination","")))
            if key in seen:
                continue
            seen.add(key)
            network_findings.append({
                "type":        f.get("type", ""),
                "severity":    f.get("severity", "Informational"),
                "source":      f.get("src", f.get("source", "--")),
                "destination": f.get("dst", f.get("destination", "--")),
                "detail":      f.get("detail", ""),
            })

        ioc_correlations = []
        for c in ur.get("ioc_correlations", []):
            ft = c.get("finding_types", "")
            ioc_correlations.append({
                "ioc":         c.get("ioc", ""),
                "convergence": c.get("convergence", 0),
                "finding_types": ", ".join(ft) if isinstance(ft, list) else ft,
                "detail":      c.get("detail", ""),
            })

        return {
            "hunt_metadata": {
                "hunt_id":   self.session.hunt_name,
                "analyst":   self.session.analyst_name,
                "generated": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            },
            "risk_assessment": {
                "normalized_score": self.unified_risk_score,
                "risk_tier":        effective_severity,
                "score_breakdown":  ur_risk.get("score_breakdown", {}),
            },
            "summary": {
                # Use the exact count from GUI all_findings if passed,
                # otherwise count only session findings (no double-counting)
                "total_findings":      self._total_findings if self._total_findings is not None
                                       else len(self.session.pcap_findings)
                                            + len(self.session.log_findings),
                "total_hypotheses":    len(hypotheses),
                "mitre_count":         len(mitre_dict),
                "ioc_match_count":     self.ioc_summary.get("match_count", 0),
                "evidence_file_count": len(evidence_files),
            },
            "narrative": {
                # Match GUI behaviour: baseline hyp_summary narrative shown first,
                # v1.7 enhanced narrative used only if baseline is absent
                "adversary_narrative": (
                    self.hyp_summary.get("adversary_narrative")
                    or ur_narrative.get("adversary_narrative", "")
                ),
            },
            "mitre_coverage": {
                "techniques":        ur_mitre.get("techniques", list(mitre_dict.keys())),
                "kill_chain_stages": ur_mitre.get("kill_chain_stages", []),
                "technique_detail":  mitre_detail,
            },
            "ioc_correlations":  ioc_correlations,
            "findings": {
                "dns":       ur_findings.get("dns",       []),
                "exfil":     ur_findings.get("exfil",     []),
                "beaconing": ur_findings.get("beaconing", []),
            },
            "network_findings":   network_findings,
            "hypotheses":         hypotheses,
            "recommended_actions": ur.get("recommended_actions", []),
            "evidence_files":     evidence_files,
        }
