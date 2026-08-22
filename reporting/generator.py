"""AHRAS — Report Generator
Produces professional HTML/PDF security reports:
- Executive Summary Report
- Technical Incident Report
- Weekly/Monthly Trend Reports
- IOC Report
"""
import time
import json
from datetime import datetime
from typing import List, Dict, Optional


class ReportGenerator:
    """Generates professional SOC reports in HTML (PDF-ready via print)."""

    _CSS = """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Inter',sans-serif;background:#f8fafc;color:#1e293b;font-size:13px;line-height:1.6}
    .page{max-width:1100px;margin:0 auto;padding:40px}
    .cover{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);color:#fff;border-radius:16px;
           padding:56px 48px;margin-bottom:32px;position:relative;overflow:hidden}
    .cover::before{content:'';position:absolute;top:-50px;right:-50px;width:300px;height:300px;
                   border-radius:50%;background:rgba(74,144,217,0.15)}
    .cover-badge{display:inline-block;background:rgba(74,144,217,0.3);color:#93c5fd;
                 border:1px solid rgba(74,144,217,0.5);border-radius:20px;
                 padding:4px 14px;font-size:11px;font-weight:600;letter-spacing:.08em;
                 text-transform:uppercase;margin-bottom:16px}
    .cover h1{font-size:32px;font-weight:800;letter-spacing:-0.5px;margin-bottom:8px}
    .cover h2{font-size:15px;font-weight:400;color:#94a3b8;margin-bottom:28px}
    .cover-meta{display:grid;grid-template-columns:repeat(4,1fr);gap:20px;margin-top:28px;
                padding-top:28px;border-top:1px solid rgba(255,255,255,0.1)}
    .cover-stat .v{font-size:28px;font-weight:800;color:#60a5fa}
    .cover-stat .l{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-top:2px}
    .section{background:#fff;border:1px solid #e2e8f0;border-radius:12px;
             padding:28px 32px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.05)}
    .section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;
                   color:#4A90D9;border-left:3px solid #4A90D9;padding-left:10px;margin-bottom:20px}
    .grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}
    .grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
    .grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    .metric{border-radius:10px;padding:20px;text-align:center;border:1px solid}
    .metric .v{font-size:32px;font-weight:800;line-height:1}
    .metric .l{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:#64748b;margin-top:6px}
    .m-green{background:#f0fdf4;border-color:#bbf7d0}.m-green .v{color:#16a34a}
    .m-yellow{background:#fffbeb;border-color:#fde68a}.m-yellow .v{color:#d97706}
    .m-orange{background:#fff7ed;border-color:#fed7aa}.m-orange .v{color:#ea580c}
    .m-red{background:#fef2f2;border-color:#fecaca}.m-red .v{color:#dc2626}
    .m-blue{background:#eff6ff;border-color:#bfdbfe}.m-blue .v{color:#2563eb}
    table{width:100%;border-collapse:collapse;font-size:12px}
    th{text-align:left;padding:9px 14px;background:#f8fafc;color:#64748b;
       font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
       border-bottom:2px solid #e2e8f0}
    td{padding:8px 14px;border-bottom:1px solid #f1f5f9}
    tr:hover td{background:#f8fafc}
    .badge{border-radius:4px;padding:2px 8px;font-size:10px;font-weight:700;display:inline-block}
    .b-LOW{background:#f0fdf4;color:#16a34a}
    .b-MEDIUM{background:#fffbeb;color:#d97706}
    .b-HIGH{background:#fff7ed;color:#ea580c}
    .b-CRITICAL{background:#fef2f2;color:#dc2626}
    .b-OPEN{background:#eff6ff;color:#2563eb}
    .b-CLOSED{background:#f0fdf4;color:#16a34a}
    .finding{background:#fef2f2;border-left:4px solid #ef4444;padding:16px 20px;
             border-radius:0 8px 8px 0;margin-bottom:12px}
    .finding.medium{background:#fffbeb;border-left-color:#f59e0b}
    .finding.low{background:#f0fdf4;border-left-color:#22c55e}
    .finding h4{font-size:13px;font-weight:600;margin-bottom:4px}
    .finding p{font-size:12px;color:#64748b}
    .rec{background:#eff6ff;border-left:4px solid #3b82f6;padding:14px 18px;
         border-radius:0 8px 8px 0;margin-bottom:10px;font-size:12px}
    .rec strong{display:block;margin-bottom:3px;color:#1e40af}
    .timeline-item{display:flex;gap:16px;margin-bottom:16px;align-items:flex-start}
    .tl-dot{width:10px;height:10px;border-radius:50%;background:#3b82f6;
            flex-shrink:0;margin-top:4px;box-shadow:0 0 0 3px #bfdbfe}
    .tl-line{flex:1}
    .tl-time{font-size:10px;color:#94a3b8;font-family:monospace}
    .tl-desc{font-size:12px;font-weight:500}
    .footer{text-align:center;color:#94a3b8;font-size:11px;margin-top:32px;
            padding-top:20px;border-top:1px solid #e2e8f0}
    .footer strong{color:#475569}
    @media print{body{background:#fff}.page{padding:20px}
      .cover{border-radius:0}.section{box-shadow:none;page-break-inside:avoid}}
    </style>
    """

    def executive_report(self, events: List[dict], severity_counts: dict,
                          attack_counts: dict, incidents: List[dict],
                          cases_stats: dict, ioc_stats: dict) -> str:
        now = datetime.now().strftime("%B %d, %Y — %H:%M UTC")
        total = len(events)
        critical = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)

        # Top attackers
        attacker_counts: Dict[str, int] = {}
        country_counts: Dict[str, int] = {}
        for e in events:
            ip = e.get("src_ip", "")
            country = e.get("country", "Unknown")
            if ip:
                attacker_counts[ip] = attacker_counts.get(ip, 0) + 1
            if country and country != "Unknown":
                country_counts[country] = country_counts.get(country, 0) + 1

        top_attackers = sorted(attacker_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # Timeline (last 10 high+ events)
        timeline_events = [e for e in events if e.get("severity") in ("HIGH", "CRITICAL")][:10]

        # Findings
        findings_html = ""
        if critical > 0:
            findings_html += f"""<div class="finding"><h4>🔴 {critical} Critical Severity Events Detected</h4>
            <p>Critical threats require immediate investigation and response. These events have the highest risk scores and indicate active exploitation attempts.</p></div>"""
        if high > 0:
            findings_html += f"""<div class="finding medium"><h4>🟡 {high} High Severity Events Detected</h4>
            <p>High severity events indicate significant threats. Review and escalate as appropriate.</p></div>"""
        if incidents:
            findings_html += f"""<div class="finding"><h4>⚡ {len(incidents)} Correlated Incidents Identified</h4>
            <p>Correlation engine detected multi-stage attack patterns. These represent confirmed attack chains rather than isolated events.</p></div>"""
        if ioc_stats.get("total_hits", 0) > 0:
            findings_html += f"""<div class="finding medium"><h4>🎯 {ioc_stats.get("total_hits",0)} IOC Matches Found</h4>
            <p>Known malicious indicators were matched against live traffic. These are confirmed threats based on threat intelligence.</p></div>"""

        if not findings_html:
            findings_html = """<div class="finding low"><h4>✅ No Critical Findings</h4>
            <p>No critical threats were detected in this reporting period. Continue monitoring.</p></div>"""

        # Recommendations
        recs = []
        if critical > 0:
            recs.append(("Immediate Incident Response", "Initiate incident response procedures for all CRITICAL events. Assign to senior analyst within 1 hour."))
        if top_attackers:
            recs.append(("Block Top Attacker IPs", f"Consider blocking {top_attackers[0][0]} ({top_attackers[0][1]} events) at the firewall level."))
        if cases_stats.get("sla_breached", 0) > 0:
            recs.append(("Resolve SLA Breaches", f"{cases_stats['sla_breached']} cases have exceeded their SLA. Prioritize these immediately."))
        recs.append(("Review IOC Database", "Ensure IOC database is updated with latest threat intelligence feeds weekly."))
        recs.append(("Enable Automated Blocking", "Consider enabling auto-block for IPs exceeding risk score 9.0 to reduce response time."))

        recs_html = "".join(f"""<div class="rec"><strong>{r[0]}</strong>{r[1]}</div>""" for r in recs)

        # Top attacker rows
        attacker_rows = "".join(
            f"<tr><td style='font-family:monospace'>{ip}</td><td>{cnt}</td>"
            f"<td>{'⚠️ High' if cnt > 10 else '📍 Medium'}</td></tr>"
            for ip, cnt in top_attackers
        )

        # Timeline HTML
        timeline_html = ""
        for e in timeline_events[:8]:
            sev = e.get("severity", "LOW")
            color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c"}.get(sev, "#3b82f6")
            timeline_html += f"""<div class="timeline-item">
                <div class="tl-dot" style="background:{color};box-shadow:0 0 0 3px {color}30"></div>
                <div class="tl-line">
                    <div class="tl-time">{e.get("timestamp_str","")}</div>
                    <div class="tl-desc">{e.get("attack_type","Unknown")} from {e.get("src_ip","?")}
                    <span class="badge b-{sev}" style="margin-left:6px">{sev}</span></div>
                </div>
            </div>"""

        return f"""<!DOCTYPE html><html lang="en"><head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>AHRAS Executive Security Report</title>{self._CSS}</head><body>
        <div class="page">
        <div class="cover">
            <div class="cover-badge">🛡 Confidential — Executive Security Report</div>
            <h1>AHRAS Security Operations Report</h1>
            <h2>Adaptive Hybrid Risk-Aware Security System v3.0 · {now}</h2>
            <div class="cover-meta">
                <div class="cover-stat"><div class="v">{total}</div><div class="l">Total Events</div></div>
                <div class="cover-stat"><div class="v" style="color:#f87171">{critical}</div><div class="l">Critical</div></div>
                <div class="cover-stat"><div class="v" style="color:#fb923c">{high}</div><div class="l">High</div></div>
                <div class="cover-stat"><div class="v" style="color:#34d399">{cases_stats.get("total",0)}</div><div class="l">Cases</div></div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Threat Summary</div>
            <div class="grid4">
                <div class="metric m-green"><div class="v">{severity_counts.get("LOW",0)}</div><div class="l">Low</div></div>
                <div class="metric m-yellow"><div class="v">{severity_counts.get("MEDIUM",0)}</div><div class="l">Medium</div></div>
                <div class="metric m-orange"><div class="v">{high}</div><div class="l">High</div></div>
                <div class="metric m-red"><div class="v">{critical}</div><div class="l">Critical</div></div>
            </div>
        </div>

        <div class="grid2" style="margin-bottom:20px">
            <div class="section">
                <div class="section-title">Key Findings</div>
                {findings_html}
            </div>
            <div class="section">
                <div class="section-title">Attack Timeline</div>
                {timeline_html or "<p style='color:#94a3b8;font-size:12px'>No high/critical events in this period.</p>"}
            </div>
        </div>

        <div class="grid2" style="margin-bottom:20px">
            <div class="section">
                <div class="section-title">Top Attackers</div>
                <table><thead><tr><th>IP Address</th><th>Events</th><th>Risk</th></tr></thead>
                <tbody>{attacker_rows or "<tr><td colspan='3' style='color:#94a3b8'>No data</td></tr>"}</tbody></table>
            </div>
            <div class="section">
                <div class="section-title">Top Attack Types</div>
                <table><thead><tr><th>Attack</th><th>Count</th></tr></thead>
                <tbody>{"".join(f"<tr><td>{a}</td><td><strong>{c}</strong></td></tr>" for a,c in top_attacks) or "<tr><td colspan='2' style='color:#94a3b8'>No data</td></tr>"}</tbody></table>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Recommendations</div>
            {recs_html}
        </div>

        <div class="footer">
            <strong>AHRAS SOC Platform v3.0</strong> · Confidential Security Report · {now}<br>
            Generated by AHRAS Adaptive Hybrid Risk-Aware Security System
        </div>
        </div></body></html>"""

    def incident_report(self, incident: dict, related_events: List[dict]) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        rows = ""
        for e in related_events[:20]:
            sev = e.get('severity', 'LOW')
            rows += (
                f"<tr><td style='font-family:monospace'>{e.get('src_ip','')}</td>"
                f"<td>{e.get('attack_type','')}</td>"
                f"<td><span class='badge b-{sev}'>{sev}</span></td>"
                f"<td>{e.get('timestamp_str','')}</td>"
                f"<td>{e.get('country','')}</td></tr>"
            )
        return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
        <title>Incident Report {incident.get("incident_id","")}</title>{self._CSS}</head><body>
        <div class="page">
        <div class="cover">
            <div class="cover-badge">⚡ Incident Report</div>
            <h1>{incident.get("rule_name","Incident")}</h1>
            <h2>{incident.get("description","")} · {now}</h2>
        </div>
        <div class="grid3" style="margin-bottom:20px">
            <div class="section"><div class="section-title">Incident ID</div>
                <div style="font-size:24px;font-weight:800;font-family:monospace">{incident.get("incident_id","")}</div>
            </div>
            <div class="section"><div class="section-title">MITRE ATT&CK</div>
                <div style="font-size:18px;font-weight:700;color:#4A90D9">{incident.get("mitre_technique","")}</div>
            </div>
            <div class="section"><div class="section-title">Severity</div>
                <span class="badge b-{incident.get('severity','LOW')}" style="font-size:16px;padding:6px 14px">
                {incident.get("severity","")}</span>
            </div>
        </div>
        <div class="section">
            <div class="section-title">Related Events ({len(related_events)})</div>
            <table><thead><tr><th>Source IP</th><th>Attack Type</th><th>Severity</th><th>Time</th><th>Country</th></tr></thead>
            <tbody>{rows}</tbody></table>
        </div>
        <div class="footer">AHRAS SOC Platform · Incident Report · {now}</div>
        </div></body></html>"""
