"""Render a RunReport as JSON or HTML."""
from __future__ import annotations

import html
import json

from .runner import RunReport


def to_json(report: RunReport) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)


def to_html(report: RunReport) -> str:
    s = report.summary()
    rows = []
    for r in report.runs:
        verdict_color = {"VULN_LEAK": "#f85149",
                         "SAFE_REFUSED": "#3fb950",
                         "AMBIGUOUS": "#d29922"}[r.verdict]
        asset_link = (f'<a href="{html.escape(r.asset_url)}" target=_blank>'
                      f'view</a>' if r.asset_url else "-")
        resp = (r.response[:300].replace("<", "&lt;") +
                ("…" if len(r.response) > 300 else ""))
        rows.append(f"""
<tr>
 <td><code>{html.escape(r.probe_id)}</code></td>
 <td>{html.escape(r.family)}</td>
 <td>{html.escape(r.asset_kind)}</td>
 <td>{asset_link}</td>
 <td><span style="background:{verdict_color};color:#000;
       padding:2px 8px;border-radius:3px">{r.verdict}</span></td>
 <td><small>{html.escape(r.prompt_text[:120])}</small></td>
 <td><small>{resp}</small></td>
 <td>{r.latency_ms}ms</td>
</tr>""")
    fams = "".join(
        f"<tr><td>{html.escape(f)}</td>" +
        "".join(f"<td>{stats.get(v,0)}</td>"
                for v in ("VULN_LEAK", "SAFE_REFUSED", "AMBIGUOUS")) +
        "</tr>"
        for f, stats in s["by_family"].items()
    )
    return f"""<!doctype html><html><head><title>Multi-Modal Garak</title>
<style>
body{{font-family:system-ui;background:#0d1117;color:#c9d1d9;
max-width:1400px;margin:2em auto;padding:0 1em}}
h1,h2{{color:#58a6ff}}
table{{border-collapse:collapse;width:100%;margin:1em 0;font-size:12px}}
th,td{{border:1px solid #30363d;padding:6px 8px;text-align:left;
vertical-align:top}}
th{{background:#161b22;color:#58a6ff}}
.kpi{{display:inline-block;background:#161b22;padding:1em;margin:.5em;
border-radius:6px;min-width:140px;text-align:center}}
.kpi b{{font-size:1.6em;display:block}}
code{{background:#161b22;padding:2px 5px;border-radius:3px}}
</style></head><body>
<h1>Multi-Modal Garak Run Report</h1>
<p><b>Model:</b> {html.escape(s['model'])}
&nbsp;|&nbsp; <b>Probes:</b> {s['total_probes']}
&nbsp;|&nbsp; <b>Duration:</b> {s['duration_s']}s
</p>
<div>
 <div class=kpi>VULN<b style="color:#f85149">{s['verdicts'].get('VULN_LEAK',0)}</b></div>
 <div class=kpi>SAFE<b style="color:#3fb950">{s['verdicts'].get('SAFE_REFUSED',0)}</b></div>
 <div class=kpi>AMBIG<b style="color:#d29922">{s['verdicts'].get('AMBIGUOUS',0)}</b></div>
 <div class=kpi>Vuln rate<b>{s['vulnerability_rate']*100:.1f}%</b></div>
</div>
<h2>By Family</h2>
<table><thead><tr><th>Family</th><th>VULN_LEAK</th>
<th>SAFE_REFUSED</th><th>AMBIGUOUS</th></tr></thead>
<tbody>{fams}</tbody></table>
<h2>Probe Runs</h2>
<table><thead><tr><th>Probe</th><th>Family</th><th>Kind</th>
<th>Asset</th><th>Verdict</th><th>Prompt</th><th>Response</th>
<th>Latency</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
</body></html>"""
