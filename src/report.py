"""Report builder: emits HTML (human-readable) + JSON (machine-readable).

Error-rate & latency charts are drawn as inline SVG (no matplotlib), so the
report is fully self-contained — open it in a browser and it just works.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

SEV_COLOR = {"P1": "#d32f2f", "P2": "#f57c00", "P3": "#fbc02d"}


def _svg_line(series: list[float], width=720, height=140, color="#d32f2f", pad=24) -> str:
    if not series:
        return "<p>(no data)</p>"
    mx = max(series) or 1
    n = len(series)
    inner_w = width - 2 * pad
    inner_h = height - 2 * pad
    step = inner_w / max(1, n - 1)
    pts = []
    for i, v in enumerate(series):
        x = pad + i * step
        y = pad + inner_h - (v / mx) * inner_h
        pts.append(f"{x:.1f},{y:.1f}")
    polyline = " ".join(pts)
    grid = (
        f'<line x1="{pad}" y1="{pad}" x2="{pad}" y2="{height-pad}" stroke="#ccc"/>'
        f'<line x1="{pad}" y1="{height-pad}" x2="{width-pad}" y2="{height-pad}" stroke="#ccc"/>'
    )
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" preserveAspectRatio="xMidYMid meet" '
        f'style="background:#fafafa;border:1px solid #eee;border-radius:8px">{grid}'
        f'<text x="{pad}" y="14" font-size="11" fill="#666">max={mx:g}</text>'
        f'<polyline fill="none" stroke="{color}" stroke-width="2" points="{polyline}"/></svg>'
    )


def _badge(sev: str) -> str:
    c = SEV_COLOR.get(sev, "#777")
    return (f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:10px;'
            f'font-size:12px;font-weight:600">{sev}</span>')


def build_html(analysis: dict, timeseries: dict, meta: dict) -> str:
    anomalies = analysis["anomalies"]
    counts = {"P1": 0, "P2": 0, "P3": 0}
    for a in anomalies:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1

    rows = []
    for a in anomalies:
        samples = "".join(
            f"<div style='font-family:monospace;font-size:12px;color:#444;"
            f"background:#f5f5f5;padding:4px 6px;margin:2px 0;border-radius:4px;overflow-x:auto'>"
            f"{html.escape(s)}</div>"
            for s in a.get("samples", [])
        )
        root = html.escape(a.get("root_cause", "") or "")
        rec = html.escape(a.get("recommendation", "") or "")
        rows.append(f"""
        <tr>
          <td style="vertical-align:top">{_badge(a['severity'])}</td>
          <td style="vertical-align:top">
            <div style="font-weight:600">{html.escape(a['title'])}</div>
            <div style="color:#555;font-size:13px;margin:4px 0">{html.escape(a['detail'])}</div>
            <div style="color:#888;font-size:12px">⏱ {html.escape(a['window_start'])} · type=<code>{a['type']}</code></div>
            {samples}
          </td>
          <td style="vertical-align:top;font-size:13px;max-width:240px">{root or '—'}</td>
          <td style="vertical-align:top;font-size:13px;max-width:280px">💡 {rec or '—'}</td>
        </tr>""")

    table = "".join(rows) or '<tr><td colspan="4">No anomalies.</td></tr>'
    err_chart = _svg_line([float(x) for x in timeseries.get("error_count", [])], color="#d32f2f")
    lat_chart = _svg_line([float(x) for x in timeseries.get("p95_ms", [])], color="#1976d2")
    llm_tag = (f"✅ Claude ({analysis.get('model', 'on')})" if analysis.get("llm_used")
               else "⚙️ Rule/stat fallback (LLM off)")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log Anomaly Report</title></head>
<body style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:960px;
margin:24px auto;padding:0 16px;color:#222">
  <h1 style="margin-bottom:4px">🔍 Log Anomaly Detection Report</h1>
  <div style="color:#777;font-size:13px">Generated {generated} · Analysis: {llm_tag}</div>

  <div style="display:flex;gap:12px;margin:16px 0;flex-wrap:wrap">
    <div style="flex:1;min-width:120px;background:#fff;border:1px solid #eee;border-radius:8px;padding:12px">
      <div style="font-size:28px;font-weight:700">{len(anomalies)}</div><div style="color:#777">Total anomalies</div></div>
    <div style="flex:1;min-width:120px;background:#fff;border:1px solid {SEV_COLOR['P1']};border-radius:8px;padding:12px">
      <div style="font-size:28px;font-weight:700;color:{SEV_COLOR['P1']}">{counts['P1']}</div><div style="color:#777">P1 (critical)</div></div>
    <div style="flex:1;min-width:120px;background:#fff;border:1px solid {SEV_COLOR['P2']};border-radius:8px;padding:12px">
      <div style="font-size:28px;font-weight:700;color:{SEV_COLOR['P2']}">{counts['P2']}</div><div style="color:#777">P2 (high)</div></div>
    <div style="flex:1;min-width:120px;background:#fff;border:1px solid #eee;border-radius:8px;padding:12px">
      <div style="font-size:28px;font-weight:700">{meta.get('log_lines', '?')}</div><div style="color:#777">Log lines scanned</div></div>
  </div>

  <div style="background:#eef6ff;border-left:4px solid #1976d2;padding:12px 16px;border-radius:6px;margin:12px 0">
    <strong>Executive summary:</strong> {html.escape(analysis.get('summary', ''))}
  </div>

  <h3>📈 Error count per {meta.get('window_seconds', 30)}s window</h3>
  {err_chart}
  <h3>⏱ Latency p95 (ms) per window</h3>
  {lat_chart}

  <h3>📋 Details &amp; recommended actions</h3>
  <table style="border-collapse:collapse;width:100%;font-size:14px" border="0">
    <thead><tr style="text-align:left;border-bottom:2px solid #eee">
      <th>Sev</th><th>Issue</th><th>Root cause</th><th>Recommended action</th></tr></thead>
    <tbody>{table}</tbody>
  </table>

  <p style="color:#999;font-size:12px;margin-top:24px">
    Generated by Log Anomaly Agent · scenario=<code>{meta.get('scenario','?')}</code>
  </p>
</body></html>"""


def build_text_summary(analysis: dict, meta: dict) -> str:
    """Plain-text summary for the console or email body."""
    lines = [
        "=" * 60,
        "LOG ANOMALY DETECTION REPORT",
        "=" * 60,
        f"Scenario : {meta.get('scenario','?')} | Log lines: {meta.get('log_lines','?')}",
        f"Analysis : {'Claude LLM' if analysis.get('llm_used') else 'Rule/stat fallback'}",
        "",
        "Summary  : " + analysis.get("summary", ""),
        "",
        "Details:",
    ]
    if not analysis["anomalies"]:
        lines.append("  (no anomalies)")
    for a in analysis["anomalies"]:
        lines.append(f"  [{a['severity']}] {a['title']}  @ {a['window_start']}")
        if a.get("recommendation"):
            lines.append(f"        -> {a['recommendation']}")
    lines.append("=" * 60)
    return "\n".join(lines)


def write_reports(analysis: dict, timeseries: dict, meta: dict,
                  html_path: str, json_path: str) -> None:
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(build_html(analysis, timeseries, meta))
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "analysis": analysis, "timeseries": timeseries},
                  fh, ensure_ascii=False, indent=2)
