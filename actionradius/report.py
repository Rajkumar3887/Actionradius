"""
report.py

Generates structured output from ActionRadius scan results.

Two formats, for two audiences:

1. JSON — machine-readable, scriptable. Pipe it into Slack, Jira, PagerDuty,
   or any automation that needs to act on findings during an incident.
   Printed to stdout so you can redirect it: `python scan.py ... --json > results.json`

2. HTML — human-readable, self-contained single-file report. Structured the
   way an IR lead actually reads one: summary at top, critical/exposed first,
   each finding with full context and rationale, not a generic dump.
   Written to a file: `python scan.py ... --html report.html`

Both formats support general scan mode (all findings) and targeted/matcher
mode (incident triage for a specific action).
"""

import json
from datetime import datetime, timezone
from typing import Optional


# ============================================================
# JSON REPORT
# ============================================================

def generate_json_general(total_sites: int, findings: list[dict]) -> str:
    """
    JSON output for a general scan (all mutable/risky pins).
    """
    severity_counts = {}
    for f in findings:
        sev = f["risk"]["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        "scan_type": "general",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_sites": total_sites,
            "mutable_sites": len(findings),
            "by_severity": severity_counts,
        },
        "findings": [
            _serialize_finding(f) for f in
            sorted(findings, key=lambda f: f["risk"]["score"], reverse=True)
        ],
    }
    return json.dumps(report, indent=2)


def generate_json_targeted(target: str, safe_refs: set[str] | None, results: list) -> str:
    """
    JSON output for a targeted/matcher scan (incident triage).
    """
    from actionradius.matcher import EXPOSED, SAFE, PINNED_UNKNOWN

    report = {
        "scan_type": "targeted",
        "target_action": target,
        "safe_refs": sorted(safe_refs) if safe_refs else [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_matches": len(results),
            "exposed": sum(1 for r in results if r.status == EXPOSED),
            "pinned_unknown": sum(1 for r in results if r.status == PINNED_UNKNOWN),
            "safe": sum(1 for r in results if r.status == SAFE),
        },
        "matches": [_serialize_match(r) for r in results],
    }
    return json.dumps(report, indent=2)


def _serialize_finding(f: dict) -> dict:
    """Convert a general finding dict to a JSON-safe structure."""
    return {
        "owner": f["owner"],
        "repo": f["repo"],
        "workflow_path": f["file"],
        "job_id": f["site"].job_id,
        "step_index": f["site"].step_index,
        "uses": f["site"].uses.raw,
        "ref": f["site"].uses.ref,
        "ref_type": f["site"].uses.ref_type,
        "resolved_sha": f["sha"],
        "source_chain": f["site"].source_chain,
        "risk": f["risk"],
    }


def _serialize_match(r) -> dict:
    """Convert a MatchResult to a JSON-safe structure."""
    return {
        "status": r.status,
        "owner": r.owner,
        "repo": r.repo,
        "workflow_path": r.workflow_path,
        "job_id": r.job_id,
        "step_index": r.step_index,
        "uses": r.raw_uses,
        "ref": r.ref,
        "ref_type": r.ref_type,
        "is_full_sha": r.is_full_sha,
        "resolved_sha": r.resolved_sha,
        "source_chain": r.source_chain,
    }


# ============================================================
# HTML REPORT
# ============================================================

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ActionRadius — {title}</title>
<style>
  :root {{
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --critical: #f85149;
    --high: #f0883e;
    --medium: #d29922;
    --low: #3fb950;
    --info: #58a6ff;
    --exposed: #f85149;
    --unknown: #d29922;
    --safe: #3fb950;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
  }}
  h1 {{
    font-size: 1.8rem;
    margin-bottom: 0.25rem;
    background: linear-gradient(135deg, #58a6ff, #bc8cff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }}
  .subtitle {{ color: var(--text-muted); margin-bottom: 2rem; font-size: 0.9rem; }}
  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    text-align: center;
  }}
  .card .count {{
    font-size: 2rem;
    font-weight: 700;
    display: block;
    margin-bottom: 0.25rem;
  }}
  .card .label {{ color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card.critical .count {{ color: var(--critical); }}
  .card.high .count {{ color: var(--high); }}
  .card.medium .count {{ color: var(--medium); }}
  .card.low .count {{ color: var(--low); }}
  .card.info .count {{ color: var(--info); }}
  .card.exposed .count {{ color: var(--exposed); }}
  .card.unknown .count {{ color: var(--unknown); }}
  .card.safe .count {{ color: var(--safe); }}
  .card.total .count {{ color: var(--text); }}
  .section-title {{
    font-size: 1.2rem;
    margin: 2rem 0 1rem 0;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
  }}
  .finding {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    margin-bottom: 0.75rem;
    border-left: 4px solid var(--border);
  }}
  .finding.critical {{ border-left-color: var(--critical); }}
  .finding.high {{ border-left-color: var(--high); }}
  .finding.medium {{ border-left-color: var(--medium); }}
  .finding.low {{ border-left-color: var(--low); }}
  .finding.exposed {{ border-left-color: var(--exposed); }}
  .finding.pinned_unknown {{ border-left-color: var(--unknown); }}
  .finding.safe {{ border-left-color: var(--safe); }}
  .badge {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .badge.critical {{ background: rgba(248,81,73,0.15); color: var(--critical); }}
  .badge.high {{ background: rgba(240,136,62,0.15); color: var(--high); }}
  .badge.medium {{ background: rgba(210,153,34,0.15); color: var(--medium); }}
  .badge.low {{ background: rgba(63,185,80,0.15); color: var(--low); }}
  .badge.info {{ background: rgba(88,166,255,0.15); color: var(--info); }}
  .badge.exposed {{ background: rgba(248,81,73,0.15); color: var(--exposed); }}
  .badge.pinned_unknown {{ background: rgba(210,153,34,0.15); color: var(--unknown); }}
  .badge.safe {{ background: rgba(63,185,80,0.15); color: var(--safe); }}
  .finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }}
  .finding-repo {{ font-weight: 600; }}
  .finding-detail {{ color: var(--text-muted); font-size: 0.85rem; margin-left: 1rem; }}
  .finding-detail code {{
    background: rgba(110,118,129,0.15);
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    font-size: 0.85em;
  }}
  .source-chain {{
    color: var(--info);
    font-size: 0.85rem;
    margin-left: 1rem;
    font-style: italic;
  }}
  .rationale {{
    margin-top: 0.5rem;
    margin-left: 1rem;
    color: var(--text-muted);
    font-size: 0.85rem;
  }}
  .empty-state {{
    text-align: center;
    color: var(--text-muted);
    padding: 3rem;
    font-size: 1.1rem;
  }}
  footer {{
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 0.8rem;
    text-align: center;
  }}
</style>
</head>
<body>
{body}
<footer>
  Generated by ActionRadius &mdash; {timestamp}
</footer>
</body>
</html>"""


def generate_html_general(total_sites: int, findings: list[dict], scan_label: str = "") -> str:
    """HTML report for a general scan."""
    title = f"General Scan — {scan_label}" if scan_label else "General Scan"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Count by severity
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f["risk"]["severity"]
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # Summary cards
    cards = f"""
    <div class="cards">
      <div class="card total"><span class="count">{total_sites}</span><span class="label">Total Sites</span></div>
      <div class="card total"><span class="count">{len(findings)}</span><span class="label">Mutable</span></div>
      <div class="card critical"><span class="count">{sev_counts['CRITICAL']}</span><span class="label">Critical</span></div>
      <div class="card high"><span class="count">{sev_counts['HIGH']}</span><span class="label">High</span></div>
      <div class="card medium"><span class="count">{sev_counts['MEDIUM']}</span><span class="label">Medium</span></div>
      <div class="card low"><span class="count">{sev_counts['LOW']}</span><span class="label">Low</span></div>
    </div>"""

    # Findings
    sorted_findings = sorted(findings, key=lambda f: f["risk"]["score"], reverse=True)
    if sorted_findings:
        findings_html = '<h2 class="section-title">Findings (by severity)</h2>\n'
        for f in sorted_findings:
            findings_html += _render_finding_html(f)
    else:
        findings_html = '<div class="empty-state">No mutable pins found — all dependencies are SHA-pinned. 🎉</div>'

    body = f"""
    <h1>🎯 ActionRadius Report</h1>
    <p class="subtitle">{title} &mdash; {timestamp}</p>
    {cards}
    {findings_html}"""

    return _HTML_TEMPLATE.format(title=title, body=body, timestamp=timestamp)


def generate_html_targeted(target: str, safe_refs: set[str] | None, results: list, scan_label: str = "") -> str:
    """HTML report for a targeted/matcher scan (incident triage)."""
    from actionradius.matcher import EXPOSED, SAFE, PINNED_UNKNOWN

    title = f"Incident Triage — {target}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    exposed = [r for r in results if r.status == EXPOSED]
    unknown = [r for r in results if r.status == PINNED_UNKNOWN]
    safe = [r for r in results if r.status == SAFE]

    safe_refs_str = ", ".join(sorted(safe_refs)) if safe_refs else "none provided"

    # Summary cards
    cards = f"""
    <div class="cards">
      <div class="card total"><span class="count">{len(results)}</span><span class="label">Total Matches</span></div>
      <div class="card exposed"><span class="count">{len(exposed)}</span><span class="label">Exposed</span></div>
      <div class="card unknown"><span class="count">{len(unknown)}</span><span class="label">Unknown</span></div>
      <div class="card safe"><span class="count">{len(safe)}</span><span class="label">Safe</span></div>
    </div>
    <p class="finding-detail">Target action: <code>{target}</code> &nbsp;|&nbsp; Known-safe refs: <code>{safe_refs_str}</code></p>"""

    body_parts = [
        f'<h1>🚨 ActionRadius — Incident Triage</h1>',
        f'<p class="subtitle">{title} &mdash; {scan_label} &mdash; {timestamp}</p>',
        cards,
    ]

    if exposed:
        body_parts.append('<h2 class="section-title" style="color: var(--exposed);">🔴 EXPOSED — Fix these NOW</h2>')
        for r in exposed:
            body_parts.append(_render_match_html(r))

    if unknown:
        body_parts.append('<h2 class="section-title" style="color: var(--unknown);">🟡 PINNED_UNKNOWN — Verify these</h2>')
        for r in unknown:
            body_parts.append(_render_match_html(r))

    if safe:
        body_parts.append('<h2 class="section-title" style="color: var(--safe);">🟢 SAFE — No action needed</h2>')
        for r in safe:
            body_parts.append(_render_match_html(r))

    if not results:
        body_parts.append(f'<div class="empty-state">No sites reference {target} in the scanned scope.</div>')

    return _HTML_TEMPLATE.format(
        title=title,
        body="\n".join(body_parts),
        timestamp=timestamp,
    )


def _render_finding_html(f: dict) -> str:
    """Render one general finding as an HTML card."""
    sev = f["risk"]["severity"].lower()
    score = f["risk"]["score"]
    source = ""
    if f["site"].source_chain:
        source = f'<div class="source-chain">Found via: {" → ".join(f["site"].source_chain)}</div>'

    rationale = ", ".join(f["risk"]["rationale"])

    return f"""
    <div class="finding {sev}">
      <div class="finding-header">
        <span class="badge {sev}">{f['risk']['severity']} ({score})</span>
        <span class="finding-repo">{f['owner']}/{f['repo']}</span>
      </div>
      <div class="finding-detail">
        📄 <code>{f['file']}</code> &nbsp;→&nbsp; Job: <code>{f['site'].job_id}</code>
      </div>
      <div class="finding-detail">
        🔗 <code>{f['site'].uses.raw}</code> &nbsp;→&nbsp; resolves to <code>{f['sha'] or 'unknown'}</code>
      </div>
      {source}
      <div class="rationale">💡 {rationale}</div>
    </div>"""


def _render_match_html(r) -> str:
    """Render one matcher result as an HTML card."""
    css_class = r.status.lower()
    source = ""
    if r.source_chain:
        source = f'<div class="source-chain">Found via: {" → ".join(r.source_chain)}</div>'

    pin_detail = ""
    if r.ref_type == "mutable_ref":
        resolved = f" → currently resolves to <code>{r.resolved_sha}</code>" if r.resolved_sha else ""
        pin_detail = f'<div class="finding-detail">📌 Mutable pin: <code>@{r.ref}</code>{resolved}</div>'
    elif r.ref_type == "sha":
        sha_type = "full SHA" if r.is_full_sha else "short SHA"
        pin_detail = f'<div class="finding-detail">📌 Pinned to {sha_type}: <code>@{r.ref}</code></div>'
    elif r.ref_type == "unresolvable":
        pin_detail = f'<div class="finding-detail">📌 Dynamic expression: <code>@{r.ref}</code> (cannot verify statically)</div>'

    action_text = ""
    if r.status == "EXPOSED":
        action_text = '<div class="finding-detail" style="color: var(--exposed);">⚠️ Action: Pin to a known-safe SHA immediately.</div>'
    elif r.status == "PINNED_UNKNOWN":
        action_text = '<div class="finding-detail" style="color: var(--unknown);">⚠️ Action: Verify this SHA is not a compromised commit.</div>'

    return f"""
    <div class="finding {css_class}">
      <div class="finding-header">
        <span class="badge {css_class}">{r.status}</span>
        <span class="finding-repo">{r.owner}/{r.repo}</span>
      </div>
      <div class="finding-detail">
        📄 <code>{r.workflow_path}</code> &nbsp;→&nbsp; Job: <code>{r.job_id}</code>
      </div>
      <div class="finding-detail">
        🔗 <code>{r.raw_uses}</code>
      </div>
      {pin_detail}
      {source}
      {action_text}
    </div>"""
