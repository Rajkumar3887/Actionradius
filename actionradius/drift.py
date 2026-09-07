import json
import typer

SEVERITY_RANKS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

def load_report(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _finding_identity(finding: dict) -> tuple:
    """
    Collision-free identity for a finding, used as the internal dict key.

    `uses_raw` (the raw `uses:` string) originates from a scanned — and
    potentially attacker-controlled — workflow file. Using it inside a
    single formatted string (as the old `_finding_key` did) meant a crafted
    `uses:` value containing the literal display separator could construct
    a key that collides with a different finding's key, silently merging
    two distinct findings in the diff. A tuple of the raw components can't
    collide this way: two findings are only ever considered "the same"
    finding if every field actually matches.
    """
    return (
        finding["repo"]["owner"],
        finding["repo"]["name"],
        finding["uses_site"]["workflow_path"],
        finding["uses_site"]["uses"]["raw"],
    )


def _finding_label(finding: dict) -> str:
    """Human-readable display string for a finding, for CLI output only —
    never used as a dict key (see `_finding_identity`)."""
    repo_owner = finding["repo"]["owner"]
    repo_name = finding["repo"]["name"]
    workflow_path = finding["uses_site"]["workflow_path"]
    uses_raw = finding["uses_site"]["uses"]["raw"]
    return f"{repo_owner}/{repo_name}:{workflow_path} -> {uses_raw}"


def diff_reports(report_a_path: str, report_b_path: str):
    """Compare two ActionRadius JSON reports and print the differences."""
    try:
        report_a = load_report(report_a_path)
        report_b = load_report(report_b_path)
    except Exception as e:
        typer.secho(f"Error loading reports: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    dict_a = {_finding_identity(f): f for f in report_a}
    dict_b = {_finding_identity(f): f for f in report_b}

    keys_a = set(dict_a.keys())
    keys_b = set(dict_b.keys())

    resolved_keys = keys_a - keys_b
    new_keys = keys_b - keys_a
    common_keys = keys_a & keys_b

    escalated = []
    de_escalated = []

    for k in common_keys:
        sev_a = dict_a[k].get("severity", "info").lower()
        sev_b = dict_b[k].get("severity", "info").lower()
        
        rank_a = SEVERITY_RANKS.get(sev_a, 0)
        rank_b = SEVERITY_RANKS.get(sev_b, 0)
        
        if rank_b > rank_a:
            escalated.append((k, sev_a, sev_b, dict_b[k]))
        elif rank_b < rank_a:
            de_escalated.append((k, sev_a, sev_b, dict_b[k]))

    # Print results
    typer.secho(f"--- ActionRadius Drift Report ---", fg=typer.colors.CYAN, bold=True)
    typer.secho(f"Base: {report_a_path} ({len(keys_a)} findings)")
    typer.secho(f"Head: {report_b_path} ({len(keys_b)} findings)\n")

    if not new_keys and not resolved_keys and not escalated and not de_escalated:
        typer.secho("✅ No drift detected. Reports are identical.", fg=typer.colors.GREEN)
        return

    if new_keys:
        typer.secho(f"🚨 NEW FINDINGS ({len(new_keys)}):", fg=typer.colors.RED, bold=True)
        for k in sorted(new_keys, key=lambda k: _finding_label(dict_b[k])):
            sev = dict_b[k].get("severity", "info").upper()
            status = dict_b[k].get("compromise_status", "UNKNOWN")
            typer.secho(f"  [{sev}] [{status}] {_finding_label(dict_b[k])}", fg=typer.colors.RED)
        print()

    if escalated:
        typer.secho(f"⚠️ ESCALATED FINDINGS ({len(escalated)}):", fg=typer.colors.YELLOW, bold=True)
        for k, sev_a, sev_b, finding in sorted(escalated, key=lambda x: _finding_label(x[3])):
            status = finding.get("compromise_status", "UNKNOWN")
            typer.secho(f"  [{sev_a.upper()} -> {sev_b.upper()}] [{status}] {_finding_label(finding)}", fg=typer.colors.YELLOW)
        print()
        
    if de_escalated:
        typer.secho(f"📉 DE-ESCALATED FINDINGS ({len(de_escalated)}):", fg=typer.colors.BLUE, bold=True)
        for k, sev_a, sev_b, finding in sorted(de_escalated, key=lambda x: _finding_label(x[3])):
            status = finding.get("compromise_status", "UNKNOWN")
            typer.secho(f"  [{sev_a.upper()} -> {sev_b.upper()}] [{status}] {_finding_label(finding)}", fg=typer.colors.BLUE)
        print()

    if resolved_keys:
        typer.secho(f"✅ RESOLVED FINDINGS ({len(resolved_keys)}):", fg=typer.colors.GREEN, bold=True)
        for k in sorted(resolved_keys, key=lambda k: _finding_label(dict_a[k])):
            typer.secho(f"  {_finding_label(dict_a[k])}", fg=typer.colors.GREEN)
        print()
