"""
Drift mode: diff two JSON report runs and show newly introduced findings.

Usage:
  python -m actionradius.drift run1.json run2.json
"""

import json
import sys
import typer

app = typer.Typer()


def _finding_key(f: dict) -> str:
    """Generate a unique key for a finding based on repo + workflow + action."""
    repo = f.get("repo", {})
    site = f.get("uses_site", {})
    uses = site.get("uses", {})
    return f"{repo.get('owner', '')}/{repo.get('name', '')}:{site.get('workflow_path', '')}:{uses.get('raw', '')}"


@app.command()
def diff(
    baseline: str = typer.Argument(..., help="Path to the baseline JSON report (older run)"),
    current: str = typer.Argument(..., help="Path to the current JSON report (newer run)"),
):
    """Compare two ActionRadius JSON reports and show new/resolved findings."""
    with open(baseline, "r", encoding="utf-8") as f:
        baseline_findings = json.load(f)
    with open(current, "r", encoding="utf-8") as f:
        current_findings = json.load(f)

    baseline_keys = {_finding_key(f) for f in baseline_findings}
    current_keys = {_finding_key(f) for f in current_findings}

    new_keys = current_keys - baseline_keys
    resolved_keys = baseline_keys - current_keys
    unchanged_keys = baseline_keys & current_keys

    # Build lookup for severity
    current_by_key = {_finding_key(f): f for f in current_findings}
    baseline_by_key = {_finding_key(f): f for f in baseline_findings}

    # --- New findings ---
    if new_keys:
        typer.secho(f"\n🚨 {len(new_keys)} NEW finding(s) introduced:", fg=typer.colors.RED)
        for key in sorted(new_keys):
            f = current_by_key[key]
            sev = f.get("severity", "unknown").upper()
            typer.secho(f"  [NEW] [{sev}] {key}", fg=typer.colors.RED)
    else:
        typer.secho("\n✅ No new findings introduced.", fg=typer.colors.GREEN)

    # --- Resolved findings ---
    if resolved_keys:
        typer.secho(f"\n✅ {len(resolved_keys)} finding(s) resolved:", fg=typer.colors.GREEN)
        for key in sorted(resolved_keys):
            f = baseline_by_key[key]
            sev = f.get("severity", "unknown").upper()
            typer.secho(f"  [RESOLVED] [{sev}] {key}", fg=typer.colors.GREEN)
    else:
        typer.secho("\nNo findings resolved since baseline.", fg=typer.colors.YELLOW)

    # --- Summary ---
    typer.secho(f"\nSummary: {len(new_keys)} new, {len(resolved_keys)} resolved, {len(unchanged_keys)} unchanged.", fg=typer.colors.CYAN)

    # Exit code 1 if new findings were introduced (useful for CI gates)
    if new_keys:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
