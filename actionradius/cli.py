import typer
import sys
from typing import Optional
from actionradius.config import get_config
from actionradius.github_client import GitHubClient
from actionradius.inventory.repo_lister import get_org_repos, get_repo
from actionradius.inventory.tree_fetcher import fetch_workflow_contents
from actionradius.parser.workflow_parser import parse_workflow_yaml
from actionradius.parser.composite_resolver import resolve_reusable_workflows
from actionradius.resolve.ref_resolver import resolve_mutable_ref
from actionradius.match.matcher import is_match, is_compromised
from actionradius.score.scoring import calculate_risk_score
from actionradius.models import Finding
from actionradius.report.json_report import generate_json_report
from actionradius.report.html_report import generate_html_report
from actionradius.report.sarif_report import generate_sarif_report
from actionradius.report.graph_report import generate_graph_report

app = typer.Typer()

@app.command()
def scan(
    target: Optional[str] = typer.Option(None, "--target", help="Target action (e.g. aquasecurity/trivy-action)"),
    org: Optional[str] = typer.Option(None, "--org", help="Organization to scan"),
    repo: Optional[str] = typer.Option(None, "--repo", help="Single repo to scan (format: owner/name)"),
    safe_refs: list[str] = typer.Option([], "--safe-ref", help="Safe SHAs/tags (can pass multiple)"),
    json_out: Optional[str] = typer.Option(None, "--json", help="Path to write JSON report"),
    html_out: Optional[str] = typer.Option(None, "--html", help="Path to write HTML report"),
    sarif_out: Optional[str] = typer.Option(None, "--sarif", help="Path to write SARIF report (for GitHub Advanced Security)"),
    graph_out: Optional[str] = typer.Option(None, "--graph", help="Path to write Graphviz DOT report"),
    ioc_search: Optional[str] = typer.Option(None, "--ioc-search", help="Search string/domain in workflow run scripts")
):
    """Scan repositories for exposed GitHub Actions."""
    config = get_config()
    client = GitHubClient(token=config.github_token)

    if not target and not ioc_search:
        typer.secho("Error: Must provide --target or --ioc-search", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    if not org and not repo:
        typer.secho("Error: Must provide --org or --repo", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    repos = []
    if org:
        typer.secho(f"Fetching repos for org: {org}...", fg=typer.colors.CYAN, err=True)
        repos = get_org_repos(client, org)
    elif repo:
        owner, name = repo.split("/", 1)
        repos = [get_repo(client, owner, name)]

    findings: list[Finding] = []
    ioc_matches = []

    for r in repos:
        typer.secho(f"Scanning {r.owner}/{r.name}...", fg=typer.colors.BLUE, err=True)
        try:
            files_dict = fetch_workflow_contents(client, r.owner, r.name, r.default_branch)
            wfs = []
            for path, text in files_dict.items():
                try:
                    wfs.append(parse_workflow_yaml(r, path, text))
                except Exception as e:
                    typer.secho(f"  WARNING: Parse error in {path}: {e}", fg=typer.colors.YELLOW, err=True)
            
            wfs = resolve_reusable_workflows(client, wfs)

            for wf in wfs:
                if ioc_search:
                    for script in getattr(wf, 'run_scripts', []):
                        if ioc_search in script:
                            ioc_matches.append((r.owner, r.name, wf.path, script))
                            typer.secho(f"[IOC MATCH] {r.owner}/{r.name}:{wf.path}", fg=typer.colors.RED, err=True)

                if target:
                    for site in wf.uses_sites:
                        if is_match(site, target):
                            resolved = resolve_mutable_ref(client, site.uses)
                            compromised = is_compromised(resolved, safe_refs)
                            score, severity, rationale = calculate_risk_score(
                                is_mutable=resolved.is_mutable,
                                is_compromised=compromised,
                                is_orphan=resolved.is_orphan,
                                trigger=wf.triggers,
                                permissions=wf.permissions,
                                secrets=wf.secrets,
                                runs_on_self_hosted=wf.runs_on_self_hosted
                            )
                            
                            f = Finding(
                                repo=r,
                                uses_site=site,
                                resolved=resolved,
                                is_compromised_version=compromised,
                                trigger=wf.triggers,
                                permissions=wf.permissions,
                                secrets=wf.secrets,
                                severity=severity,
                                score=score,
                                rationale=rationale
                            )
                            findings.append(f)
        except Exception as e:
            typer.secho(f"  WARNING: failed scanning {r.owner}/{r.name}: {e}", fg=typer.colors.YELLOW, err=True)

    if ioc_search:
        typer.secho(f"\nIOC Search complete. Found {len(ioc_matches)} scripts containing '{ioc_search}'.", fg=typer.colors.GREEN, err=True)
        return

    typer.secho(f"\nScan complete. Found {len(findings)} matching sites.", fg=typer.colors.GREEN, err=True)
    
    if json_out:
        generate_json_report(findings, json_out)
        typer.secho(f"Wrote JSON report to {json_out}", fg=typer.colors.GREEN, err=True)
        
    if html_out:
        generate_html_report(findings, html_out, target)
        typer.secho(f"Wrote HTML report to {html_out}", fg=typer.colors.GREEN, err=True)
        
    if sarif_out:
        generate_sarif_report(findings, sarif_out)
        typer.secho(f"Wrote SARIF report to {sarif_out}", fg=typer.colors.GREEN, err=True)

    if graph_out:
        generate_graph_report(findings, graph_out, target)
        typer.secho(f"Wrote Graphviz DOT report to {graph_out}", fg=typer.colors.GREEN, err=True)

    if not json_out and not html_out and not sarif_out and not graph_out:
        for f in findings:
            typer.secho(f"[{f.severity.upper()}] {f.repo.owner}/{f.repo.name}:{f.uses_site.workflow_path} -> {f.uses_site.uses.raw}", err=True)

if __name__ == "__main__":
    app()
