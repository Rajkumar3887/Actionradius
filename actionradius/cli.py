import typer
import json
import sys
from typing import Optional
from pathlib import Path
from actionradius.config import get_config
from actionradius.github_client import GitHubClient
from actionradius.inventory.repo_lister import get_org_repos, get_repo, check_exfil_repos
from actionradius.inventory.tree_fetcher import fetch_workflow_contents
from actionradius.parser.workflow_parser import parse_workflow_yaml
from actionradius.parser.composite_resolver import resolve_reusable_workflows
from actionradius.resolve.ref_resolver import resolve_mutable_ref
from actionradius.match.matcher import is_match, determine_compromise_status
from actionradius.score.scoring import calculate_risk_score
from actionradius.models import Finding, ResolvedRef
from actionradius.report.json_report import generate_json_report
from actionradius.report.html_report import generate_html_report
from actionradius.report.sarif_report import generate_sarif_report
from actionradius.report.graph_report import generate_graph_report
from actionradius.match.typosquat import check_typosquat
from actionradius.match.sha_comment_check import detect_sha_comment_mismatches
from actionradius.context.publisher_trust import check_publisher_trust

app = typer.Typer()


def _load_feed(feed_path: str) -> list[dict]:
    """Load a compromised-actions JSON feed file."""
    with open(feed_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Feed must be a JSON array of entries")
    return data


def _scan_workflows(
    client: GitHubClient,
    repos: list,
    target: str,
    safe_refs: list[str],
    bad_range: dict | None,
    ioc_search: str | None,
    findings: list[Finding],
    ioc_matches: list,
    attack_window: dict | None = None,
    run_typosquat: bool = True,
    external_findings: set | None = None,
    prefetched_files: dict | None = None,
):
    """Core scanning loop shared by single-target and feed modes."""
    for r in repos:
        typer.secho(f"Scanning {r.owner}/{r.name}...", fg=typer.colors.BLUE, err=True)
        try:
            repo_key = f"{r.owner}/{r.name}"
            if prefetched_files and repo_key in prefetched_files:
                files_dict = prefetched_files[repo_key]
            else:
                files_dict = fetch_workflow_contents(client, r.owner, r.name, r.default_branch)
            wfs = []
            for path, text in files_dict.items():
                try:
                    wfs.append(parse_workflow_yaml(r, path, text))
                except Exception as e:
                    typer.secho(f"  WARNING: Parse error in {path}: {e}", fg=typer.colors.YELLOW, err=True)

            wfs = resolve_reusable_workflows(client, wfs)

            # SHA/comment mismatch detection — catches spoofed version comments
            for path, text in files_dict.items():
                try:
                    mismatches = detect_sha_comment_mismatches(client, path, text)
                    for mm in mismatches:
                        typer.secho(
                            f"[SHA MISMATCH] {r.owner}/{r.name}:{mm.workflow_path}:{mm.line_number} "
                            f"pins {mm.owner}/{mm.repo}@{mm.pinned_sha[:12]}... "
                            f"but comment says '{mm.comment_tag}' "
                            f"(tag actually resolves to {mm.actual_tag_sha[:12] if mm.actual_tag_sha else '???'}...)",
                            fg=typer.colors.RED, err=True
                        )
                except Exception:
                    pass

            for wf in wfs:
                if ioc_search:
                    for script in getattr(wf, 'run_scripts', []):
                        if ioc_search in script:
                            ioc_matches.append((r.owner, r.name, wf.path, script))
                            typer.secho(f"[IOC MATCH] {r.owner}/{r.name}:{wf.path}", fg=typer.colors.RED, err=True)

                # Typosquat detection — runs on every scan, independent of target
                if run_typosquat:
                    for site in wf.uses_sites:
                        squat = check_typosquat(site)
                        if squat:
                            typer.secho(
                                f"[TYPOSQUAT] {r.owner}/{r.name}:{squat['workflow_path']} "
                                f"uses '{squat['suspicious_action']}' — looks like '{squat['similar_to']}' "
                                f"(edit distance: {squat['edit_distance']})",
                                fg=typer.colors.RED, err=True
                            )
                            
                            resolved = ResolvedRef(uses=site.uses, current_sha=None, is_mutable=True)
                            score, severity, rationale = calculate_risk_score(
                                is_mutable=True,
                                compromise_status="UNKNOWN",
                                is_orphan=False,
                                trigger=wf.triggers,
                                permissions=wf.permissions,
                                secrets=wf.secrets,
                                runs_on_self_hosted=wf.runs_on_self_hosted,
                                is_typosquat=True,
                                has_external_finding=(external_findings is not None and wf.path in external_findings),
                            )
                            
                            hist_exp = "UNKNOWN"
                            if attack_window:
                                from actionradius.context.historical import check_historical_exposure
                                hist_exp = check_historical_exposure(client, r.owner, r.name, site.workflow_path, attack_window, site.uses)
                                
                            f = Finding(
                                repo=r,
                                uses_site=site,
                                resolved=resolved,
                                compromise_status="UNKNOWN",
                                historical_exposure=hist_exp,
                                pin_type=site.uses.ref_type,
                                trigger=wf.triggers,
                                permissions=wf.permissions,
                                secrets=wf.secrets,
                                severity=severity,
                                score=score,
                                rationale=rationale,
                                is_typosquat=True
                            )
                            findings.append(f)

                if target:
                    for site in wf.uses_sites:
                        # Docker mutable-tag detection — runs on every target scan, independent of target
                        if site.uses.ref_type == "docker":
                            resolved = ResolvedRef(
                                uses=site.uses,
                                current_sha=None,
                                is_mutable=True,
                            )
                            score, severity, rationale = calculate_risk_score(
                                is_mutable=True,
                                compromise_status="UNKNOWN",
                                is_orphan=False,
                                trigger=wf.triggers,
                                permissions=wf.permissions,
                                secrets=wf.secrets,
                                runs_on_self_hosted=wf.runs_on_self_hosted,
                                is_docker_mutable=True,
                                has_external_finding=(external_findings is not None and wf.path in external_findings),
                            )
                            hist_exp = "UNKNOWN"
                            if attack_window:
                                from actionradius.context.historical import check_historical_exposure
                                hist_exp = check_historical_exposure(client, r.owner, r.name, site.workflow_path, attack_window, site.uses)

                            f = Finding(
                                repo=r,
                                uses_site=site,
                                resolved=resolved,
                                compromise_status="UNKNOWN",
                                historical_exposure=hist_exp,
                                pin_type="docker",
                                trigger=wf.triggers,
                                permissions=wf.permissions,
                                secrets=wf.secrets,
                                severity=severity,
                                score=score,
                                rationale=rationale,
                            )
                            findings.append(f)
                            typer.secho(
                                f"[DOCKER] {r.owner}/{r.name}:{site.workflow_path} "
                                f"uses mutable Docker tag: {site.uses.raw}",
                                fg=typer.colors.YELLOW, err=True,
                            )
                            continue  # Already handled — skip target matching for this site

                        if is_match(site, target):
                            resolved = resolve_mutable_ref(client, site.uses)

                            # Determine compromise status using unified function
                            compromise_status = determine_compromise_status(
                                client=client,
                                resolved=resolved,
                                safe_refs=safe_refs,
                                bad_range=bad_range,
                            )

                            publisher_trust = "unknown"
                            if site.uses.owner and site.uses.repo:
                                publisher_trust = check_publisher_trust(client, site.uses.owner, site.uses.repo)

                            score, severity, rationale = calculate_risk_score(
                                is_mutable=resolved.is_mutable,
                                compromise_status=compromise_status,
                                is_orphan=resolved.is_orphan,
                                trigger=wf.triggers,
                                permissions=wf.permissions,
                                secrets=wf.secrets,
                                runs_on_self_hosted=wf.runs_on_self_hosted,
                                is_unverified_publisher=(publisher_trust == "new_org"),
                                has_external_finding=(external_findings is not None and wf.path in external_findings),
                            )

                            hist_exp = "UNKNOWN"
                            if attack_window:
                                from actionradius.context.historical import check_historical_exposure
                                hist_exp = check_historical_exposure(client, r.owner, r.name, site.workflow_path, attack_window, site.uses)

                            f = Finding(
                                repo=r,
                                uses_site=site,
                                resolved=resolved,
                                compromise_status=compromise_status,
                                historical_exposure=hist_exp,
                                pin_type=site.uses.ref_type,
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


@app.command()
def scan(
    target: Optional[str] = typer.Option(None, "--target", help="Target action (e.g. aquasecurity/trivy-action)"),
    org: Optional[str] = typer.Option(None, "--org", help="Organization to scan"),
    repo: Optional[str] = typer.Option(None, "--repo", help="Single repo to scan (format: owner/name)"),
    safe_refs: list[str] = typer.Option([], "--safe-ref", help="Safe SHAs/tags (can pass multiple)"),
    bad_from: Optional[str] = typer.Option(None, "--bad-from", help="Start of compromised commit range (inclusive)"),
    bad_to: Optional[str] = typer.Option(None, "--bad-to", help="End of compromised commit range (the fix commit)"),
    target_feed: Optional[str] = typer.Option(None, "--target-feed", help="Path to a compromised-actions JSON feed file"),
    json_out: Optional[str] = typer.Option(None, "--json", help="Path to write JSON report"),
    html_out: Optional[str] = typer.Option(None, "--html", help="Path to write HTML report"),
    sarif_out: Optional[str] = typer.Option(None, "--sarif", help="Path to write SARIF report (for GitHub Advanced Security)"),
    graph_out: Optional[str] = typer.Option(None, "--graph", help="Path to write Graphviz DOT report"),
    ioc_search: Optional[str] = typer.Option(None, "--ioc-search", help="Search string/domain in workflow run scripts"),
    check_exfil: bool = typer.Option(False, "--check-exfil", help="Search org members for tpcp-docs exfiltration repos"),
    weights_file: Optional[str] = typer.Option(None, "--weights", help="Path to custom weights.yaml for scoring"),
    external_sarif: Optional[str] = typer.Option(None, "--external-sarif", help="Path to a SARIF file from an external linter (e.g. zizmor/poutine)"),
    concurrent: bool = typer.Option(False, "--concurrent", help="Use async concurrent fetching for org scans"),
):
    """Scan repositories for exposed GitHub Actions."""
    config = get_config()
    client = GitHubClient(token=config.github_token)

    # Load custom weights if provided
    if weights_file:
        from actionradius.score.scoring import load_weights
        load_weights(weights_file)

    # --- Argument validation ---
    if not target and not ioc_search and not target_feed and not check_exfil:
        typer.secho("Error: Must provide --target, --target-feed, --ioc-search, or --check-exfil", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    if not org and not repo:
        typer.secho("Error: Must provide --org or --repo", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # --safe-ref and --bad-from/--bad-to are mutually exclusive
    if safe_refs and (bad_from or bad_to):
        typer.secho("Error: --safe-ref and --bad-from/--bad-to are mutually exclusive. Use one matching mode.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # --bad-from and --bad-to must both be provided
    if (bad_from and not bad_to) or (bad_to and not bad_from):
        typer.secho("Error: --bad-from and --bad-to must both be provided to define a compromised range.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # --- Exfiltration check (tpcp-docs) ---
    if check_exfil:
        scan_org = org or (repo.split("/", 1)[0] if repo else None)
        if not scan_org:
            typer.secho("Error: --check-exfil requires --org or --repo", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        typer.secho(f"Checking for tpcp-docs exfiltration repos in {scan_org}...", fg=typer.colors.CYAN, err=True)
        hits = check_exfil_repos(client, scan_org)
        if hits:
            typer.secho(f"\n🚨 EXFILTRATION DETECTED: Found tpcp-docs repos on {len(hits)} account(s):", fg=typer.colors.RED, err=True)
            for h in hits:
                typer.secho(f"  → https://github.com/{h}/tpcp-docs", fg=typer.colors.RED, err=True)
            typer.secho("\n  These repos may contain encrypted credential bundles from the TeamPCP/Trivy attack.", fg=typer.colors.RED, err=True)
            typer.secho("  IMMEDIATE ACTION: Rotate all secrets accessible to CI workflows on these accounts.", fg=typer.colors.RED, err=True)
        else:
            typer.secho("✅ No tpcp-docs exfiltration repos found.", fg=typer.colors.GREEN, err=True)
        if not target and not ioc_search and not target_feed:
            return  # --check-exfil was the only action requested

    repos = []
    if org:
        typer.secho(f"Fetching repos for org: {org}...", fg=typer.colors.CYAN, err=True)
        repos = get_org_repos(client, org)
    elif repo:
        owner, name = repo.split("/", 1)
        repos = [get_repo(client, owner, name)]

    external_findings = None
    if external_sarif:
        from actionradius.context.external_findings import load_external_sarif
        external_findings = load_external_sarif(external_sarif)
        typer.secho(f"Loaded {len(external_findings)} tainted workflow paths from external SARIF.", fg=typer.colors.CYAN, err=True)

    prefetched_files = None
    if concurrent:
        try:
            from actionradius.async_scan import prefetch_all_workflows
            typer.secho(f"Prefetching workflows for {len(repos)} repos concurrently...", fg=typer.colors.CYAN, err=True)
            prefetched_files = prefetch_all_workflows(token=config.github_token, repos=repos)
        except ImportError:
            typer.secho("Error: --concurrent requires httpx. Run: pip install httpx", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

    findings: list[Finding] = []
    ioc_matches = []

    # --- Feed mode: iterate over every entry in the curated JSON ---
    if target_feed:
        feed = _load_feed(target_feed)
        typer.secho(f"Loaded {len(feed)} entries from feed: {target_feed}", fg=typer.colors.CYAN, err=True)

        for i, entry in enumerate(feed):
            action = entry["action"]
            feed_bad_range = entry.get("bad_range")
            cve = entry.get("cve", "N/A")
            typer.secho(f"\n--- Scanning for {action} ({cve}) ---", fg=typer.colors.MAGENTA, err=True)

            _scan_workflows(
                client=client,
                repos=repos,
                target=action,
                safe_refs=[],
                bad_range=feed_bad_range,
                ioc_search=None,
                findings=findings,
                ioc_matches=ioc_matches,
                attack_window=entry.get("attack_window"),
                run_typosquat=(i == 0),
                external_findings=external_findings,
                prefetched_files=prefetched_files,
            )

    # --- Single-target mode ---
    else:
        bad_range = None
        if bad_from and bad_to:
            bad_range = {"introduced": bad_from, "fixed": bad_to}

        _scan_workflows(
            client=client,
            repos=repos,
            target=target,
            safe_refs=safe_refs,
            bad_range=bad_range,
            ioc_search=ioc_search,
            findings=findings,
            ioc_matches=ioc_matches,
            attack_window=None,
            external_findings=external_findings,
            prefetched_files=prefetched_files,
        )

    # --- IOC results ---
    if ioc_search:
        typer.secho(f"\nIOC Search complete. Found {len(ioc_matches)} scripts containing '{ioc_search}'.", fg=typer.colors.GREEN, err=True)
        return

    # --- Report output ---
    typer.secho(f"\nScan complete. Found {len(findings)} matching sites.", fg=typer.colors.GREEN, err=True)

    report_target = target or "multi-target (feed)"

    if json_out:
        generate_json_report(findings, json_out)
        typer.secho(f"Wrote JSON report to {json_out}", fg=typer.colors.GREEN, err=True)

    if html_out:
        generate_html_report(findings, html_out, report_target)
        typer.secho(f"Wrote HTML report to {html_out}", fg=typer.colors.GREEN, err=True)

    if sarif_out:
        generate_sarif_report(findings, sarif_out)
        typer.secho(f"Wrote SARIF report to {sarif_out}", fg=typer.colors.GREEN, err=True)

    if graph_out:
        if target_feed:
            typer.secho("WARNING: --graph not supported with --target-feed. Run per-action for per-action graphs.", fg=typer.colors.YELLOW, err=True)
        else:
            generate_graph_report(findings, graph_out, report_target)
            typer.secho(f"Wrote Graphviz DOT report to {graph_out}", fg=typer.colors.GREEN, err=True)

    if not json_out and not html_out and not sarif_out and not graph_out:
        for f in findings:
            status_label = f.compromise_status
            typer.secho(f"[{f.severity.upper()}] [{status_label}] {f.repo.owner}/{f.repo.name}:{f.uses_site.workflow_path} -> {f.uses_site.uses.raw}", err=True)


@app.command()
def diff(
    base_report: str = typer.Argument(..., help="Path to the base (older) JSON report"),
    head_report: str = typer.Argument(..., help="Path to the head (newer) JSON report")
):
    """Compare two JSON reports to find new, resolved, and escalated findings."""
    from actionradius.drift import diff_reports
    diff_reports(base_report, head_report)

if __name__ == "__main__":
    app()
