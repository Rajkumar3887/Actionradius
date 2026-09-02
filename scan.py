"""
scan.py — CLI entry point for ActionRadius.

Two modes of operation:

1. GENERAL SCAN (existing):
   python scan.py <owner> <repo>           # one repo
   python scan.py --org <org>              # all repos in an org
   Shows all mutable/risky pins, scored and prioritized.

2. INCIDENT TRIAGE (new — the matcher):
   python scan.py <owner> <repo> --target aquasecurity/trivy-action
   python scan.py --org <org> --target aquasecurity/trivy-action
   python scan.py --org <org> --target aquasecurity/trivy-action --safe-refs 57a97c7
   Filters to just that one action and classifies every site as
   EXPOSED / SAFE / PINNED_UNKNOWN. This is the question defenders
   couldn't answer quickly during real incidents.
"""

import sys
import os
from dotenv import load_dotenv
from actionradius.github_client import GitHubClient
from actionradius.inventory import inventory_repo
from actionradius.context import analyze_context
from actionradius.scoring import calculate_risk_score
from actionradius.ref_resolver import resolve_mutable_ref
from actionradius.matcher import match_target, format_match_summary, EXPOSED
from actionradius.report import (
    generate_json_general, generate_json_targeted,
    generate_html_general, generate_html_targeted,
)
from actionradius.incidents import get_incident, list_incidents, format_incident_list


def scan_repo(client, owner, repo):
    """
    Core scanning logic for ONE repo — pure with respect to output (no
    printing here), so both single-repo and org-wide modes can share it.
    Returns (total_sites, findings). Each finding also carries owner/repo
    so an org-wide caller can tell which repo it came from.
    """
    workflows = inventory_repo(client, owner, repo)

    total_sites = 0
    findings = []

    for wf in workflows:
        # 1. Get the security context for this specific workflow
        ctx = analyze_context(wf.raw_dict)

        for site in wf.uses_sites:
            total_sites += 1

            # UsesRef classifies refs via `ref_type` (a Literal), not a
            # boolean — "mutable_ref" means we couldn't tell tag vs branch
            # from the YAML alone, which is exactly the case we need to
            # resolve via the API below.
            if site.uses.ref_type == "mutable_ref":
                # Resolve against the ACTION's own owner/repo (e.g. actions/checkout),
                # not the repo being scanned — those are almost always different.
                current_sha = resolve_mutable_ref(site.uses.owner, site.uses.repo, site.uses.ref)

                # Calculate Risk using our heuristic model
                risk = calculate_risk_score(is_mutable=True, context=ctx)

                findings.append({
                    "owner": owner,
                    "repo": repo,
                    "file": wf.path,
                    "site": site,
                    "sha": current_sha,
                    "risk": risk
                })

    return total_sites, findings


def scan_repo_targeted(client, owner, repo, target_owner, target_repo, safe_refs):
    """
    Targeted scan for incident triage: inventory one repo, then filter
    to just sites referencing the target action and classify each one.

    Unlike scan_repo(), this returns MatchResults, not generic findings.
    It also resolves mutable refs for exposed sites so the triage output
    can show what SHA they currently point to (i.e. "is this the
    compromised commit right now?").
    """
    workflows = inventory_repo(client, owner, repo)
    results = match_target(
        workflows,
        target_owner=target_owner,
        target_repo=target_repo,
        scanned_owner=owner,
        scanned_repo=repo,
        safe_refs=safe_refs,
    )

    # For EXPOSED sites, resolve the mutable ref so the IR lead can see
    # what SHA the tag/branch currently points to. This is the "is this
    # repo pointing at the compromised commit RIGHT NOW?" question.
    for r in results:
        if r.status == EXPOSED and r.ref_type == "mutable_ref" and r.ref:
            r.resolved_sha = resolve_mutable_ref(target_owner, target_repo, r.ref)

    return workflows, results


def print_findings(findings, show_repo=False):
    """Shared findings printer. show_repo=True prefixes each line with
    owner/repo, which only makes sense once results span multiple repos."""
    findings = sorted(findings, key=lambda f: f["risk"]["score"], reverse=True)
    for f in findings:
        prefix = f"{f['owner']}/{f['repo']} " if show_repo else ""
        print(f"[{f['risk']['severity']}] {prefix}{f['file']} (Job: {f['site'].job_id}) -> {f['site'].uses}")
        if f['site'].source_chain:
            print(f"  Found via: {' -> '.join(f['site'].source_chain)}")
        print(f"  Resolved SHA: {f['sha']}")
        print(f"  Rationale: {', '.join(f['risk']['rationale'])}\n")


def scan_single(client, owner, repo, target=None, safe_refs=None, output_json=False, html_file=None):
    scan_label = f"{owner}/{repo}"
    if target:
        t_owner, t_repo = target.split("/", 1)
        print(f"Scanning {owner}/{repo} for {target}...\n", file=sys.stderr)

        workflows, results = scan_repo_targeted(client, owner, repo, t_owner, t_repo, safe_refs)

        total_sites = sum(len(wf.uses_sites) for wf in workflows)
        print(f"Total uses: sites found: {total_sites}", file=sys.stderr)
        print(f"Sites referencing {target}: {len(results)}\n", file=sys.stderr)

        if output_json:
            print(generate_json_targeted(target, safe_refs, results))
        elif html_file:
            html = generate_html_targeted(target, safe_refs, results, scan_label=scan_label)
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"HTML report written to: {html_file}", file=sys.stderr)
        else:
            if results:
                print(format_match_summary(results, target))
            else:
                print(f"No sites reference {target} in this repo.")
    else:
        print(f"Scanning {owner}/{repo}...\n", file=sys.stderr)
        total_sites, findings = scan_repo(client, owner, repo)

        print(f"Total uses: sites found: {total_sites}", file=sys.stderr)
        print(f"Mutable (unpinned) sites: {len(findings)}\n", file=sys.stderr)

        if output_json:
            print(generate_json_general(total_sites, findings))
        elif html_file:
            html = generate_html_general(total_sites, findings, scan_label=scan_label)
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"HTML report written to: {html_file}", file=sys.stderr)
        else:
            if findings:
                print("--- PRIORITIZED FINDINGS ---\n")
                print_findings(findings, show_repo=False)


def scan_org(client, org, target=None, safe_refs=None, output_json=False, html_file=None):
    scan_label = f"org:{org}"
    print(f"Scanning org: {org}...\n", file=sys.stderr)
    repos = client.get_org_repos(org)  # forks/archived excluded by default
    print(f"Found {len(repos)} repo(s) to scan (forks/archived excluded)\n", file=sys.stderr)

    if target:
        t_owner, t_repo = target.split("/", 1)
        all_results = []

        for i, repo_info in enumerate(repos, start=1):
            repo_name = repo_info["name"]
            print(f"[{i}/{len(repos)}] Scanning {org}/{repo_name}...", file=sys.stderr)
            try:
                _, results = scan_repo_targeted(client, org, repo_name, t_owner, t_repo, safe_refs)
                all_results.extend(results)
            except Exception as e:
                print(f"  WARNING: couldn't scan {org}/{repo_name}: {e}", file=sys.stderr)
                continue

        if output_json:
            print(generate_json_targeted(target, safe_refs, all_results))
        elif html_file:
            html = generate_html_targeted(target, safe_refs, all_results, scan_label=scan_label)
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"HTML report written to: {html_file}", file=sys.stderr)
        else:
            print(f"\n{format_match_summary(all_results, target)}")
    else:
        total_sites_all = 0
        all_findings = []

        for i, repo_info in enumerate(repos, start=1):
            repo_name = repo_info["name"]
            print(f"[{i}/{len(repos)}] Scanning {org}/{repo_name}...", file=sys.stderr)
            try:
                total_sites, findings = scan_repo(client, org, repo_name)
            except Exception as e:
                # One repo failing (empty repo, disabled workflows API, etc.)
                # shouldn't kill an org-wide scan — flag it and move on.
                print(f"  WARNING: couldn't scan {org}/{repo_name}: {e}", file=sys.stderr)
                continue

            total_sites_all += total_sites
            all_findings.extend(findings)

        if output_json:
            print(generate_json_general(total_sites_all, all_findings))
        elif html_file:
            html = generate_html_general(total_sites_all, all_findings, scan_label=scan_label)
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"HTML report written to: {html_file}", file=sys.stderr)
        else:
            print(f"\n=== ORG-WIDE SUMMARY: {org} ===")
            print(f"Repos scanned: {len(repos)}")
            print(f"Total uses: sites found: {total_sites_all}")
            print(f"Mutable (unpinned) sites: {len(all_findings)}\n")

            if all_findings:
                print("--- PRIORITIZED FINDINGS (org-wide) ---\n")
                print_findings(all_findings, show_repo=True)


def parse_args(argv):
    """
    Simple argument parser. We're not using argparse/click to keep
    dependencies minimal and the code transparent — but the CLI is
    getting complex enough that we should at least centralize parsing.

    Returns a dict with keys: mode, owner, repo, org, target, safe_refs
    """
    args = {
        "mode": None,       # "single", "org"
        "owner": None,
        "repo": None,
        "org": None,
        "target": None,     # e.g. "aquasecurity/trivy-action"
        "safe_refs": set(),  # e.g. {"57a97c7", "3fb12ec"}
        "json": False,      # --json: output JSON to stdout
        "html": None,       # --html <file>: write HTML report
        "incident": None,   # --incident <id>: use curated incident data
        "list_incidents": False,  # --list-incidents: show available incidents
    }

    positional = []
    i = 1
    while i < len(argv):
        if argv[i] == "--org":
            if i + 1 >= len(argv):
                return None  # missing value
            args["mode"] = "org"
            args["org"] = argv[i + 1]
            i += 2
        elif argv[i] == "--target":
            if i + 1 >= len(argv):
                return None
            args["target"] = argv[i + 1]
            i += 2
        elif argv[i] == "--safe-refs":
            if i + 1 >= len(argv):
                return None
            # Comma-separated list of SHAs
            args["safe_refs"] = {s.strip() for s in argv[i + 1].split(",") if s.strip()}
            i += 2
        elif argv[i] == "--json":
            args["json"] = True
            i += 1
        elif argv[i] == "--html":
            if i + 1 >= len(argv):
                return None
            args["html"] = argv[i + 1]
            i += 2
        elif argv[i] == "--incident":
            if i + 1 >= len(argv):
                return None
            args["incident"] = argv[i + 1]
            i += 2
        elif argv[i] == "--list-incidents":
            args["list_incidents"] = True
            i += 1
        else:
            positional.append(argv[i])
            i += 1

    # Determine mode from positional args if --org wasn't used
    if args["mode"] is None:
        if len(positional) == 2:
            args["mode"] = "single"
            args["owner"] = positional[0]
            args["repo"] = positional[1]
        else:
            return None

    # Validate --target format
    if args["target"] and "/" not in args["target"]:
        print(f"ERROR: --target must be in 'owner/repo' format, got: {args['target']}")
        return None

    return args


def print_usage():
    print("Usage:")
    print("  python scan.py <owner> <repo>                              # general scan")
    print("  python scan.py --org <org>                                 # org-wide general scan")
    print("")
    print("  Incident triage (the matcher):")
    print("  python scan.py <owner> <repo> --target <action>            # targeted scan")
    print("  python scan.py --org <org> --target <action>               # org-wide targeted scan")
    print("  python scan.py --org <org> --target <action> --safe-refs <sha1,sha2,...>")
    print("")
    print("  Known incidents (curated database):")
    print("  python scan.py --list-incidents                            # show available incidents")
    print("  python scan.py --org <org> --incident trivy-2026           # scan using incident data")
    print("")
    print("  Output formats:")
    print("  python scan.py ... --json                                  # JSON to stdout")
    print("  python scan.py ... --html report.html                      # HTML report file")
    print("")
    print("Examples:")
    print("  python scan.py aquasecurity trivy-action")
    print("  python scan.py --org my-company --target aquasecurity/trivy-action")
    print("  python scan.py --org my-company --target aquasecurity/trivy-action --safe-refs 57a97c7")
    print("  python scan.py --org my-company --incident trivy-2026")
    print("  python scan.py --org my-company --incident trivy-2026 --html triage.html")
    print("  python scan.py --org my-company --json > results.json")


def main():
    load_dotenv()

    # Handle --list-incidents before we even need a token
    if "--list-incidents" in sys.argv:
        print(format_incident_list())
        sys.exit(0)

    client = GitHubClient(os.getenv("GITHUB_TOKEN"))

    args = parse_args(sys.argv)
    if args is None:
        print_usage()
        sys.exit(1)

    # --incident expands to --target + --safe-refs for each target in the
    # incident. Some incidents affect multiple actions (e.g. trivy-2026
    # affected both trivy-action AND setup-trivy), so we loop over all
    # targets and combine results.
    if args["incident"]:
        incident = get_incident(args["incident"])
        if incident is None:
            print(f"ERROR: Unknown incident '{args['incident']}'\n", file=sys.stderr)
            print(format_incident_list(), file=sys.stderr)
            sys.exit(1)

        print(f"\n{'='*60}", file=sys.stderr)
        print(f"INCIDENT: {incident.name}", file=sys.stderr)
        print(f"Date: {incident.date} | CVE: {incident.cve or 'N/A'}", file=sys.stderr)
        print(f"\n{incident.description}", file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)

        # Run a targeted scan for each affected action in the incident
        for target_info in incident.targets:
            target = f"{target_info['owner']}/{target_info['repo']}"
            safe_refs = target_info.get("safe_refs", set())

            # Merge any user-provided --safe-refs with incident's safe refs
            if args["safe_refs"]:
                safe_refs = safe_refs | args["safe_refs"]

            print(f"--- Scanning for {target} (safe refs: {', '.join(safe_refs) or 'none'}) ---\n", file=sys.stderr)

            if args["mode"] == "org":
                scan_org(client, args["org"], target=target, safe_refs=safe_refs,
                         output_json=args["json"], html_file=args["html"])
            elif args["mode"] == "single":
                scan_single(client, args["owner"], args["repo"], target=target,
                            safe_refs=safe_refs,
                            output_json=args["json"], html_file=args["html"])
    else:
        if args["mode"] == "org":
            scan_org(client, args["org"], target=args["target"], safe_refs=args["safe_refs"] or None,
                     output_json=args["json"], html_file=args["html"])
        elif args["mode"] == "single":
            scan_single(client, args["owner"], args["repo"], target=args["target"],
                        safe_refs=args["safe_refs"] or None,
                        output_json=args["json"], html_file=args["html"])

    print(f"\nRequests remaining this hour: {client.rate_limit_remaining}", file=sys.stderr)

if __name__ == '__main__':
    main()