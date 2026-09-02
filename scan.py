import sys
import os
from dotenv import load_dotenv
from actionradius.github_client import GitHubClient
from actionradius.inventory import inventory_repo
from actionradius.context import analyze_context
from actionradius.scoring import calculate_risk_score
from actionradius.ref_resolver import resolve_mutable_ref

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


def scan_single(client, owner, repo):
    print(f"Scanning {owner}/{repo}...\n")
    total_sites, findings = scan_repo(client, owner, repo)

    print(f"Total uses: sites found: {total_sites}")
    print(f"Mutable (unpinned) sites: {len(findings)}\n")

    if findings:
        print("--- PRIORITIZED FINDINGS ---\n")
        print_findings(findings, show_repo=False)


def scan_org(client, org):
    print(f"Scanning org: {org}...\n")
    repos = client.get_org_repos(org)  # forks/archived excluded by default
    print(f"Found {len(repos)} repo(s) to scan (forks/archived excluded)\n")

    total_sites_all = 0
    all_findings = []

    for i, repo_info in enumerate(repos, start=1):
        repo_name = repo_info["name"]
        print(f"[{i}/{len(repos)}] Scanning {org}/{repo_name}...")
        try:
            total_sites, findings = scan_repo(client, org, repo_name)
        except Exception as e:
            # One repo failing (empty repo, disabled workflows API, etc.)
            # shouldn't kill an org-wide scan — flag it and move on.
            print(f"  WARNING: couldn't scan {org}/{repo_name}: {e}")
            continue

        total_sites_all += total_sites
        all_findings.extend(findings)

    print(f"\n=== ORG-WIDE SUMMARY: {org} ===")
    print(f"Repos scanned: {len(repos)}")
    print(f"Total uses: sites found: {total_sites_all}")
    print(f"Mutable (unpinned) sites: {len(all_findings)}\n")

    if all_findings:
        print("--- PRIORITIZED FINDINGS (org-wide) ---\n")
        print_findings(all_findings, show_repo=True)


def main():
    load_dotenv()
    client = GitHubClient(os.getenv("GITHUB_TOKEN"))

    if len(sys.argv) == 3 and sys.argv[1] == "--org":
        scan_org(client, sys.argv[2])
    elif len(sys.argv) == 3:
        scan_single(client, sys.argv[1], sys.argv[2])
    else:
        print("Usage:")
        print("  python scan.py <owner> <repo>   # scan a single repo")
        print("  python scan.py --org <org>      # scan every repo in an org")
        sys.exit(1)

    print(f"\nRequests remaining this hour: {client.rate_limit_remaining}")

if __name__ == '__main__':
    main()