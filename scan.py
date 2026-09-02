import sys
import os
from dotenv import load_dotenv
from actionradius.github_client import GitHubClient
from actionradius.inventory import inventory_repo
from actionradius.context import analyze_context
from actionradius.scoring import calculate_risk_score
from actionradius.ref_resolver import resolve_mutable_ref

def main():
    load_dotenv()
    if len(sys.argv) != 3:
        print("Usage: python scan.py <owner> <repo>")
        sys.exit(1)

    owner, repo = sys.argv[1], sys.argv[2]
    client = GitHubClient(os.getenv("GITHUB_TOKEN"))
    
    print(f"Scanning {owner}/{repo}...\n")
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
                    "file": wf.path,
                    "site": site,
                    "sha": current_sha,
                    "risk": risk
                })

    print(f"Total uses: sites found: {total_sites}")
    print(f"Mutable (unpinned) sites: {len(findings)}\n")
    
    if findings:
        print("--- PRIORITIZED FINDINGS ---\n")
        # Sort findings by score (highest first)
        findings.sort(key=lambda x: x["risk"]["score"], reverse=True)
        
        for f in findings:
            print(f"[{f['risk']['severity']}] {f['file']} (Job: {f['site'].job_id}) -> {f['site'].uses}")
            print(f"  Resolved SHA: {f['sha']}")
            print(f"  Rationale: {', '.join(f['risk']['rationale'])}\n")
        
    print(f"Requests remaining this hour: {client.rate_limit_remaining}")

if __name__ == '__main__':
    main()