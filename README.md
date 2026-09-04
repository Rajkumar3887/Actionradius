ActionRadius 💥
Fleet-wide exposure analysis for compromised GitHub Actions dependencies.
The Problem
On March 19, 2026, attackers hijacked 75 of 76 version tags on aquasecurity/trivy-action — a security scanner used in thousands of CI pipelines — and used it to steal cloud credentials from downstream workflows. They also swapped a SHA pin in Trivy's own release workflow to point at an orphan commit in actions/checkout, leaving the # v6.0.2 comment intact so reviewers wouldn't notice.
If you were a security lead that morning, your first question wasn't "is our workflow YAML well-written" (zizmor/poutine answer that). It was:
"Which of our repos actually pull this action, at what pin, triggered by what, with access to what secrets — right now?"
Nobody's tooling answered that question in an hour. ActionRadius does.
How It Works
ActionRadius connects directly to the GitHub API, inventories your entire organization's workflow files in seconds via the Git Trees API, resolves every mutable tag to its live SHA, evaluates the contextual risk (secrets, permissions, triggers), and outputs a ranked incident-response report with tri-state compromise classification: COMPROMISED, SAFE, or UNKNOWN.
Features
Feature
What it does
Zero-Setup Inventory
Git Trees API (?recursive=1) pulls workflows across hundreds of repos without hitting Code Search rate limits
Live Ref Resolution
Resolves mutable tags (@v4) to their exact 40-char SHAs in real-time
Compromised Range Matching
--bad-from / --bad-to checks if a resolved SHA falls inside a known-bad commit window via the Compare API
Tri-State Classification
Every finding is COMPROMISED, SAFE, or UNKNOWN — never silently treated as safe
Orphan Commit Detection
Flags hidden SHAs not on any branch (the exact technique from the Trivy binary attack)
Docker Action Support
Fully parses uses: docker:// references and correctly scores mutable Docker tags
SHA/Comment Mismatch
Detects when @SHA # v6.0.2 claims a version tag the SHA doesn't actually match
Context-Aware Scoring
Evaluates triggers, permissions, secrets, and runner type alongside compromise status
Curated Incident Feed
--target-feed scans your org against every known-compromised action in one pass
IOC Hunting
Searches run: blocks for malicious domains (e.g., aquasecurtiy.org)
SARIF / HTML / Graphviz
Multiple report formats including GHAS-compatible SARIF and blast-radius graphs
Why Not Zizmor / Poutine?
Zizmor and Poutine are excellent tools for per-workflow hygiene — flagging pull_request_target with untrusted input, detecting taint in shell expressions, and linting YAML patterns.
ActionRadius solves a different problem: fleet-wide incident response. When trivy-action@0.34.2 was compromised on March 19, zizmor could tell you "this workflow has a risky trigger pattern." It could not tell you:
Which of your 500 repos currently resolve trivy-action@0.34.2 to the poisoned SHA (ddb9da44)
That the actions/checkout SHA pin in your release workflow is an orphan commit with a spoofed version comment (# v6.0.2)
That the workflow leaking your AWS credentials has secrets: inherit + pull_request_target + a self-hosted runner
ActionRadius answers all three. It treats your CI/CD estate as a graph and ranks the blast radius.
Quick Start
git clone https://github.com/Rajkumar3887/Actionradius.git cd Actionradius python -m venv venv source venv/bin/activate # Windows: .\venv\Scripts\activate pip install -e . export GITHUB_TOKEN="your_token_here"
Incident Response Mode (Compromised Range)
# "Which repos are exposed to the Trivy compromise?" actionradius scan \ --org my-org \ --target aquasecurity/trivy-action \ --bad-from ddb9da44 \ --bad-to 76d05ec629db6c6a67e5a1f8a6cbf069d1e4e1de
Curated Feed Mode (All Known Incidents)
# "Show me my org's exposure to EVERY known-compromised action" actionradius scan \ --org my-org \ --target-feed data/compromised_feed.json \ --html report.html
Legacy Safe-Ref Mode
# "Flag everything except this known-good SHA" actionradius scan \ --org my-org \ --target actions/checkout \ --safe-ref 8410ad0602e1e429cee44a835ae97775bbe51671
Drift Mode (CI/CD Scanning)
# "What changed since yesterday's scan?" actionradius diff report-monday.json report-tuesday.json
Outputs NEW findings, RESOLVED findings, and ESCALATED severities.
IOC Hunting
# "Did any workflow pull from the typosquatted C2?" actionradius scan \ --org my-org \ --ioc-search "aquasecurtiy.org"
Ingesting External SARIF (zizmor / poutine)
--external-sarif lets ActionRadius bump the severity of findings that an external linter (zizmor, poutine, or any SARIF-2.1.0-compatible tool) has already flagged, by feeding that SARIF file's results back into ActionRadius's scoring.
Single-repo scans (--repo) always work, regardless of what the SARIF file contains:
zizmor --format sarif .github/workflows > zizmor.sarif actionradius scan \ --repo my-org/my-repo \ --target actions/checkout \ --safe-ref 8410ad0602e1e429cee44a835ae97775bbe51671 \ --external-sarif zizmor.sarif
Organization-wide scans (--org) are different: a SARIF file's results only carry a bare artifact path (e.g. .github/workflows/ci.yml), with no indication of which repository that path came from. Applying those findings blindly across every repo in the org would silently mismatch findings from one repo onto an unrelated repo with a similarly-named workflow file.
To resolve this safely, ActionRadius requires the SARIF file to carry repository identity via the standard [versionControlProvenance](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) property, which zizmor and poutine emit when run against a checked-out git repository (rather than piped from a single file). Each run.versionControlProvenance entry's repositoryUri is mapped to result locations via mappedTo.uriBaseId, letting ActionRadius attribute every finding to an exact owner/repo.
If every result in the SARIF file can be traced back to a repository through versionControlProvenance, ActionRadius loads it as repo-scoped findings and applies each finding only to its own repo.
If the SARIF file is missing versionControlProvenance, or even a single result can't be mapped to a repo through it, ActionRadius refuses to guess: --external-sarif combined with --org (and no --repo) exits with an error rather than risk applying a finding to the wrong repository.
When your SARIF file doesn't have repository identity, run per repository instead:
for repo in repo-a repo-b repo-c; do zizmor --format sarif "$repo/.github/workflows" > "$repo.sarif" actionradius scan --repo "my-org/$repo" --target actions/checkout --external-sarif "$repo.sarif" done
ActionRadius does not attempt to infer repository identity from anything other than versionControlProvenance (e.g. file paths, working-directory conventions, or CI environment variables) — if the tool that produced the SARIF didn't record repo provenance, per-repo scanning is the only supported path for org-wide runs.
Report Output
Each finding answers the incident-response question directly:
[CRITICAL] [COMPROMISED] my-org/payment-api:.github/workflows/deploy.yml -> aquasecurity/trivy-action@0.34.2 Resolved SHA: ddb9da44... Pin type: mutable_ref Rationale: Mutable pin exposed to compromised commit (+3), Fork-reachable trigger (+3), Inherited secrets (+3)
HTML reports split findings into three sections:
🚨 Currently Compromised — action resolves to a known-bad SHA right now
⚠️ Unknown — cannot confirm safe (API error, unresolvable ref)
✅ Safe — provably outside the compromised range
Scoring Model
All weights are configurable via data/weights.yaml:
Signal
Default Weight
Rationale
Orphan commit SHA
+8.0
Hidden commit not on any branch — strong attack indicator
SHA pinned to compromised commit
+8.0
Directly executing known-bad code
Mutable pin + compromised
+3.0
Tag/branch currently points at bad commit
Unknown compromise status
+4.0
Cannot confirm safe — don't assume it is
Fork-reachable trigger
+3.0
pull_request_target, workflow_run from forks
secrets: inherit
+3.0
All org secrets available to the action
Explicit secrets
+2.0
Named secrets (AWS_KEY, NPM_TOKEN, etc.)
Self-hosted runner
+2.0
Persistent infrastructure access
Score → severity: 0-1 info, 2-4 medium, 5-7 high, 8+ critical.
License
MIT — see [LICENSE](https://claude.ai/chat/LICENSE).
