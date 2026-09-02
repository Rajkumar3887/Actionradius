"""
recursion.py

Follows reusable workflow calls to discover transitive action dependencies.

THE PROBLEM THIS SOLVES:
  If your workflow does `uses: my-org/shared/.github/workflows/deploy.yml@v1`,
  we currently record that one call and stop. But deploy.yml might internally
  call `uses: actions/checkout@v4` — and if checkout gets compromised, your
  repo is exposed through that transitive dependency. This module follows
  those hops so we can see the full picture.

HOW IT WORKS:
  For each UsesSite where `is_reusable_workflow == True`, we:
  1. Fetch that workflow file from the referenced repo via the GitHub API
  2. Parse it with the same workflow_parser we use for everything else
  3. Add its uses_sites to our results, tagged with a source_chain so
     the report shows WHERE we found each transitive dependency

SAFETY LIMITS:
  - max_depth (default 2): don't follow chains deeper than this
  - visited set: prevent infinite loops if A calls B calls A
  - individual fetch failures are warned and skipped, never fatal

WHY THIS LIVES IN ITS OWN MODULE:
  inventory.py is deliberately split into pure-logic and thin-network layers.
  Recursion is inherently a network operation (we fetch files from OTHER
  repos), so it doesn't belong in the pure-logic layer. Keeping it separate
  also makes it easy to disable/cap if it causes scope creep — you can
  just not call it.
"""

from actionradius.github_client import GitHubClient
from actionradius.workflow_parser import ParsedWorkflow, UsesSite, parse_workflow_yaml


def resolve_reusable_workflows(
    client: GitHubClient,
    workflows: list[ParsedWorkflow],
    max_depth: int = 2,
) -> list[ParsedWorkflow]:
    """
    Takes the already-parsed workflows from a repo and follows any
    reusable workflow calls up to `max_depth` levels deep.

    Returns the SAME list of ParsedWorkflow objects, but with transitive
    UsesSites appended (each carrying a source_chain showing provenance).

    The original UsesSite for the reusable workflow call is KEPT — it's
    still a real dependency that matters for pinning analysis. We ADD
    the transitive sites alongside it, we don't replace it.
    """
    # Track what we've already fetched to avoid cycles and redundant work.
    # Key: (owner, repo, path, ref) of the reusable workflow file.
    visited: set[tuple[str, str, str, str]] = set()

    for wf in workflows:
        # Collect transitive sites separately, then extend — don't modify
        # the list we're iterating over.
        transitive_sites: list[UsesSite] = []

        for site in wf.uses_sites:
            if site.uses.is_reusable_workflow and site.uses.ref_type != "local":
                _follow_reusable(
                    client=client,
                    ref=site.uses,
                    source_chain=[site.uses.raw],
                    depth=1,
                    max_depth=max_depth,
                    visited=visited,
                    out=transitive_sites,
                )

        wf.uses_sites.extend(transitive_sites)

    return workflows


def _follow_reusable(
    client: GitHubClient,
    ref,  # UsesRef — the reusable workflow reference to follow
    source_chain: list[str],
    depth: int,
    max_depth: int,
    visited: set[tuple[str, str, str, str]],
    out: list[UsesSite],
) -> None:
    """
    Recursively follows a single reusable workflow call.

    Fetches the workflow file from the referenced repo, parses it, and
    adds all its uses_sites to `out` with the appropriate source_chain.
    If any of THOSE sites are themselves reusable workflow calls, recurse
    (up to max_depth).
    """
    # Safety: don't go deeper than max_depth
    if depth > max_depth:
        return

    # Need owner, repo, path, and ref to fetch the file
    if not all([ref.owner, ref.repo, ref.path, ref.ref]):
        return

    visit_key = (ref.owner, ref.repo, ref.path, ref.ref)
    if visit_key in visited:
        return  # already followed this exact workflow — cycle or duplicate
    visited.add(visit_key)

    # Fetch and parse the reusable workflow file from the referenced repo.
    # This is a cross-repo fetch — we're reading a file from ANOTHER repo,
    # not the one being scanned. That's the whole point: the dependency
    # lives in a different repository.
    try:
        yaml_text = client.get_file_content(
            ref.owner, ref.repo, ref.path, ref=ref.ref
        )
        parsed = parse_workflow_yaml(
            f"{ref.owner}/{ref.repo}/{ref.path}",  # synthetic path for reporting
            yaml_text,
        )
    except Exception as e:
        # Cross-repo fetch failures are expected — private repos, deleted
        # files, rate limits. Warn and continue, never crash the scan.
        print(f"  WARNING: couldn't follow reusable workflow {ref.raw}: {e}")
        return

    # Add every uses_site from the reusable workflow to our output,
    # tagged with the chain of calls that led us here.
    for site in parsed.uses_sites:
        transitive_site = UsesSite(
            job_id=site.job_id,
            step_index=site.step_index,
            uses=site.uses,
            source_chain=list(source_chain),  # copy to avoid mutation
        )
        out.append(transitive_site)

        # If this transitive site is ITSELF a reusable workflow call,
        # follow it too (up to max_depth).
        if site.uses.is_reusable_workflow and site.uses.ref_type != "local":
            _follow_reusable(
                client=client,
                ref=site.uses,
                source_chain=source_chain + [site.uses.raw],
                depth=depth + 1,
                max_depth=max_depth,
                visited=visited,
                out=out,
            )
