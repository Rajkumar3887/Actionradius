"""
matcher.py

The core differentiator of ActionRadius: given a specific compromised
action (e.g. "aquasecurity/trivy-action"), find every site across the
scanned inventory that references it, and classify each one as EXPOSED,
SAFE, or PINNED_UNKNOWN.

THIS IS THE QUESTION NO OTHER TOOL ANSWERS.

Existing tools (zizmor, poutine, runner-guard, Cortex Cloud) all answer
"does this workflow file have risky patterns." They answer a per-file
hygiene question. The matcher answers a fleet-wide, dependency-driven,
incident-specific question:

    "Given THIS specific compromised action, which repos in our org
     are actually exposed to it right now?"

That's a fundamentally different data shape. During the Trivy incident,
defenders couldn't answer this question quickly — they had to manually
grep across hundreds of repos. This module automates that triage.

HOW IT WORKS:
  1. Takes the full inventory (list of ParsedWorkflows with all uses_sites)
  2. Filters to only sites referencing the target action
  3. Classifies each match:
     - EXPOSED: mutable pin (tag/branch) — attacker could have swapped it
     - SAFE: pinned to a SHA in the known-safe set
     - PINNED_UNKNOWN: pinned to a SHA, but not in the safe set
       (might be fine, might be the compromised commit — needs manual check)

USAGE IN AN INCIDENT:
  # "trivy-action was compromised! Who's exposed?"
  python scan.py --org my-company --target aquasecurity/trivy-action

  # "Aqua published safe SHAs — update the triage"
  python scan.py --org my-company --target aquasecurity/trivy-action \\
      --safe-refs 57a97c7
"""

from dataclasses import dataclass, field
from typing import Optional
from actionradius.workflow_parser import ParsedWorkflow, UsesSite


# The three possible states during incident triage
EXPOSED = "EXPOSED"            # mutable pin — assume compromised until proven otherwise
SAFE = "SAFE"                  # pinned to known-safe SHA
PINNED_UNKNOWN = "PINNED_UNKNOWN"  # pinned to SHA, but is it safe or bad? needs checking


@dataclass
class MatchResult:
    """One site that references the target action, with its triage status."""
    owner: str                    # owner of the SCANNED repo (not the action)
    repo: str                     # name of the SCANNED repo
    workflow_path: str            # path to the workflow file
    job_id: str
    step_index: Optional[int]
    raw_uses: str                 # the original uses: string
    ref: Optional[str]            # the @ref part (tag, SHA, branch)
    ref_type: str                 # "mutable_ref", "sha", "local", "unresolvable"
    is_full_sha: bool
    status: str                   # EXPOSED, SAFE, or PINNED_UNKNOWN
    source_chain: list[str] = field(default_factory=list)
    resolved_sha: Optional[str] = None  # filled in later by the scan pipeline


def match_target(
    workflows: list[ParsedWorkflow],
    target_owner: str,
    target_repo: str,
    scanned_owner: str,
    scanned_repo: str,
    safe_refs: set[str] | None = None,
) -> list[MatchResult]:
    """
    Given parsed workflows from a single repo, find every uses_site that
    references the target action and classify it.

    Args:
        workflows: parsed workflows from inventory_repo()
        target_owner: owner of the action to search for (e.g. "aquasecurity")
        target_repo: repo name of the action (e.g. "trivy-action")
        scanned_owner: owner of the repo being scanned
        scanned_repo: name of the repo being scanned
        safe_refs: optional set of known-safe SHAs (can be short or full).
                   If provided, SHA-pinned sites matching these are marked SAFE.

    Returns:
        List of MatchResult objects, one per matching site.
    """
    safe_refs = safe_refs or set()
    # Normalize safe refs to lowercase for comparison
    safe_refs_lower = {r.lower() for r in safe_refs}

    results: list[MatchResult] = []

    for wf in workflows:
        for site in wf.uses_sites:
            # Skip sites that don't reference the target action.
            # Compare case-insensitively — GitHub org/repo names are
            # case-insensitive in practice.
            if not _matches_target(site, target_owner, target_repo):
                continue

            status = _classify(site, safe_refs_lower)

            results.append(MatchResult(
                owner=scanned_owner,
                repo=scanned_repo,
                workflow_path=wf.path,
                job_id=site.job_id,
                step_index=site.step_index,
                raw_uses=site.uses.raw,
                ref=site.uses.ref,
                ref_type=site.uses.ref_type,
                is_full_sha=site.uses.is_full_sha,
                status=status,
                source_chain=list(site.source_chain),
            ))

    return results


def _matches_target(site: UsesSite, target_owner: str, target_repo: str) -> bool:
    """Does this uses_site reference the target action?"""
    if site.uses.owner is None or site.uses.repo is None:
        return False
    return (
        site.uses.owner.lower() == target_owner.lower()
        and site.uses.repo.lower() == target_repo.lower()
    )


def _classify(site: UsesSite, safe_refs_lower: set[str]) -> str:
    """
    Classify a matching site's exposure status.

    The logic mirrors how a human incident responder would triage:
    1. Mutable pin (tag/branch)? → EXPOSED until you rotate it.
    2. SHA pin matching a known-safe ref? → SAFE, no action needed.
    3. SHA pin but not in the safe list? → PINNED_UNKNOWN, needs checking.
       Could be the compromised commit, could be a version we haven't
       verified yet. Don't ignore it, don't panic about it.
    4. Unresolvable (dynamic expression)? → EXPOSED, conservatively.
       We can't tell what it resolves to at runtime, so assume the worst.
    5. Local? → shouldn't match a third-party target, but if it somehow
       does, it's not exposed to a supply chain attack.
    """
    if site.uses.ref_type == "mutable_ref":
        return EXPOSED

    if site.uses.ref_type == "sha":
        ref_lower = site.uses.ref.lower() if site.uses.ref else ""

        # Check exact match first (covers both full and short SHAs)
        if ref_lower in safe_refs_lower:
            return SAFE

        # Check prefix match: a short SHA in the workflow might match
        # a full SHA in the safe list, or vice versa. This is important
        # because advisories often publish full SHAs but repos pin with
        # short ones (like trivy-action@57a97c7).
        for safe in safe_refs_lower:
            if safe.startswith(ref_lower) or ref_lower.startswith(safe):
                return SAFE

        return PINNED_UNKNOWN

    if site.uses.ref_type == "unresolvable":
        # Dynamic expression like @${{ inputs.ref }} — we can't tell
        # what it resolves to at runtime. Conservative: assume exposed.
        return EXPOSED

    # "local" shouldn't match a third-party target, but defensively:
    return SAFE


def format_match_summary(
    results: list[MatchResult],
    target: str,
) -> str:
    """
    Formats the match results into a human-readable incident triage summary.

    Structured the way an IR lead reads it: exposed count first (what to
    fix NOW), then unknown (what to verify), then safe (what to ignore).
    """
    exposed = [r for r in results if r.status == EXPOSED]
    unknown = [r for r in results if r.status == PINNED_UNKNOWN]
    safe = [r for r in results if r.status == SAFE]

    lines = []
    lines.append(f"=== INCIDENT TRIAGE: {target} ===\n")
    lines.append(f"Total sites referencing {target}: {len(results)}")
    lines.append(f"  🔴 EXPOSED (mutable pin):    {len(exposed)}")
    lines.append(f"  🟡 PINNED_UNKNOWN:           {len(unknown)}")
    lines.append(f"  🟢 SAFE (known-good pin):    {len(safe)}")
    lines.append("")

    if exposed:
        lines.append("--- EXPOSED: Fix these NOW ---\n")
        for r in exposed:
            repo_prefix = f"{r.owner}/{r.repo} " if r.owner else ""
            lines.append(f"  {repo_prefix}{r.workflow_path} (Job: {r.job_id})")
            lines.append(f"    uses: {r.raw_uses}")
            if r.source_chain:
                lines.append(f"    Found via: {' -> '.join(r.source_chain)}")
            if r.resolved_sha:
                lines.append(f"    Currently resolves to: {r.resolved_sha}")
            lines.append(f"    Action: Pin to a known-safe SHA immediately.\n")

    if unknown:
        lines.append("--- PINNED_UNKNOWN: Verify these ---\n")
        for r in unknown:
            repo_prefix = f"{r.owner}/{r.repo} " if r.owner else ""
            lines.append(f"  {repo_prefix}{r.workflow_path} (Job: {r.job_id})")
            lines.append(f"    uses: {r.raw_uses}")
            if r.source_chain:
                lines.append(f"    Found via: {' -> '.join(r.source_chain)}")
            lines.append(f"    Pinned to: {r.ref} ({'full SHA' if r.is_full_sha else 'short SHA'})")
            lines.append(f"    Action: Verify this SHA is not a compromised commit.\n")

    if safe:
        lines.append("--- SAFE: No action needed ---\n")
        for r in safe:
            repo_prefix = f"{r.owner}/{r.repo} " if r.owner else ""
            lines.append(f"  {repo_prefix}{r.workflow_path} (Job: {r.job_id})")
            lines.append(f"    uses: {r.raw_uses}")
            lines.append(f"    Pinned to known-safe ref: {r.ref}\n")

    return "\n".join(lines)
