from actionradius.models import UsesSite, ResolvedRef, CompromiseStatus
from actionradius.github_client import GitHubClient


def is_match(site: UsesSite, target_action: str) -> bool:
    """
    Checks if a given uses site points to the target action.
    target_action format: "owner/repo" (e.g. "aquasecurity/trivy-action")
    """
    if not site.uses.owner or not site.uses.repo:
        return False

    full_target = f"{site.uses.owner}/{site.uses.repo}".lower()
    return full_target == target_action.lower()


def is_compromised(resolved: ResolvedRef, safe_refs: list[str]) -> bool:
    """
    Legacy safe-ref allowlist mode.
    If it's in the safe_refs, it's not compromised.
    Otherwise, if it's mutable or an unknown SHA, it's considered compromised.
    """
    if not safe_refs:
        return True  # Without safe refs, anything matching the target is flagged

    # Check if the exact current SHA or short ref matches a safe ref
    if resolved.current_sha and resolved.current_sha in safe_refs:
        return False

    if resolved.uses.ref and resolved.uses.ref in safe_refs:
        return False

    # Check prefixes for short SHAs
    for safe_ref in safe_refs:
        if resolved.current_sha and resolved.current_sha.startswith(safe_ref):
            return False
        if resolved.uses.ref and resolved.uses.ref.startswith(safe_ref):
            return False
        if resolved.current_sha and safe_ref.startswith(resolved.current_sha):
            return False

    return True


def is_in_bad_range(
    client: GitHubClient,
    resolved: ResolvedRef,
    bad_from: str,
    bad_to: str,
) -> CompromiseStatus:
    """
    Check if the resolved SHA falls within a known-bad commit range
    using the GitHub Compare API.

    Returns:
        "COMPROMISED" — SHA is inside the bad window [bad_from, bad_to]
        "SAFE"        — SHA is provably outside the bad window
        "UNKNOWN"     — cannot determine (API error, unresolvable ref)
    """
    sha = resolved.current_sha
    if not sha:
        return "UNKNOWN"  # Can't resolve → honestly report unknown

    owner = resolved.uses.owner
    repo = resolved.uses.repo
    if not owner or not repo:
        return "UNKNOWN"

    try:
        # Is the SHA at or after the bad commit was introduced?
        cmp_intro = client._get(f"/repos/{owner}/{repo}/compare/{bad_from}...{sha}")
        intro_status = cmp_intro.get("status", "")
        # 'ahead' = sha is after introduced, 'identical' = sha IS the introduced commit
        if intro_status not in ("ahead", "identical"):
            return "SAFE"  # SHA is before the bad range

        # Is the SHA at or before the fix?
        cmp_fix = client._get(f"/repos/{owner}/{repo}/compare/{sha}...{bad_to}")
        fix_status = cmp_fix.get("status", "")
        # 'ahead' = fix is after sha, 'identical' = sha IS the fix commit
        if fix_status in ("ahead", "identical"):
            return "COMPROMISED"  # SHA is inside the bad window

        return "SAFE"  # SHA is after the fix

    except Exception:
        # API error → honestly report unknown rather than guessing
        return "UNKNOWN"


def determine_compromise_status(
    client: GitHubClient | None,
    resolved: ResolvedRef,
    safe_refs: list[str],
    bad_range: dict | None,
) -> CompromiseStatus:
    """
    Unified entry point that picks the right matching strategy.

    - bad_range mode: uses GitHub Compare API for precise range checking
    - safe_refs mode: uses allowlist (legacy), maps bool to CompromiseStatus
    - neither provided: returns UNKNOWN
    """
    if bad_range and client:
        return is_in_bad_range(
            client, resolved,
            bad_range["introduced"],
            bad_range["fixed"],
        )

    if safe_refs:
        compromised = is_compromised(resolved, safe_refs)
        return "COMPROMISED" if compromised else "SAFE"

    # No matching criteria provided — cannot determine
    return "UNKNOWN"
