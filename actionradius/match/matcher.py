from actionradius.models import UsesSite, ResolvedRef
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
    Determines if the resolved reference is compromised.
    If it's in the safe_refs, it's not compromised.
    Otherwise, if it's mutable or an unknown SHA, it's considered compromised.
    """
    if not safe_refs:
        return True # Without safe refs, anything matching the target is flagged
        
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
    bad_introduced: str,
    bad_fixed: str,
) -> bool:
    """
    Check if the resolved SHA falls within a known-bad commit range.
    
    Uses the GitHub Compare API:
    - Compare introduced...current_sha: if status is 'ahead' or 'identical',
      the SHA was introduced at or after the bad commit.
    - Compare current_sha...fixed: if status is 'behind' or 'identical',
      the SHA is at or before the fix.
    
    If both conditions are true, the SHA is inside the compromised window.
    If either API call fails, we conservatively assume compromised.
    """
    sha = resolved.current_sha
    if not sha:
        return True  # Can't resolve → assume worst case
        
    owner = resolved.uses.owner
    repo = resolved.uses.repo
    if not owner or not repo:
        return True
    
    try:
        # Is the SHA at or after the bad commit was introduced?
        cmp_intro = client._get(f"/repos/{owner}/{repo}/compare/{bad_introduced}...{sha}")
        intro_status = cmp_intro.get("status", "")
        # 'ahead' = sha is after introduced, 'identical' = sha IS the introduced commit
        if intro_status not in ("ahead", "identical"):
            return False  # SHA is before the bad range → safe

        # Is the SHA at or before the fix?
        cmp_fix = client._get(f"/repos/{owner}/{repo}/compare/{sha}...{bad_fixed}")
        fix_status = cmp_fix.get("status", "")
        # 'ahead' = fix is after sha, 'identical' = sha IS the fix commit
        if fix_status in ("ahead", "identical"):
            return True  # SHA is inside the bad window
        
        return False  # SHA is after the fix → safe
        
    except Exception:
        # API error (404, rate limit, etc.) → conservatively flag as compromised
        return True
