from actionradius.models import UsesSite, ResolvedRef

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
