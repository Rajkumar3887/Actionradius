from typing import Optional
from actionradius.github_client import GitHubClient
from actionradius.models import UsesRef, ResolvedRef

_RESOLUTION_CACHE = {}

def resolve_mutable_ref(client: GitHubClient, uses: UsesRef) -> ResolvedRef:
    """
    Resolves a mutable ref (like 'v1' or 'main') to its current 40-character SHA.
    Checks tags first, then branches. Caches results to save API rate limits.
    """
    is_mutable = uses.ref_type in ("mutable_ref", "tag", "branch")
    
    if uses.ref_type == "sha":
        return ResolvedRef(uses=uses, current_sha=uses.ref, is_mutable=False)
        
    if not is_mutable or not uses.owner or not uses.repo or not uses.ref:
        return ResolvedRef(uses=uses, current_sha=None, is_mutable=is_mutable)

    cache_key = (uses.owner, uses.repo, uses.ref)
    if cache_key in _RESOLUTION_CACHE:
        return ResolvedRef(uses=uses, current_sha=_RESOLUTION_CACHE[cache_key], is_mutable=is_mutable)

    try:
        data = client._get(f"/repos/{uses.owner}/{uses.repo}/git/ref/tags/{uses.ref}")
        if "object" in data and "sha" in data["object"]:
            sha = data["object"]["sha"]
            _RESOLUTION_CACHE[cache_key] = sha
            return ResolvedRef(uses=uses, current_sha=sha, is_mutable=is_mutable)
    except ValueError:
        pass # 404 Not Found, expected fallback to branch
        
    try:
        data = client._get(f"/repos/{uses.owner}/{uses.repo}/git/ref/heads/{uses.ref}")
        if "object" in data and "sha" in data["object"]:
            sha = data["object"]["sha"]
            _RESOLUTION_CACHE[cache_key] = sha
            return ResolvedRef(uses=uses, current_sha=sha, is_mutable=is_mutable)
    except ValueError:
        pass

    _RESOLUTION_CACHE[cache_key] = None
    return ResolvedRef(uses=uses, current_sha=None, is_mutable=is_mutable)
