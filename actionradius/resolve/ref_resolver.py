from typing import Optional
from actionradius.github_client import GitHubClient
from actionradius.models import UsesRef, ResolvedRef

# Process-lifetime cache, keyed by (owner, repo, ref). Intentionally never
# expires or gets invalidated within a run.
#
# Design assumption: ActionRadius is a short-lived CLI process — one `scan`
# invocation resolves each ref at most once, at effectively a single point
# in time, so a mutable ref (a tag/branch) can't meaningfully change out
# from under a scan while it's running. Caching within that window is a
# pure win (fewer GitHub API calls, no correctness cost).
#
# This assumption breaks if ActionRadius is ever run as a long-lived
# process reused across scans separated by real wall-clock time (e.g. a
# daemon/server mode) — a tag re-pointed between two such scans would
# still resolve to its first-seen (now stale) SHA for the rest of the
# process's life. There's no such mode today, so no TTL/invalidation logic
# has been added speculatively; if one is built, this cache is the first
# thing to revisit.
_RESOLUTION_CACHE = {}

def resolve_mutable_ref(client: GitHubClient, uses: UsesRef) -> ResolvedRef:
    """
    Resolves a mutable ref (like 'v1' or 'main') to its current 40-character SHA.
    Checks tags first, then branches. Caches results to save API rate limits.
    """
    is_mutable = uses.ref_type in ("mutable_ref", "tag", "branch", "docker")
    
    if uses.ref_type == "sha":
        is_orphan = False
        if uses.owner and uses.repo:
            try:
                # Compare default branch (HEAD) against the SHA.
                # If the status is 'diverged' or 'ahead', the commit is NOT in the
                # history of the default branch (it's either a side branch or an orphan).
                data = client._get(f"/repos/{uses.owner}/{uses.repo}/compare/HEAD...{uses.ref}")
                if data.get("status") in ["diverged", "ahead"]:
                    is_orphan = True
            except Exception:
                pass # e.g. 404 if commit doesn't exist or HEAD is invalid

        return ResolvedRef(uses=uses, current_sha=uses.ref, is_mutable=False, is_orphan=is_orphan)
        
    if not is_mutable or not uses.owner or not uses.repo or not uses.ref:
        return ResolvedRef(uses=uses, current_sha=None, is_mutable=is_mutable)

    cache_key = (uses.owner, uses.repo, uses.ref)
    if cache_key in _RESOLUTION_CACHE:
        return ResolvedRef(uses=uses, current_sha=_RESOLUTION_CACHE[cache_key], is_mutable=is_mutable)

    try:
        data = client._get(f"/repos/{uses.owner}/{uses.repo}/git/ref/tags/{uses.ref}")
        if "object" in data and "sha" in data["object"]:
            sha = data["object"]["sha"]
            
            if data["object"].get("type") == "tag":
                # Dereference the annotated tag to get the commit SHA
                try:
                    tag_data = client._get(f"/repos/{uses.owner}/{uses.repo}/git/tags/{sha}")
                    if "object" in tag_data and "sha" in tag_data["object"]:
                        sha = tag_data["object"]["sha"]
                except Exception:
                    pass # Keep the original sha if dereferencing fails

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
