import os
import requests
from typing import Optional

# In-memory cache: {(owner, repo, ref): "sha"}
_RESOLUTION_CACHE = {}

def resolve_mutable_ref(owner: str, repo: str, ref: str) -> Optional[str]:
    """
    Resolves a mutable ref (like 'v1' or 'main') to its current 40-character SHA.
    Checks tags first, then branches. Caches results to save API rate limits.
    """
    cache_key = (owner, repo, ref)
    if cache_key in _RESOLUTION_CACHE:
        return _RESOLUTION_CACHE[cache_key]

    token = os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # 1. Try to resolve as a tag
    tag_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{ref}"
    resp = requests.get(tag_url, headers=headers)
    
    if resp.status_code == 200:
        data = resp.json()
        if "object" in data and "sha" in data["object"]:
            sha = data["object"]["sha"]
            _RESOLUTION_CACHE[cache_key] = sha
            return sha
            
    # 2. Try to resolve as a branch (head)
    branch_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{ref}"
    resp = requests.get(branch_url, headers=headers)
    
    if resp.status_code == 200:
        data = resp.json()
        if "object" in data and "sha" in data["object"]:
            sha = data["object"]["sha"]
            _RESOLUTION_CACHE[cache_key] = sha
            return sha

    # 3. Not found (or error)
    _RESOLUTION_CACHE[cache_key] = None
    return None