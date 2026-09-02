from actionradius.github_client import GitHubClient
from actionradius.models import RepoRef

def get_org_repos(client: GitHubClient, org: str, include_forks: bool = False, include_archived: bool = False) -> list[RepoRef]:
    """
    List every repo in an org — paginated, since GitHub caps each page at
    100. Converts them to RepoRef models.
    """
    repos_data = []
    page = 1
    endpoint = f"/orgs/{org}/repos"
    
    # Try org first, fallback to user if 404
    try:
        client._get(endpoint, params={"per_page": 1})
    except ValueError:
        endpoint = f"/users/{org}/repos"

    while True:
        batch = client._get(endpoint, params={"per_page": 100, "page": page})
        repos_data.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    if not include_forks:
        repos_data = [r for r in repos_data if not r.get("fork", False)]
    if not include_archived:
        repos_data = [r for r in repos_data if not r.get("archived", False)]

    refs = []
    for r in repos_data:
        refs.append(RepoRef(
            owner=r["owner"]["login"],
            name=r["name"],
            default_branch=r["default_branch"],
            is_private=r.get("private", False)
        ))
    return refs

def get_repo(client: GitHubClient, owner: str, repo: str) -> RepoRef:
    """Basic repo info for a single repo."""
    r = client._get(f"/repos/{owner}/{repo}")
    return RepoRef(
        owner=r["owner"]["login"],
        name=r["name"],
        default_branch=r["default_branch"],
        is_private=r.get("private", False)
    )
