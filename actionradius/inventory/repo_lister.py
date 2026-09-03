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


def check_exfil_repos(client: GitHubClient, org: str) -> list[str]:
    """
    Search org members for 'tpcp-docs' repos — a sign of successful
    TeamPCP credential exfiltration from the March 2026 Trivy incident.

    The attack's fallback exfil path creates a public repo named 'tpcp-docs'
    on the victim's GitHub account and uploads stolen secrets as release assets.
    """
    hits = []

    try:
        members = []
        page = 1
        while True:
            chunk = client._get(f"/orgs/{org}/members", params={"per_page": 100, "page": page})
            if not chunk:
                break
            members.extend(chunk)
            if len(chunk) < 100:
                break
            page += 1
    except Exception:
        # Fallback: try checking the org itself
        members = [{"login": org}]

    for m in members:
        login = m.get("login", "")
        try:
            client._get(f"/repos/{login}/tpcp-docs")
            hits.append(login)
        except ValueError:
            pass  # 404 = not found, expected for clean accounts
        except Exception as e:
            print(f"  WARNING: tpcp-docs check failed for {login}: {e}")

    return hits
