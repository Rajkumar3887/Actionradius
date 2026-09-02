import base64
from actionradius.github_client import GitHubClient

def is_workflow_path(path: str) -> bool:
    return path.startswith(".github/workflows/") and (path.endswith(".yml") or path.endswith(".yaml"))

def find_workflow_paths(client: GitHubClient, owner: str, repo: str, branch: str) -> list[str]:
    data = client._get(f"/repos/{owner}/{repo}/git/trees/{branch}", params={"recursive": "1"})
    if data.get("truncated"):
        print(f"  WARNING: tree for {owner}/{repo} was truncated by GitHub's API")
    tree = data.get("tree", [])
    
    return [item["path"] for item in tree if item["type"] == "blob" and is_workflow_path(item["path"])]

def fetch_workflow_contents(client: GitHubClient, owner: str, repo: str, branch: str) -> dict[str, str]:
    """Returns {path: content_string} for all workflows in the repo."""
    paths = find_workflow_paths(client, owner, repo, branch)
    files = {}
    for path in paths:
        data = client._get(f"/repos/{owner}/{repo}/contents/{path}", params={"ref": branch})
        files[path] = base64.b64decode(data["content"]).decode("utf-8")
    return files
