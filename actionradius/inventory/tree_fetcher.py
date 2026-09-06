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
    """Returns {path: content_string} for all workflows in the repo.

    A single problematic file (non-UTF8 content, missing/None `content`
    field — e.g. GitHub's Contents API omits `content` for files over 1MB —
    or any other per-file fetch error) is skipped rather than aborting the
    whole repo: the outer scan loop only catches exceptions per-repo, so
    letting one bad file propagate here would silently drop every finding
    for that repo instead of just that one file. This mirrors the existing,
    already-tested behavior in async_tree_fetcher.py's `_fetch_file`.
    """
    paths = find_workflow_paths(client, owner, repo, branch)
    files = {}
    for path in paths:
        try:
            data = client._get(f"/repos/{owner}/{repo}/contents/{path}", params={"ref": branch})
            files[path] = base64.b64decode(data["content"]).decode("utf-8")
        except Exception as e:
            print(f"  WARNING: Failed to fetch {owner}/{repo}:{path}: {e}")
    return files
