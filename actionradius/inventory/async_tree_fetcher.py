"""Async workflow-content fetcher — mirrors tree_fetcher.py for concurrent use."""

import base64


async def fetch_workflow_contents_async(client, owner: str, repo: str, branch: str) -> dict[str, str]:
    """Async version of fetch_workflow_contents."""
    from actionradius.inventory.tree_fetcher import is_workflow_path

    data = await client._get(f"/repos/{owner}/{repo}/git/trees/{branch}", params={"recursive": "1"})
    if data.get("truncated"):
        print(f"  WARNING: tree for {owner}/{repo} was truncated by GitHub's API")

    tree = data.get("tree", [])
    paths = [item["path"] for item in tree if item["type"] == "blob" and is_workflow_path(item["path"])]

    files = {}
    for path in paths:
        file_data = await client._get(f"/repos/{owner}/{repo}/contents/{path}", params={"ref": branch})
        files[path] = base64.b64decode(file_data["content"]).decode("utf-8")

    return files
