"""Async workflow-content fetcher — mirrors tree_fetcher.py for concurrent use."""

import base64

import asyncio

async def fetch_workflow_contents_async(client, owner: str, repo: str, branch: str, semaphore: asyncio.Semaphore | None = None) -> dict[str, str]:
    """Async version of fetch_workflow_contents with request-level concurrency."""
    from actionradius.inventory.tree_fetcher import is_workflow_path

    async def _do_get(path, params):
        if semaphore:
            async with semaphore:
                return await client._get(path, params=params)
        return await client._get(path, params=params)

    data = await _do_get(f"/repos/{owner}/{repo}/git/trees/{branch}", params={"recursive": "1"})
    if data.get("truncated"):
        print(f"  WARNING: tree for {owner}/{repo} was truncated by GitHub's API")

    tree = data.get("tree", [])
    paths = [item["path"] for item in tree if item["type"] == "blob" and is_workflow_path(item["path"])]

    async def _fetch_file(path: str) -> tuple[str, str | None]:
        try:
            file_data = await _do_get(f"/repos/{owner}/{repo}/contents/{path}", params={"ref": branch})
            return path, base64.b64decode(file_data["content"]).decode("utf-8")
        except Exception as e:
            print(f"  WARNING: Failed to fetch {owner}/{repo}:{path}: {e}")
            return path, None

    results = await asyncio.gather(*[_fetch_file(p) for p in paths], return_exceptions=True)
    
    files = {}
    for res in results:
        if isinstance(res, tuple) and res[1] is not None:
            files[res[0]] = res[1]

    return files
