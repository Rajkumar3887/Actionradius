"""Async prefetch orchestrator for concurrent repo scanning."""

import asyncio
from actionradius.models import RepoRef


async def _fetch_one(client, repo: RepoRef, semaphore: asyncio.Semaphore) -> tuple[RepoRef, dict[str, str] | None]:
    """Fetch workflows for a single repo under semaphore."""
    from actionradius.inventory.async_tree_fetcher import fetch_workflow_contents_async

    async with semaphore:
        try:
            files = await fetch_workflow_contents_async(client, repo.owner, repo.name, repo.default_branch)
            return (repo, files)
        except Exception as e:
            print(f"  WARNING: async fetch failed for {repo.owner}/{repo.name}: {e}")
            return (repo, None)


async def _prefetch(token: str | None, repos: list[RepoRef], concurrency: int) -> dict:
    """Internal async entry point — creates client, gathers, returns results."""
    from actionradius.github_client_async import AsyncGitHubClient, compute_concurrency

    client = AsyncGitHubClient(token=token)

    # Use a lightweight request to calibrate concurrency from rate-limit headers
    try:
        await client._get("/rate_limit")
        actual_concurrency = compute_concurrency(client.rate_limit_remaining)
        concurrency = min(concurrency, actual_concurrency)
    except Exception:
        pass  # Proceed with the user-specified or default concurrency

    semaphore = asyncio.Semaphore(concurrency)
    tasks = [_fetch_one(client, repo, semaphore) for repo in repos]
    results = await asyncio.gather(*tasks)
    await client.close()

    return {repo.owner + "/" + repo.name: files for repo, files in results if files is not None}


def prefetch_all_workflows(token: str | None, repos: list[RepoRef], concurrency: int = 10) -> dict:
    """
    Synchronous wrapper for async prefetch — called from CLI.

    Returns {"owner/repo": {path: content}} for all repos that succeeded.
    """
    return asyncio.run(_prefetch(token, repos, concurrency))
