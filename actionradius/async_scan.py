"""Async prefetch orchestrator for concurrent repo scanning."""

import asyncio
from actionradius.models import RepoRef

# Never recalibrate concurrency below this, regardless of how depleted the
# rate-limit budget gets — a scan should always be able to make forward
# progress instead of stalling at 0 in-flight requests.
MIN_CONCURRENCY = 2


async def _fetch_one(client, repo: RepoRef, semaphore, initial_concurrency: int) -> tuple[RepoRef, dict[str, str] | None]:
    """Fetch workflows for a single repo under semaphore, then recalibrate
    concurrency for the next repo based on the freshest rate-limit reading."""
    from actionradius.inventory.async_tree_fetcher import fetch_workflow_contents_async

    try:
        files = await fetch_workflow_contents_async(client, repo.owner, repo.name, repo.default_branch, semaphore)
        return (repo, files)
    except Exception as e:
        print(f"  WARNING: async fetch failed for {repo.owner}/{repo.name}: {e}")
        return (repo, None)
    finally:
        # Recalibrate after every repo, not just once up front — this is what
        # lets concurrency shrink mid-scan as the rate-limit budget drops
        # (and grow back toward the originally requested level if the budget
        # is healthy again, e.g. after a reset). Recalibration only ever
        # happens once the fetch above has released its own semaphore
        # permits, so this can never deadlock against itself.
        await _recalibrate(client, semaphore, initial_concurrency)


async def _recalibrate(client, semaphore, initial_concurrency: int) -> None:
    from actionradius.github_client_async import recalibrate_concurrency

    target = recalibrate_concurrency(
        rate_limit_remaining=client.rate_limit_remaining,
        initial_limit=initial_concurrency,
        minimum=min(MIN_CONCURRENCY, initial_concurrency),
    )
    if target != semaphore.limit:
        new_limit = await semaphore.resize(target)
        if new_limit < initial_concurrency:
            print(f"  INFO: reduced concurrency to {new_limit} (rate-limit remaining: {client.rate_limit_remaining})")


async def _prefetch(token: str | None, repos: list[RepoRef], concurrency: int) -> dict:
    """Internal async entry point — creates client, gathers, returns results."""
    from actionradius.github_client_async import AsyncGitHubClient, compute_concurrency, DynamicSemaphore

    client = AsyncGitHubClient(token=token)

    # Use a lightweight request to calibrate concurrency from rate-limit headers
    try:
        await client._get("/rate_limit")
        actual_concurrency = compute_concurrency(client.rate_limit_remaining)
        concurrency = min(concurrency, actual_concurrency)
    except Exception:
        pass  # Proceed with the user-specified or default concurrency

    initial_concurrency = max(1, concurrency)
    semaphore = DynamicSemaphore(
        initial=initial_concurrency,
        minimum=min(MIN_CONCURRENCY, initial_concurrency),
        maximum=initial_concurrency,
    )
    tasks = [_fetch_one(client, repo, semaphore, initial_concurrency) for repo in repos]
    results = await asyncio.gather(*tasks)
    await client.close()

    return {repo.owner + "/" + repo.name: files for repo, files in results if files is not None}


def prefetch_all_workflows(token: str | None, repos: list[RepoRef], concurrency: int = 10) -> dict:
    """
    Synchronous wrapper for async prefetch — called from CLI.

    Returns {"owner/repo": {path: content}} for all repos that succeeded.
    """
    return asyncio.run(_prefetch(token, repos, concurrency))
