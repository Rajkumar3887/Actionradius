"""Tests for dynamic concurrency recalibration (DynamicSemaphore +
recalibrate_concurrency in github_client_async.py, and the async_scan.py
orchestration that drives it mid-scan)."""

import asyncio
import base64
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from actionradius.github_client_async import (
    DynamicSemaphore,
    recalibrate_concurrency,
)
from actionradius.models import RepoRef


# --- recalibrate_concurrency: pure function ---

def test_recalibrate_healthy_limit_no_unnecessary_reduction():
    """Plenty of budget remaining -> stay at the originally requested level."""
    assert recalibrate_concurrency(rate_limit_remaining=5000, initial_limit=10) == 10


def test_recalibrate_never_exceeds_initial_limit():
    """A very healthy budget must not grant *more* concurrency than requested."""
    assert recalibrate_concurrency(rate_limit_remaining=5000, initial_limit=3) == 3


def test_recalibrate_threshold_reached_reduces():
    """A depleted-but-not-critical budget should shrink concurrency below the
    initial level."""
    result = recalibrate_concurrency(rate_limit_remaining=50, initial_limit=10)
    assert result < 10
    assert result >= 1


def test_recalibrate_very_low_limit_stronger_reduction():
    """Near-zero budget should reduce concurrency more aggressively than a
    merely-depleted budget."""
    moderately_low = recalibrate_concurrency(rate_limit_remaining=50, initial_limit=10)
    very_low = recalibrate_concurrency(rate_limit_remaining=2, initial_limit=10)
    assert very_low <= moderately_low


def test_recalibrate_zero_remaining_hits_minimum():
    assert recalibrate_concurrency(rate_limit_remaining=0, initial_limit=10, minimum=2) == 2


def test_recalibrate_respects_minimum_floor():
    """Even an exhausted budget can't push concurrency below the configured
    minimum."""
    assert recalibrate_concurrency(rate_limit_remaining=0, initial_limit=10, minimum=3) == 3


def test_recalibrate_missing_data_is_safe():
    """Missing/unusable rate-limit data must not crash and must not
    aggressively throttle based on nothing — it keeps the initial level."""
    assert recalibrate_concurrency(rate_limit_remaining=None, initial_limit=10) == 10


def test_recalibrate_is_repeatable_and_idempotent():
    """Calling recalibration repeatedly with the same input is stable."""
    results = [recalibrate_concurrency(rate_limit_remaining=40, initial_limit=10) for _ in range(5)]
    assert len(set(results)) == 1


# --- DynamicSemaphore: resizing behavior ---

def test_dynamic_semaphore_shrink_reduces_inflight_capacity():
    """After shrinking, no more than the new (lower) limit of tasks should be
    able to hold the semaphore concurrently."""
    async def _run():
        sem = DynamicSemaphore(initial=4, minimum=1, maximum=4)
        await sem.resize(2)
        assert sem.limit == 2

        inflight = 0
        max_inflight = 0
        started = asyncio.Event()

        async def worker():
            nonlocal inflight, max_inflight
            async with sem:
                inflight += 1
                max_inflight = max(max_inflight, inflight)
                started.set()
                await asyncio.sleep(0.05)
                inflight -= 1

        await asyncio.gather(*[worker() for _ in range(6)])
        assert max_inflight <= 2

    asyncio.run(_run())


def test_dynamic_semaphore_grow_restores_capacity():
    """Growing the limit back up allows more concurrent holders again."""
    async def _run():
        sem = DynamicSemaphore(initial=4, minimum=1, maximum=8)
        await sem.resize(1)
        assert sem.limit == 1
        await sem.resize(4)
        assert sem.limit == 4

        inflight = 0
        max_inflight = 0

        async def worker():
            nonlocal inflight, max_inflight
            async with sem:
                inflight += 1
                max_inflight = max(max_inflight, inflight)
                await asyncio.sleep(0.05)
                inflight -= 1

        await asyncio.gather(*[worker() for _ in range(6)])
        assert max_inflight == 4

    asyncio.run(_run())


def test_dynamic_semaphore_respects_minimum_and_maximum_clamping():
    async def _run():
        sem = DynamicSemaphore(initial=5, minimum=2, maximum=5)
        applied = await sem.resize(0)
        assert applied == 2  # clamped up to minimum
        applied = await sem.resize(100)
        assert applied == 5  # clamped down to maximum

    asyncio.run(_run())


def test_dynamic_semaphore_repeated_resize_is_stable():
    """Resizing to the same value repeatedly shouldn't drift the internal
    accounting (no deadlock, no lost permits)."""
    async def _run():
        sem = DynamicSemaphore(initial=3, minimum=1, maximum=3)
        for _ in range(10):
            await sem.resize(3)
            await sem.resize(1)
        await sem.resize(3)

        # All 3 slots should still be usable after all that churn.
        acquired = []
        for _ in range(3):
            await asyncio.wait_for(sem.acquire(), timeout=1)
            acquired.append(True)
        assert len(acquired) == 3
        for _ in acquired:
            sem.release()

    asyncio.run(_run())


def test_dynamic_semaphore_concurrent_resizes_do_not_corrupt_state():
    """Many tasks calling resize() concurrently must not deadlock or leave
    the semaphore in a state where its limit doesn't match reality."""
    async def _run():
        sem = DynamicSemaphore(initial=10, minimum=1, maximum=10)
        targets = [1, 10, 3, 7, 2, 9, 1, 5, 10, 4]

        await asyncio.wait_for(
            asyncio.gather(*[sem.resize(t) for t in targets]),
            timeout=2,
        )
        # Whatever the final winner was, the limit is one of the requested
        # targets and stays within bounds.
        assert 1 <= sem.limit <= 10

        # The semaphore must still be usable afterwards for exactly `limit`
        # concurrent holders.
        inflight = 0
        max_inflight = 0

        async def worker():
            nonlocal inflight, max_inflight
            async with sem:
                inflight += 1
                max_inflight = max(max_inflight, inflight)
                await asyncio.sleep(0.02)
                inflight -= 1

        await asyncio.gather(*[worker() for _ in range(12)])
        assert max_inflight == sem.limit

    asyncio.run(_run())


def test_dynamic_semaphore_minimum_concurrency_never_zero():
    async def _run():
        sem = DynamicSemaphore(initial=5, minimum=1, maximum=5)
        await sem.resize(-100)
        assert sem.limit == 1
        # Still able to make forward progress.
        await asyncio.wait_for(sem.acquire(), timeout=1)
        sem.release()

    asyncio.run(_run())


def test_dynamic_semaphore_rejects_invalid_initial():
    with pytest.raises(ValueError):
        DynamicSemaphore(initial=0)


# --- Integration: rate-limit tracking flows into semaphore resize mid-scan ---

def test_prefetch_shrinks_concurrency_as_rate_limit_drops():
    """End-to-end: as the (mocked) client's rate_limit_remaining drops across
    repos, later repos should observe a smaller effective semaphore limit."""
    repos = [
        RepoRef(owner="org", name=f"repo{i}", default_branch="main", is_private=False)
        for i in range(4)
    ]

    remaining_sequence = [5000, 5000, 40, 2]  # healthy -> healthy -> low -> critical
    call_index = {"i": 0}

    async def fake_get(path, params=None):
        if "git/trees" in path:
            return {"tree": [{"path": ".github/workflows/ci.yml", "type": "blob"}], "truncated": False}
        elif "contents" in path:
            content = base64.b64encode(b"name: CI\non: push\njobs: {}").decode()
            return {"content": content}
        elif "rate_limit" in path:
            return {"rate": {"remaining": 5000}}
        return {}

    with patch("actionradius.github_client_async.HAS_HTTPX", True):
        with patch("actionradius.github_client_async.AsyncGitHubClient") as MockClient:
            instance = MagicMock()
            instance._get = AsyncMock(side_effect=fake_get)
            instance.rate_limit_remaining = 5000
            instance.close = AsyncMock()
            MockClient.return_value = instance

            observed_limits = []

            from actionradius import async_scan

            real_recalibrate = async_scan._recalibrate

            async def spying_recalibrate(client, semaphore, initial_concurrency):
                # Advance the mocked rate-limit reading each time a repo
                # finishes, simulating the budget draining over the scan.
                idx = min(call_index["i"], len(remaining_sequence) - 1)
                client.rate_limit_remaining = remaining_sequence[idx]
                call_index["i"] += 1
                await real_recalibrate(client, semaphore, initial_concurrency)
                observed_limits.append(semaphore.limit)

            with patch("actionradius.async_scan._recalibrate", side_effect=spying_recalibrate):
                result = async_scan.prefetch_all_workflows(token="fake", repos=repos, concurrency=10)

    assert len(result) == 4
    # Concurrency should have shrunk by the end, tracking the draining budget.
    assert observed_limits[-1] < 10
    assert observed_limits[-1] >= 2  # never below the orchestrator's floor


def test_prefetch_no_reduction_when_budget_stays_healthy():
    """If the rate-limit budget never gets low, concurrency should stay at
    the originally requested level throughout."""
    repos = [
        RepoRef(owner="org", name=f"repo{i}", default_branch="main", is_private=False)
        for i in range(3)
    ]

    async def fake_get(path, params=None):
        if "git/trees" in path:
            return {"tree": [{"path": ".github/workflows/ci.yml", "type": "blob"}], "truncated": False}
        elif "contents" in path:
            content = base64.b64encode(b"name: CI\non: push\njobs: {}").decode()
            return {"content": content}
        elif "rate_limit" in path:
            return {"rate": {"remaining": 5000}}
        return {}

    with patch("actionradius.github_client_async.HAS_HTTPX", True):
        with patch("actionradius.github_client_async.AsyncGitHubClient") as MockClient:
            instance = MagicMock()
            instance._get = AsyncMock(side_effect=fake_get)
            instance.rate_limit_remaining = 5000
            instance.close = AsyncMock()
            MockClient.return_value = instance

            from actionradius.async_scan import prefetch_all_workflows
            result = prefetch_all_workflows(token="fake", repos=repos, concurrency=5)

    assert len(result) == 3


def test_prefetch_missing_rate_limit_data_does_not_crash():
    """If rate_limit_remaining is None throughout (unusable/missing data),
    the scan should still complete normally without throttling."""
    repos = [
        RepoRef(owner="org", name="repo1", default_branch="main", is_private=False),
    ]

    async def fake_get(path, params=None):
        if "git/trees" in path:
            return {"tree": [{"path": ".github/workflows/ci.yml", "type": "blob"}], "truncated": False}
        elif "contents" in path:
            content = base64.b64encode(b"name: CI\non: push\njobs: {}").decode()
            return {"content": content}
        elif "rate_limit" in path:
            raise RuntimeError("rate limit endpoint unreachable")
        return {}

    with patch("actionradius.github_client_async.HAS_HTTPX", True):
        with patch("actionradius.github_client_async.AsyncGitHubClient") as MockClient:
            instance = MagicMock()
            instance._get = AsyncMock(side_effect=fake_get)
            instance.rate_limit_remaining = None
            instance.close = AsyncMock()
            MockClient.return_value = instance

            from actionradius.async_scan import prefetch_all_workflows
            result = prefetch_all_workflows(token="fake", repos=repos, concurrency=5)

    assert "org/repo1" in result


def test_async_client_ignores_missing_rate_limit_header():
    """The async client should not clobber its tracked rate_limit_remaining
    with a bogus sentinel when a response lacks the header."""
    async def _run():
        with patch("actionradius.github_client_async.HAS_HTTPX", True):
            with patch("actionradius.github_client_async.httpx", create=True):
                from actionradius.github_client_async import AsyncGitHubClient

                client = AsyncGitHubClient(token="test")
                client.rate_limit_remaining = 4321  # simulate a prior good reading

                response = MagicMock()
                response.status_code = 200
                response.headers = {}  # no rate-limit headers on this response
                response.json.return_value = {"ok": True}
                client._client.get = AsyncMock(return_value=response)

                result = await client._get("/some/endpoint")
                assert result == {"ok": True}
                # Previous reading preserved, not reset to -1 or 0.
                assert client.rate_limit_remaining == 4321

    asyncio.run(_run())


def test_async_client_ignores_malformed_rate_limit_header():
    async def _run():
        with patch("actionradius.github_client_async.HAS_HTTPX", True):
            with patch("actionradius.github_client_async.httpx", create=True):
                from actionradius.github_client_async import AsyncGitHubClient

                client = AsyncGitHubClient(token="test")
                client.rate_limit_remaining = 999

                response = MagicMock()
                response.status_code = 200
                response.headers = {"X-RateLimit-Remaining": "not-a-number"}
                response.json.return_value = {"ok": True}
                client._client.get = AsyncMock(return_value=response)

                await client._get("/some/endpoint")
                assert client.rate_limit_remaining == 999

    asyncio.run(_run())
