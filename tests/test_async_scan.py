"""Tests for the async scanning semaphore-sizing logic (no httpx required)."""

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch
from actionradius.models import RepoRef


def test_compute_concurrency_none():
    from actionradius.github_client_async import compute_concurrency
    assert compute_concurrency(None) == 1


def test_compute_concurrency_zero():
    from actionradius.github_client_async import compute_concurrency
    assert compute_concurrency(0) == 1


def test_compute_concurrency_low():
    from actionradius.github_client_async import compute_concurrency
    assert compute_concurrency(5) == 1


def test_compute_concurrency_medium():
    from actionradius.github_client_async import compute_concurrency
    assert compute_concurrency(100) == 10


def test_compute_concurrency_high():
    from actionradius.github_client_async import compute_concurrency
    assert compute_concurrency(500) == 20  # clamped to 20


def test_compute_concurrency_exact_boundary():
    from actionradius.github_client_async import compute_concurrency
    assert compute_concurrency(200) == 20


def test_prefetch_orchestration():
    """Integration test: exercises real concurrency, semaphore usage, and per-repo fetching."""
    repos = [
        RepoRef(owner="org", name="repo1", default_branch="main", is_private=False),
        RepoRef(owner="org", name="repo2", default_branch="main", is_private=False),
    ]

    async def fake_get(path, params=None):
        if "git/trees" in path:
            return {
                "tree": [{"path": ".github/workflows/ci.yml", "type": "blob"}],
                "truncated": False,
            }
        elif "contents" in path:
            content = base64.b64encode(b"name: CI\non: push\njobs: {}").decode()
            return {"content": content}
        elif "rate_limit" in path:
            return {"rate": {"remaining": 4999}}
        return {}

    with patch("actionradius.github_client_async.HAS_HTTPX", True):
        with patch("actionradius.github_client_async.AsyncGitHubClient") as MockClient:
            instance = MagicMock()
            instance._get = AsyncMock(side_effect=fake_get)
            instance.rate_limit_remaining = 4999
            instance.close = AsyncMock()
            MockClient.return_value = instance

            from actionradius.async_scan import prefetch_all_workflows
            result = prefetch_all_workflows(token="fake", repos=repos, concurrency=5)

    assert "org/repo1" in result
    assert "org/repo2" in result
    assert ".github/workflows/ci.yml" in result["org/repo1"]
