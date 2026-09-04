"""Tests for transient 5xx retry/backoff, mirroring the existing 403
retry-after / primary-rate-limit test patterns in test_github_client_async.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from actionradius.github_client import GitHubClient
from actionradius.github_client_async import AsyncGitHubClient


# --- sync client ---

def test_sync_get_retries_on_502_then_succeeds():
    client = GitHubClient(token="test")

    mock_502 = MagicMock()
    mock_502.status_code = 502
    mock_502.headers = {}

    mock_200 = MagicMock()
    mock_200.status_code = 200
    mock_200.headers = {"X-RateLimit-Remaining": "4999"}
    mock_200.json.return_value = {"success": True}

    client.session.get = MagicMock(side_effect=[mock_502, mock_200])

    with patch("time.sleep") as mock_sleep:
        res = client._get("/test")
        assert res == {"success": True}
        assert client.session.get.call_count == 2
        mock_sleep.assert_called_once()


def test_sync_get_gives_up_after_max_retries_on_503():
    client = GitHubClient(token="test")

    mock_503 = MagicMock()
    mock_503.status_code = 503
    mock_503.headers = {}
    mock_503.raise_for_status.side_effect = Exception("server error")

    client.session.get = MagicMock(return_value=mock_503)

    with patch("time.sleep"):
        try:
            client._get("/test")
            assert False, "expected an exception after exhausting retries"
        except Exception:
            pass

    # 1 initial attempt + 3 retries = 4 total calls
    assert client.session.get.call_count == 4


def test_sync_get_does_not_retry_on_404():
    client = GitHubClient(token="test")

    mock_404 = MagicMock()
    mock_404.status_code = 404
    mock_404.headers = {}

    client.session.get = MagicMock(return_value=mock_404)

    with patch("time.sleep") as mock_sleep:
        try:
            client._get("/test")
            assert False, "expected ValueError for 404"
        except ValueError:
            pass

    assert client.session.get.call_count == 1
    mock_sleep.assert_not_called()


def test_sync_get_missing_rate_limit_header_preserves_prior_value():
    client = GitHubClient(token="test")
    client.rate_limit_remaining = 4321

    mock_200 = MagicMock()
    mock_200.status_code = 200
    mock_200.headers = {}
    mock_200.json.return_value = {"ok": True}

    client.session.get = MagicMock(return_value=mock_200)

    result = client._get("/test")
    assert result == {"ok": True}
    assert client.rate_limit_remaining == 4321


# --- async client ---

@patch("actionradius.github_client_async.HAS_HTTPX", True)
@patch("actionradius.github_client_async.httpx", create=True)
def test_async_get_retries_on_500_then_succeeds(mock_httpx):
    client = AsyncGitHubClient(token="test")

    mock_500 = MagicMock()
    mock_500.status_code = 500
    mock_500.headers = {}

    mock_200 = MagicMock()
    mock_200.status_code = 200
    mock_200.headers = {"X-RateLimit-Remaining": "4999"}
    mock_200.json.return_value = {"success": True}

    client._client.get = AsyncMock(side_effect=[mock_500, mock_200])

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        res = asyncio.run(client._get("/test"))
        assert res == {"success": True}
        assert client._client.get.call_count == 2
        mock_sleep.assert_called_once_with(1)  # 2 ** 0 backoff on first attempt


@patch("actionradius.github_client_async.HAS_HTTPX", True)
@patch("actionradius.github_client_async.httpx", create=True)
def test_async_get_gives_up_after_max_retries_on_504(mock_httpx):
    client = AsyncGitHubClient(token="test")

    mock_504 = MagicMock()
    mock_504.status_code = 504
    mock_504.headers = {}
    mock_504.raise_for_status.side_effect = Exception("server error")

    client._client.get = AsyncMock(return_value=mock_504)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        try:
            asyncio.run(client._get("/test"))
            assert False, "expected an exception after exhausting retries"
        except Exception:
            pass

    assert client._client.get.call_count == 4


@patch("actionradius.github_client_async.HAS_HTTPX", True)
@patch("actionradius.github_client_async.httpx", create=True)
def test_async_get_does_not_retry_on_404(mock_httpx):
    client = AsyncGitHubClient(token="test")

    mock_404 = MagicMock()
    mock_404.status_code = 404
    mock_404.headers = {}

    client._client.get = AsyncMock(return_value=mock_404)

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        try:
            asyncio.run(client._get("/test"))
            assert False, "expected ValueError for 404"
        except ValueError:
            pass

    assert client._client.get.call_count == 1
    mock_sleep.assert_not_called()
