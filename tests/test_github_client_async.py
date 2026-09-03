import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from actionradius.github_client_async import AsyncGitHubClient

@patch("actionradius.github_client_async.HAS_HTTPX", True)
@patch("actionradius.github_client_async.httpx", create=True)
def test_async_get_success(mock_httpx):
    client = AsyncGitHubClient(token="test")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"X-RateLimit-Remaining": "4999"}
    mock_response.json.return_value = {"success": True}
    
    client._client.get = AsyncMock(return_value=mock_response)
    
    res = asyncio.run(client._get("/test"))
    assert res == {"success": True}
    assert client.rate_limit_remaining == 4999

@patch("actionradius.github_client_async.HAS_HTTPX", True)
@patch("actionradius.github_client_async.httpx", create=True)
def test_async_get_retry_after(mock_httpx):
    client = AsyncGitHubClient(token="test")
    
    mock_403 = MagicMock()
    mock_403.status_code = 403
    mock_403.headers = {"Retry-After": "1", "X-RateLimit-Remaining": "100"}
    
    mock_200 = MagicMock()
    mock_200.status_code = 200
    mock_200.headers = {"X-RateLimit-Remaining": "99"}
    mock_200.json.return_value = {"success": True}
    
    client._client.get = AsyncMock(side_effect=[mock_403, mock_200])
    
    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        res = asyncio.run(client._get("/test"))
        assert res == {"success": True}
        mock_sleep.assert_called_once_with(2)  # int(retry_after) + 1
        assert client._client.get.call_count == 2

@patch("actionradius.github_client_async.HAS_HTTPX", True)
@patch("actionradius.github_client_async.httpx", create=True)
def test_async_get_primary_rate_limit(mock_httpx):
    import time
    client = AsyncGitHubClient(token="test")
    
    mock_403 = MagicMock()
    mock_403.status_code = 403
    reset_time = int(time.time()) + 5
    mock_403.headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset_time)}
    
    mock_200 = MagicMock()
    mock_200.status_code = 200
    mock_200.headers = {"X-RateLimit-Remaining": "5000"}
    mock_200.json.return_value = {"success": True}
    
    client._client.get = AsyncMock(side_effect=[mock_403, mock_200])
    
    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        res = asyncio.run(client._get("/test"))
        assert res == {"success": True}
        mock_sleep.assert_called_once()
        assert client._client.get.call_count == 2
