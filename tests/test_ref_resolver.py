import pytest
from unittest.mock import patch, Mock
from actionradius.ref_resolver import resolve_mutable_ref, _RESOLUTION_CACHE

@pytest.fixture(autouse=True)
def clear_cache():
    """Ensure a clean cache before every test."""
    _RESOLUTION_CACHE.clear()

@patch("actionradius.ref_resolver.requests.get")
def test_resolves_tag_successfully(mock_get):
    # Arrange: Mock a successful GitHub API tag response
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"object": {"sha": "1234567890abcdef"}}
    
    # Act
    sha = resolve_mutable_ref("actions", "checkout", "v3")
    
    # Assert
    assert sha == "1234567890abcdef"
    mock_get.assert_called_once()
    assert "tags/v3" in mock_get.call_args[0][0]

@patch("actionradius.ref_resolver.requests.get")
def test_falls_back_to_branch_if_tag_fails(mock_get):
    # Arrange: First call (tag) 404s, Second call (branch) 200s
    resp1 = Mock()
    resp1.status_code = 404
    
    resp2 = Mock()
    resp2.status_code = 200
    resp2.json.return_value = {"object": {"sha": "abcdef1234567890"}}
    
    mock_get.side_effect = [resp1, resp2]
    
    # Act
    sha = resolve_mutable_ref("actions", "checkout", "main")
    
    # Assert
    assert sha == "abcdef1234567890"
    assert mock_get.call_count == 2

@patch("actionradius.ref_resolver.requests.get")
def test_cache_prevents_duplicate_api_calls(mock_get):
    # Arrange
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"object": {"sha": "cached_sha"}}
    
    # Act: Request the same ref twice
    sha1 = resolve_mutable_ref("org", "repo", "v1")
    sha2 = resolve_mutable_ref("org", "repo", "v1")
    
    # Assert
    assert sha1 == "cached_sha"
    assert sha2 == "cached_sha"
    mock_get.assert_called_once()