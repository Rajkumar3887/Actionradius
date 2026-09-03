from unittest.mock import MagicMock
from actionradius.context.historical import check_historical_exposure

def test_historical_exposure_existed_through_window():
    """1. workflow existed through attack window → COMPROMISED"""
    client = MagicMock()
    client._get.return_value = [{"sha": "abc12345"}]
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    
    result = check_historical_exposure(client, "owner", "repo", "path.yml", window)
    
    assert result == "COMPROMISED"
    # Ensure we passed the correct 'until' parameter
    client._get.assert_called_with(
        "/repos/owner/repo/commits", 
        params={"path": "path.yml", "until": "2026-03-20T05:40:00Z", "per_page": 1}
    )

def test_historical_exposure_first_appeared_after_window():
    """2. workflow first appeared after attack window → UNKNOWN"""
    client = MagicMock()
    # No commits returned before the 'until' date
    client._get.return_value = []
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    
    result = check_historical_exposure(client, "owner", "repo", "path.yml", window)
    
    assert result == "UNKNOWN"

def test_historical_exposure_changed_before_or_within_window():
    """3. workflow was changed before/within window → correct result"""
    client = MagicMock()
    client._get.return_value = [{"sha": "def67890"}]
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    
    result = check_historical_exposure(client, "owner", "repo", "path.yml", window)
    
    assert result == "COMPROMISED"

def test_historical_exposure_missing_invalid_data():
    """4. missing/invalid commit data → UNKNOWN"""
    client = MagicMock()
    # E.g., API returns a dict with an error message instead of a list of commits
    client._get.return_value = {"message": "Not Found"}
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    
    result = check_historical_exposure(client, "owner", "repo", "path.yml", window)
    
    assert result == "UNKNOWN"

def test_historical_exposure_api_error():
    """5. API error → UNKNOWN"""
    client = MagicMock()
    client._get.side_effect = Exception("API rate limit exceeded")
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    
    result = check_historical_exposure(client, "owner", "repo", "path.yml", window)
    
    assert result == "UNKNOWN"

def test_historical_exposure_no_window():
    """Missing window altogether → UNKNOWN"""
    client = MagicMock()
    result = check_historical_exposure(client, "owner", "repo", "path.yml", None)
    assert result == "UNKNOWN"
