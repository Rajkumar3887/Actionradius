from unittest.mock import MagicMock
from actionradius.context.historical import check_historical_exposure

def test_historical_exposure_no_window():
    client = MagicMock()
    # Missing attack window should return UNKNOWN
    assert check_historical_exposure(client, "owner", "repo", "path.yml", None) == "UNKNOWN"

def test_historical_exposure_api_error():
    client = MagicMock()
    client._get.side_effect = Exception("API Error")
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    assert check_historical_exposure(client, "owner", "repo", "path.yml", window) == "UNKNOWN"

def test_historical_exposure_inside_window():
    client = MagicMock()
    # Commit during the window
    client._get.return_value = [{"commit": {"committer": {"date": "2026-03-19T20:00:00Z"}}}]
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    assert check_historical_exposure(client, "owner", "repo", "path.yml", window) == "COMPROMISED"

def test_historical_exposure_before_window():
    client = MagicMock()
    # Commit before the window (workflow was active during the attack)
    client._get.return_value = [{"commit": {"committer": {"date": "2025-01-01T12:00:00Z"}}}]
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    assert check_historical_exposure(client, "owner", "repo", "path.yml", window) == "COMPROMISED"

def test_historical_exposure_after_window():
    client = MagicMock()
    # Commit after the window (we can't be sure if the action was present during the attack)
    client._get.return_value = [{"commit": {"committer": {"date": "2026-04-01T12:00:00Z"}}}]
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    assert check_historical_exposure(client, "owner", "repo", "path.yml", window) == "UNKNOWN"

def test_historical_exposure_empty_response():
    client = MagicMock()
    client._get.return_value = []
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    assert check_historical_exposure(client, "owner", "repo", "path.yml", window) == "UNKNOWN"
