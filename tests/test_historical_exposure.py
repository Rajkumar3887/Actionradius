import base64
from unittest.mock import MagicMock
from actionradius.context.historical import check_historical_exposure
from actionradius.models import UsesRef

WF_WITH_TARGET = b"""
name: test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/trivy-action@master
"""

WF_WITH_DIFFERENT_REF = b"""
name: test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/trivy-action@v1
"""

WF_WITHOUT_TARGET = b"""
name: test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: other/action@v1
"""

def test_historical_exposure_existed_through_window():
    """workflow + target existed during attack -> COMPROMISED"""
    client = MagicMock()
    client._get.side_effect = [
        [{"sha": "abc12345"}],
        {"content": base64.b64encode(WF_WITH_TARGET).decode("utf-8")}
    ]
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    target = UsesRef("aquasecurity/trivy-action@master", "aquasecurity", "trivy-action", None, "master", "mutable_ref", False)
    
    result = check_historical_exposure(client, "owner", "repo", "path.yml", window, target)
    assert result == "COMPROMISED"
    client._get.assert_any_call("/repos/owner/repo/commits", params={"path": "path.yml", "until": "2026-03-20T05:40:00Z", "per_page": 1})
    client._get.assert_any_call("/repos/owner/repo/contents/path.yml", params={"ref": "abc12345"})

def test_historical_exposure_different_ref_during_window():
    """workflow existed but used a DIFFERENT ref -> UNKNOWN (was not exposed to THIS ref)"""
    client = MagicMock()
    client._get.side_effect = [
        [{"sha": "def67890"}],
        {"content": base64.b64encode(WF_WITH_DIFFERENT_REF).decode("utf-8")}
    ]
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    target = UsesRef("aquasecurity/trivy-action@master", "aquasecurity", "trivy-action", None, "master", "mutable_ref", False)
    
    result = check_historical_exposure(client, "owner", "repo", "path.yml", window, target)
    assert result == "UNKNOWN"

def test_historical_exposure_target_added_after_window():
    """target added after attack -> UNKNOWN. The file existed, but didn't have the target."""
    client = MagicMock()
    client._get.side_effect = [
        [{"sha": "def67890"}],
        {"content": base64.b64encode(WF_WITHOUT_TARGET).decode("utf-8")}
    ]
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    target = UsesRef("aquasecurity/trivy-action@master", "aquasecurity", "trivy-action", None, "master", "mutable_ref", False)
    
    result = check_historical_exposure(client, "owner", "repo", "path.yml", window, target)
    assert result == "UNKNOWN"

def test_historical_exposure_first_appeared_after_window():
    """API returns empty list (workflow didn't exist at all before end) -> UNKNOWN"""
    client = MagicMock()
    client._get.return_value = []
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    target = UsesRef("aquasecurity/trivy-action@master", "aquasecurity", "trivy-action", None, "master", "mutable_ref", False)
    
    result = check_historical_exposure(client, "owner", "repo", "path.yml", window, target)
    assert result == "UNKNOWN"

def test_historical_exposure_missing_invalid_data():
    """missing/invalid commit data -> UNKNOWN"""
    client = MagicMock()
    client._get.return_value = {"message": "Not Found"}
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    target = UsesRef("aquasecurity/trivy-action@master", "aquasecurity", "trivy-action", None, "master", "mutable_ref", False)
    
    result = check_historical_exposure(client, "owner", "repo", "path.yml", window, target)
    assert result == "UNKNOWN"

def test_historical_exposure_api_error():
    """API error -> UNKNOWN"""
    client = MagicMock()
    client._get.side_effect = Exception("API rate limit exceeded")
    window = {"start": "2026-03-19T17:43:00Z", "end": "2026-03-20T05:40:00Z"}
    target = UsesRef("aquasecurity/trivy-action@master", "aquasecurity", "trivy-action", None, "master", "mutable_ref", False)
    
    result = check_historical_exposure(client, "owner", "repo", "path.yml", window, target)
    assert result == "UNKNOWN"

def test_historical_exposure_no_window():
    """Missing window altogether -> UNKNOWN"""
    client = MagicMock()
    target = UsesRef("aquasecurity/trivy-action@master", "aquasecurity", "trivy-action", "master", "tag", "tag", False)
    result = check_historical_exposure(client, "owner", "repo", "path.yml", None, target)
    assert result == "UNKNOWN"
