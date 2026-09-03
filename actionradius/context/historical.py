from datetime import datetime
from actionradius.github_client import GitHubClient
from actionradius.models import CompromiseStatus

def check_historical_exposure(
    client: GitHubClient, 
    owner: str, 
    repo: str, 
    workflow_path: str, 
    attack_window: dict | None
) -> CompromiseStatus:
    """
    Checks if a workflow was present and unmodified (or modified) during the attack window.
    Returns 'COMPROMISED' if exposed historically, else 'UNKNOWN'.
    """
    if not attack_window or not client:
        return "UNKNOWN"
        
    try:
        # To determine if the workflow existed during the attack window,
        # we ask GitHub for the most recent commit to this file UNTIL the end of the window.
        # If the file existed before or during the window, the API will return a commit.
        # If it was created strictly AFTER the window, it returns an empty list.
        end_date_str = attack_window.get("end")
        if not end_date_str:
            return "UNKNOWN"

        params = {
            "path": workflow_path,
            "until": end_date_str,
            "per_page": 1
        }
        
        data = client._get(f"/repos/{owner}/{repo}/commits", params=params)
        
        if not isinstance(data, list):
            return "UNKNOWN"
            
        if len(data) > 0:
            return "COMPROMISED"
            
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"
