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
        data = client._get(f"/repos/{owner}/{repo}/commits", params={"path": workflow_path, "per_page": 1})
        if not data or not isinstance(data, list) or len(data) == 0:
            return "UNKNOWN"
            
        commit_date_str = data[0].get("commit", {}).get("committer", {}).get("date")
        if not commit_date_str:
            return "UNKNOWN"
            
        commit_date = datetime.fromisoformat(commit_date_str.replace("Z", "+00:00"))
        
        # We only strictly need end_date to know if it was exposed.
        # If the workflow's last modification was AFTER the attack window ended,
        # we can't be sure it contained the compromised action during the attack
        # (it might have been added recently).
        # If the last modification was ON OR BEFORE the attack window ended,
        # and it currently has the action, it was running during the attack.
        end_date = datetime.fromisoformat(attack_window["end"].replace("Z", "+00:00"))
        
        if commit_date <= end_date:
            return "COMPROMISED"
            
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"
