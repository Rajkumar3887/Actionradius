import base64
from datetime import datetime
from actionradius.github_client import GitHubClient
from actionradius.models import CompromiseStatus, UsesRef, RepoRef
from actionradius.parser.workflow_parser import parse_workflow_yaml

def check_historical_exposure(
    client: GitHubClient, 
    owner: str, 
    repo: str, 
    workflow_path: str, 
    attack_window: dict | None,
    target_uses: UsesRef
) -> CompromiseStatus:
    """
    Checks if a workflow contained the target action during the attack window.
    Fetches the latest commit until attack_window.end, downloads the YAML at that SHA,
    and parses it to verify the target was present.
    """
    if not attack_window or not client:
        return "UNKNOWN"
        
    try:
        end_date_str = attack_window.get("end")
        if not end_date_str:
            return "UNKNOWN"

        params = {
            "path": workflow_path,
            "until": end_date_str,
            "per_page": 1
        }
        
        data = client._get(f"/repos/{owner}/{repo}/commits", params=params)
        if not isinstance(data, list) or len(data) == 0:
            return "UNKNOWN"
            
        historical_sha = data[0].get("sha")
        if not historical_sha:
            return "UNKNOWN"
            
        # Fetch file content at that historical SHA
        file_data = client._get(f"/repos/{owner}/{repo}/contents/{workflow_path}", params={"ref": historical_sha})
        if "content" not in file_data:
            return "UNKNOWN"
            
        content = base64.b64decode(file_data["content"]).decode("utf-8")
        
        # Parse historical workflow
        dummy_repo = RepoRef(owner, repo, "main", False)
        historical_wf = parse_workflow_yaml(dummy_repo, workflow_path, content)
        
        # Verify the target action existed in this historical version
        for h_site in historical_wf.uses_sites:
            if h_site.uses.owner == target_uses.owner and h_site.uses.repo == target_uses.repo:
                return "COMPROMISED"
                
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"
