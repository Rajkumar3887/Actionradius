from actionradius.models import PermissionsContext

def extract_permissions(workflow_dict: dict, job_dict: dict | None = None) -> PermissionsContext:
    target_dict = job_dict if job_dict else workflow_dict
    raw_perms = target_dict.get("permissions", {})
    
    scope = "job" if job_dict else "workflow"
    if not raw_perms and scope == "workflow":
        scope = "default"
        
    contents = "read" # Assume read by default, might be modified
    if isinstance(raw_perms, str):
        if raw_perms == "write-all":
            contents = "write"
    elif isinstance(raw_perms, dict):
        if any(v in ["write", "admin"] for v in raw_perms.values()):
            contents = "write"

    return PermissionsContext(
        scope=scope,
        contents=contents,
        raw=raw_perms if isinstance(raw_perms, dict) else {"all": raw_perms}
    )
