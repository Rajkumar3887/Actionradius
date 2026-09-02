def analyze_context(workflow_dict):
    """
    Analyzes a parsed workflow dictionary for security context risks.
    Returns a dictionary of found risks.
    """
    risks = {
        "has_pr_target": False,
        "elevated_permissions": False,
        "inherits_secrets": False,
        "explicit_secrets": []
    }

    if not workflow_dict or not isinstance(workflow_dict, dict):
        return risks

    # 1. Trigger Risk
    triggers = workflow_dict.get("on", workflow_dict.get(True, {}))

    if isinstance(triggers, dict) and "pull_request_target" in triggers:
        risks["has_pr_target"] = True
    elif isinstance(triggers, list) and "pull_request_target" in triggers:
        risks["has_pr_target"] = True
    elif isinstance(triggers, str) and triggers == "pull_request_target":
        risks["has_pr_target"] = True

    # 2. Global Permissions Risk
    global_perms = workflow_dict.get("permissions", {})

    if isinstance(global_perms, str) and global_perms == "write-all":
        risks["elevated_permissions"] = True

    elif isinstance(global_perms, dict):
        if any(v in ["write", "admin"] for v in global_perms.values()):
            risks["elevated_permissions"] = True

    # 3. Job-Level Secrets and Permissions
    jobs = workflow_dict.get("jobs", {})

    if isinstance(jobs, dict):
        for job_name, job_data in jobs.items():

            if not isinstance(job_data, dict):
                continue

            # Secrets
            job_secrets = job_data.get("secrets", {})

            if isinstance(job_secrets, str) and job_secrets == "inherit":
                risks["inherits_secrets"] = True

            elif isinstance(job_secrets, dict):
                risks["explicit_secrets"].extend(job_secrets.keys())

            # Permissions
            job_perms = job_data.get("permissions", {})

            if isinstance(job_perms, str) and job_perms == "write-all":
                risks["elevated_permissions"] = True

            elif isinstance(job_perms, dict):
                if any(v in ["write", "admin"] for v in job_perms.values()):
                    risks["elevated_permissions"] = True

    # Remove duplicates
    risks["explicit_secrets"] = list(set(risks["explicit_secrets"]))

    return risks