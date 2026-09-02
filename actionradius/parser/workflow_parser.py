def parse_workflow_yaml(repo: RepoRef, path: str, yaml_text: str) -> WorkflowFile:
    parsed = yaml.safe_load(yaml_text)
    if not isinstance(parsed, dict):
        raise ValueError(f"{path}: not a valid workflow file")

    raw_triggers = parsed.get("on", parsed.get(True))
    triggers = extract_trigger_risk(raw_triggers)
    
    permissions = extract_permissions(parsed)
    
    # FIX: Extract secrets globally from the entire parsed workflow dictionary
    secrets = extract_secrets(parsed)
    
    # Check runs_on_self_hosted by doing a simplistic check across jobs
    runs_on_self_hosted = False
    jobs = parsed.get("jobs", {})
    
    uses_sites = []
    run_scripts = []
    
    if isinstance(jobs, dict):
        for job_id, job_def in jobs.items():
            if not isinstance(job_def, dict):
                continue
                
            runs_on = job_def.get("runs-on", "")
            if isinstance(runs_on, str) and ("self-hosted" in runs_on):
                runs_on_self_hosted = True
            elif isinstance(runs_on, list) and "self-hosted" in runs_on:
                runs_on_self_hosted = True
                
            # REMOVED: job_secrets reassignment block that was overwriting data

            if "uses" in job_def:
                uses_sites.append(UsesSite(
                    workflow_path=path,
                    job_id=job_id,
                    step_index=None,
                    uses=parse_uses(job_def["uses"]),
                    depth=0,
                    source_chain=[]
                ))

            steps = job_def.get("steps", [])
            if isinstance(steps, list):
                for i, step in enumerate(steps):
                    if isinstance(step, dict):
                        if "uses" in step:
                            uses_sites.append(UsesSite(
                                workflow_path=path,
                                job_id=job_id,
                                step_index=i,
                                uses=parse_uses(step["uses"]),
                                depth=0,
                                source_chain=[]
                            ))
                        if "run" in step:
                            run_scripts.append(step["run"])

    return WorkflowFile(
        repo=repo,
        path=path,
        triggers=triggers,
        permissions=permissions,
        secrets=secrets,
        runs_on_self_hosted=runs_on_self_hosted,
        uses_sites=uses_sites,
        run_scripts=run_scripts
    )