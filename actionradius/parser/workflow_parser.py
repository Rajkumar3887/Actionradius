import yaml
from actionradius.models import WorkflowFile, UsesSite, RepoRef
from actionradius.parser.uses_parser import parse_uses
from actionradius.context.trigger_risk import extract_trigger_risk
from actionradius.context.permissions import extract_permissions
from actionradius.context.secrets import extract_secrets

def parse_workflow_yaml(repo: RepoRef, path: str, yaml_text: str) -> WorkflowFile:
    parsed = yaml.safe_load(yaml_text)
    if not isinstance(parsed, dict):
        raise ValueError(f"{path}: not a valid workflow file")

    raw_triggers = parsed.get("on", parsed.get(True))
    triggers = extract_trigger_risk(raw_triggers)
    
    permissions = extract_permissions(parsed)
    
    # Check runs_on_self_hosted by doing a simplistic check across jobs
    runs_on_self_hosted = False
    jobs = parsed.get("jobs", {})
    secrets = extract_secrets({}) # default empty
    
    uses_sites = []
    
    if isinstance(jobs, dict):
        for job_id, job_def in jobs.items():
            if not isinstance(job_def, dict):
                continue
                
            runs_on = job_def.get("runs-on", "")
            if isinstance(runs_on, str) and ("self-hosted" in runs_on):
                runs_on_self_hosted = True
            elif isinstance(runs_on, list) and "self-hosted" in runs_on:
                runs_on_self_hosted = True
                
            job_secrets = extract_secrets(job_def)
            if job_secrets.has_real_secrets:
                secrets = job_secrets

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
                    if isinstance(step, dict) and "uses" in step:
                        uses_sites.append(UsesSite(
                            workflow_path=path,
                            job_id=job_id,
                            step_index=i,
                            uses=parse_uses(step["uses"]),
                            depth=0,
                            source_chain=[]
                        ))

    return WorkflowFile(
        repo=repo,
        path=path,
        triggers=triggers,
        permissions=permissions,
        secrets=secrets,
        runs_on_self_hosted=runs_on_self_hosted,
        uses_sites=uses_sites
    )
