from actionradius.context.trigger_risk import extract_trigger_risk
from actionradius.context.permissions import extract_permissions
from actionradius.context.secrets import extract_secrets

def test_normal_workflow_has_no_risk():
    workflow = {"on": {"push": None}, "permissions": {"contents": "read"}, "jobs": {}}
    
    triggers = extract_trigger_risk(workflow["on"])
    assert not triggers.fork_reachable
    
    perms = extract_permissions(workflow)
    assert perms.contents == "read"
    
def test_pull_request_target_is_detected():
    triggers = extract_trigger_risk({"pull_request_target": None})
    assert triggers.fork_reachable is True
    assert triggers.risk == "high"

def test_write_all_is_detected():
    workflow = {"permissions": "write-all"}
    perms = extract_permissions(workflow)
    assert perms.contents == "write"

def test_job_write_permission_is_detected():
    job = {"permissions": {"contents": "write"}}
    perms = extract_permissions({}, job_dict=job)
    assert perms.contents == "write"
    assert perms.scope == "job"

def test_inherited_secrets_are_detected():
    job = {"secrets": "inherit"}
    secrets = extract_secrets(job)
    assert secrets.inherits_all is True
    assert secrets.has_real_secrets is True

def test_explicit_secrets_are_detected():
    job = {"secrets": {"AWS_KEY": "some-secret", "DEPLOY_TOKEN": "another-secret"}}
    secrets = extract_secrets(job)
    assert "AWS_KEY" in secrets.explicit_secrets
    assert "DEPLOY_TOKEN" in secrets.explicit_secrets
    assert secrets.has_real_secrets is True