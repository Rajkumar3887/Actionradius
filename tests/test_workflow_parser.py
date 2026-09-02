from actionradius.parser.workflow_parser import parse_workflow_yaml
from actionradius.models import RepoRef

def load_fixture(name: str) -> str:
    with open(f"tests/fixtures/{name}", encoding="utf-8") as f:
        return f.read()

def test_normal_ci_extracts_all_uses_sites():
    text = load_fixture("normal_ci.yml")
    repo = RepoRef(owner="test", name="test", default_branch="main", is_private=False)
    wf = parse_workflow_yaml(repo, "tests/fixtures/normal_ci.yml", text)

    assert len(wf.uses_sites) == 5

    checkout_tag = next(s for s in wf.uses_sites if s.uses.ref == "v4")
    assert checkout_tag.job_id == "build"
    assert checkout_tag.uses.ref_type == "mutable_ref"

    checkout_sha = next(s for s in wf.uses_sites if s.uses.ref_type == "sha")
    assert checkout_sha.uses.owner == "actions"

    trivy = next(s for s in wf.uses_sites if s.uses.repo == "trivy-action")
    assert trivy.uses.ref_type == "sha"

    local = next(s for s in wf.uses_sites if s.uses.ref_type == "local")
    assert local.uses.path == "./.github/actions/local-build-step"

    reusable = next(s for s in wf.uses_sites if s.uses.is_reusable_workflow)
    assert reusable.job_id == "publish"
    assert reusable.step_index is None

def test_on_trigger_parsed_despite_yaml_boolean_gotcha():
    text = load_fixture("normal_ci.yml")
    repo = RepoRef(owner="test", name="test", default_branch="main", is_private=False)
    wf = parse_workflow_yaml(repo, "tests/fixtures/normal_ci.yml", text)
    assert wf.triggers.events == ["push", "pull_request"]

def test_risky_workflow_extracts_pull_request_target_trigger():
    text = load_fixture("risky_pull_request_target.yml")
    repo = RepoRef(owner="test", name="test", default_branch="main", is_private=False)
    wf = parse_workflow_yaml(repo, "tests/fixtures/risky_pull_request_target.yml", text)

    assert "pull_request_target" in wf.triggers.events
    assert wf.triggers.fork_reachable is True
    
    trivy_site = next(s for s in wf.uses_sites if s.uses.repo == "trivy-action")
    assert trivy_site.uses.ref == "v0.28.0"
    assert trivy_site.uses.ref_type == "mutable_ref"
