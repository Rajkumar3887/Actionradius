"""
Tests for workflow_parser.py, using fixture workflow files.
Run from project root: pytest -v
"""
import sys
sys.path.insert(0, "actionradius")
from workflow_parser import parse_workflow_yaml


def load_fixture(name: str) -> str:
    with open(f"tests/fixtures/{name}", encoding="utf-8") as f:
        return f.read()


def test_normal_ci_extracts_all_uses_sites():
    text = load_fixture("normal_ci.yml")
    wf = parse_workflow_yaml("tests/fixtures/normal_ci.yml", text)

    assert wf.name == "CI"
    # 5 in the `build` job (4 uses steps) + 1 job-level uses in `publish` = 5 total
    assert len(wf.uses_sites) == 5

    # Spot-check a few specific sites rather than every single one
    checkout_tag = next(s for s in wf.uses_sites if s.uses.ref == "v4")
    assert checkout_tag.job_id == "build"
    assert checkout_tag.uses.ref_type == "mutable_ref"

    checkout_sha = next(s for s in wf.uses_sites if s.uses.ref_type == "sha" and s.uses.is_full_sha)
    assert checkout_sha.uses.owner == "actions"

    trivy = next(s for s in wf.uses_sites if s.uses.repo == "trivy-action")
    assert trivy.uses.ref_type == "sha"
    assert trivy.uses.is_full_sha is False  # the short SHA again

    local = next(s for s in wf.uses_sites if s.uses.ref_type == "local")
    assert local.uses.path == "./.github/actions/local-build-step"

    # The reusable workflow call — job-level uses:, so step_index is None
    reusable = next(s for s in wf.uses_sites if s.uses.is_reusable_workflow)
    assert reusable.job_id == "publish"
    assert reusable.step_index is None


def test_on_trigger_parsed_despite_yaml_boolean_gotcha():
    text = load_fixture("normal_ci.yml")
    wf = parse_workflow_yaml("tests/fixtures/normal_ci.yml", text)
    # If we'd gotten the True/"on" key handling wrong, this would be None.
    assert wf.raw_triggers == ["push", "pull_request"]


def test_risky_workflow_extracts_pull_request_target_trigger():
    text = load_fixture("risky_pull_request_target.yml")
    wf = parse_workflow_yaml("tests/fixtures/risky_pull_request_target.yml", text)

    assert "pull_request_target" in wf.raw_triggers
    trivy_site = next(s for s in wf.uses_sites if s.uses.repo == "trivy-action")
    assert trivy_site.uses.ref == "v0.28.0"
    assert trivy_site.uses.ref_type == "mutable_ref"  # exactly the pin type that got poisoned
