"""
Tests for inventory.py — deliberately only the pure-logic parts.
No network calls happen in this test file at all.
"""
import sys
sys.path.insert(0, "actionradius")
from inventory import is_workflow_path, parse_workflow_files


def test_is_workflow_path_accepts_valid_paths():
    assert is_workflow_path(".github/workflows/ci.yml")
    assert is_workflow_path(".github/workflows/release.yaml")


def test_is_workflow_path_rejects_other_paths():
    assert not is_workflow_path("README.md")
    assert not is_workflow_path(".github/actions/some-action/action.yml")  # an Action def, not a workflow
    assert not is_workflow_path("src/workflows/ci.yml")  # right filename, wrong location


def test_parse_workflow_files_across_multiple_files():
    def load(name):
        with open(f"tests/fixtures/{name}", encoding="utf-8") as f:
            return f.read()

    files = {
        "tests/fixtures/normal_ci.yml": load("normal_ci.yml"),
        "tests/fixtures/risky_pull_request_target.yml": load("risky_pull_request_target.yml"),
    }
    workflows = parse_workflow_files(files)

    assert len(workflows) == 2
    total_sites = sum(len(wf.uses_sites) for wf in workflows)
    assert total_sites == 7  # 5 from normal_ci.yml + 2 from risky_pull_request_target.yml
    # (risky_pull_request_target.yml has TWO uses: steps — checkout@v4 AND trivy-action@v0.28.0)


def test_parse_workflow_files_skips_malformed_without_crashing():
    files = {
        "tests/fixtures/normal_ci.yml": open("tests/fixtures/normal_ci.yml", encoding="utf-8").read(),
        "broken.yml": "this is: not: valid: yaml: [structure",
    }
    workflows = parse_workflow_files(files)
    # The good file still parses; the broken one is skipped, not fatal.
    assert len(workflows) == 1
    assert workflows[0].path == "tests/fixtures/normal_ci.yml"
