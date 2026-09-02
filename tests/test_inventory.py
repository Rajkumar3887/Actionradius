from actionradius.inventory.tree_fetcher import is_workflow_path
from actionradius.parser.workflow_parser import parse_workflow_yaml
from actionradius.models import RepoRef

def test_is_workflow_path_accepts_valid_paths():
    assert is_workflow_path(".github/workflows/ci.yml")
    assert is_workflow_path(".github/workflows/release.yaml")

def test_is_workflow_path_rejects_other_paths():
    assert not is_workflow_path("README.md")
    assert not is_workflow_path(".github/actions/some-action/action.yml")
    assert not is_workflow_path("src/workflows/ci.yml")

def test_parse_workflow_files_across_multiple_files():
    def load(name):
        with open(f"tests/fixtures/{name}", encoding="utf-8") as f:
            return f.read()

    files = {
        "tests/fixtures/normal_ci.yml": load("normal_ci.yml"),
        "tests/fixtures/risky_pull_request_target.yml": load("risky_pull_request_target.yml"),
    }
    
    repo = RepoRef(owner="test", name="test", default_branch="main", is_private=False)
    
    workflows = []
    for path, content in files.items():
        try:
            workflows.append(parse_workflow_yaml(repo, path, content))
        except Exception:
            pass

    assert len(workflows) == 2
    total_sites = sum(len(wf.uses_sites) for wf in workflows)
    assert total_sites == 7

def test_parse_workflow_files_skips_malformed_without_crashing():
    files = {
        "tests/fixtures/normal_ci.yml": open("tests/fixtures/normal_ci.yml", encoding="utf-8").read(),
        "broken.yml": "this is: not: valid: yaml: [structure",
    }
    
    repo = RepoRef(owner="test", name="test", default_branch="main", is_private=False)
    
    workflows = []
    for path, content in files.items():
        try:
            workflows.append(parse_workflow_yaml(repo, path, content))
        except Exception:
            pass
            
    assert len(workflows) == 1
    assert workflows[0].path == "tests/fixtures/normal_ci.yml"
