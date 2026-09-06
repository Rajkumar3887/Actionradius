import base64
from unittest.mock import MagicMock

from actionradius.inventory.tree_fetcher import (
    is_workflow_path,
    find_workflow_paths,
    fetch_workflow_contents,
)


def test_is_workflow_path_matches_yml_and_yaml():
    assert is_workflow_path(".github/workflows/ci.yml")
    assert is_workflow_path(".github/workflows/ci.yaml")
    assert not is_workflow_path(".github/actions/foo/action.yml")
    assert not is_workflow_path("src/workflows/ci.yml")


def test_find_workflow_paths_filters_tree():
    client = MagicMock()
    client._get.return_value = {
        "truncated": False,
        "tree": [
            {"path": ".github/workflows/ci.yml", "type": "blob"},
            {"path": ".github/workflows/release.yaml", "type": "blob"},
            {"path": "README.md", "type": "blob"},
            {"path": ".github/workflows", "type": "tree"},
        ],
    }
    paths = find_workflow_paths(client, "org", "repo", "main")
    assert paths == [".github/workflows/ci.yml", ".github/workflows/release.yaml"]


def test_fetch_workflow_contents_decodes_base64():
    client = MagicMock()

    def fake_get(path, params=None):
        if "git/trees" in path:
            return {"tree": [{"path": ".github/workflows/ci.yml", "type": "blob"}], "truncated": False}
        content = base64.b64encode(b"name: CI\non: push").decode()
        return {"content": content}

    client._get.side_effect = fake_get
    files = fetch_workflow_contents(client, "org", "repo", "main")
    assert files[".github/workflows/ci.yml"] == "name: CI\non: push"


def test_fetch_workflow_contents_isolates_single_file_failure():
    """One bad file (missing content, decode error, network error, etc.)
    must not lose every other workflow's findings for the repo — mirrors
    the existing behavior in async_tree_fetcher.py's `_fetch_file`."""
    client = MagicMock()

    def fake_get(path, params=None):
        if "git/trees" in path:
            return {
                "tree": [
                    {"path": ".github/workflows/good.yml", "type": "blob"},
                    {"path": ".github/workflows/bad.yml", "type": "blob"},
                ],
                "truncated": False,
            }
        if "bad.yml" in path:
            raise ValueError("Not found: file too large, no content field")
        content = base64.b64encode(b"name: Good\non: push").decode()
        return {"content": content}

    client._get.side_effect = fake_get
    files = fetch_workflow_contents(client, "org", "repo", "main")

    assert ".github/workflows/good.yml" in files
    assert files[".github/workflows/good.yml"] == "name: Good\non: push"
    assert ".github/workflows/bad.yml" not in files


def test_fetch_workflow_contents_warns_on_truncated_tree(capsys):
    client = MagicMock()
    client._get.return_value = {"tree": [], "truncated": True}
    fetch_workflow_contents(client, "org", "repo", "main")
    captured = capsys.readouterr()
    assert "truncated" in captured.out.lower()
