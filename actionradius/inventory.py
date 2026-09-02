"""
inventory.py

Wires together everything built so far: list workflow files in a repo,
fetch each one's content, parse them all, then follow reusable workflow
calls to discover transitive dependencies.

Deliberately split into two layers:
  - is_workflow_path() / parse_workflow_files() — pure logic, no network,
    fully unit-testable with fixtures (see test_inventory.py).
  - find_workflow_paths() / inventory_repo() — the thin wrapper that
    actually talks to GitHub. We don't unit-test this part directly
    (that's what running scan.py against a real repo is for); keeping
    it thin means there's very little here that COULD be wrong.
"""

from actionradius.github_client import GitHubClient
from actionradius.workflow_parser import ParsedWorkflow, parse_workflow_yaml
from actionradius.recursion import resolve_reusable_workflows


def is_workflow_path(path: str) -> bool:
    return path.startswith(".github/workflows/") and (path.endswith(".yml") or path.endswith(".yaml"))


def parse_workflow_files(files: dict[str, str]) -> list[ParsedWorkflow]:
    """Pure function: {path: yaml_text} -> parsed workflows. No network I/O."""
    parsed_workflows = []
    for path, content in files.items():
        try:
            parsed_workflows.append(parse_workflow_yaml(path, content))
        except Exception as e:
            # One malformed workflow shouldn't kill the whole scan — flag it and move on.
            print(f"  WARNING: couldn't parse {path}: {e}")
    return parsed_workflows


def find_workflow_paths(client: GitHubClient, owner: str, repo: str, branch: str) -> list[str]:
    tree = client.get_full_tree(owner, repo, branch)
    return [item["path"] for item in tree if item["type"] == "blob" and is_workflow_path(item["path"])]


def inventory_repo(client: GitHubClient, owner: str, repo: str) -> list[ParsedWorkflow]:
    repo_info = client.get_repo(owner, repo)
    default_branch = repo_info["default_branch"]

    workflow_paths = find_workflow_paths(client, owner, repo, default_branch)

    files = {path: client.get_file_content(owner, repo, path, ref=default_branch) for path in workflow_paths}
    workflows = parse_workflow_files(files)

    # Follow reusable workflow calls to find transitive action dependencies.
    # Depth-capped at 2 levels by default — see recursion.py for details.
    workflows = resolve_reusable_workflows(client, workflows, max_depth=2)

    return workflows