"""
Milestone 1: prove we can talk to GitHub and find workflow files.

Run: python explore.py OWNER REPO

The GitHub token (if you have one) is read from a `.env` file via
python-dotenv — NEVER hardcode a token in a .py file, and NEVER commit
.env to git (that's what .gitignore is for). This mirrors the exact
"static secret in a place attackers/history can reach" problem we've
been discussing about GitHub Actions itself — same principle applies to
your own laptop.
"""
import os
import sys
from dotenv import load_dotenv

sys.path.insert(0, "actionradius")
from github_client import GitHubClient

load_dotenv()  # reads .env in the current folder into os.environ, if present


def find_workflow_files(client: GitHubClient, owner: str, repo: str) -> list[str]:
    repo_info = client.get_repo(owner, repo)
    default_branch = repo_info["default_branch"]
    print(f"{owner}/{repo} — default branch: {default_branch}")

    tree = client.get_full_tree(owner, repo, default_branch)
    print(f"Total files in repo: {len(tree)}")

    # A "workflow file" lives under .github/workflows/ and is a .yml or .yaml file.
    # An "action definition" is action.yml or action.yaml at the repo root or
    # in a subfolder (defines a reusable Action, not a workflow that runs it).
    workflow_files = [
        item["path"] for item in tree
        if item["type"] == "blob"
        and item["path"].startswith(".github/workflows/")
        and (item["path"].endswith(".yml") or item["path"].endswith(".yaml"))
    ]
    return workflow_files


if __name__ == "__main__":
    owner, repo = sys.argv[1], sys.argv[2]
    token = os.environ.get("GITHUB_TOKEN")  # None if not set — client falls back to unauthenticated
    if token:
        print("Using GITHUB_TOKEN from .env (5,000 req/hour)")
    else:
        print("No GITHUB_TOKEN found — running unauthenticated (60 req/hour)")

    client = GitHubClient(token=token)
    files = find_workflow_files(client, owner, repo)

    print(f"\nFound {len(files)} workflow file(s):")
    for f in files:
        print(f"  - {f}")

    print(f"\nRequests remaining this hour: {client.rate_limit_remaining}")
