"""
Comment/SHA mismatch detector.

Catches the exact technique used in the March 2026 Trivy binary attack:
  uses: actions/checkout@70379aad1a8b40919ce8b382d3cd7d0315cde1d0 # v6.0.2

The inline comment says v6.0.2, but the SHA does not correspond to v6.0.2.
This detects when a pinned SHA contradicts its own version comment — a strong
indicator that someone swapped the SHA while leaving the comment to fool reviewers.
"""

import re
from dataclasses import dataclass
from actionradius.github_client import GitHubClient

# Matches lines like:
#   uses: owner/repo@<40-hex-sha> # v1.2.3
#   uses: owner/repo@<40-hex-sha> # tag-name
_USES_SHA_COMMENT_RE = re.compile(
    r"uses:\s+"
    r"(?P<owner>[a-zA-Z0-9_.-]+)/(?P<repo>[a-zA-Z0-9_.-]+)"
    r"@(?P<sha>[0-9a-fA-F]{40})"
    r"\s+#\s*(?P<comment_tag>\S+)"
)


@dataclass
class SHACommentMismatch:
    owner: str
    repo: str
    pinned_sha: str
    comment_tag: str
    actual_tag_sha: str | None     # What the tag actually resolves to
    workflow_path: str
    line_number: int


def detect_sha_comment_mismatches(
    client: GitHubClient,
    workflow_path: str,
    raw_yaml: str,
) -> list[SHACommentMismatch]:
    """
    Scan raw YAML text for uses: lines where a SHA pin has an inline
    comment claiming a version tag, and verify whether the SHA actually
    matches what that tag resolves to.
    """
    mismatches = []

    for line_num, line in enumerate(raw_yaml.splitlines(), start=1):
        match = _USES_SHA_COMMENT_RE.search(line)
        if not match:
            continue

        owner = match.group("owner")
        repo = match.group("repo")
        pinned_sha = match.group("sha").lower()
        comment_tag = match.group("comment_tag")

        # Resolve the tag to see what SHA it actually points to
        actual_sha = _resolve_tag_sha(client, owner, repo, comment_tag)

        if actual_sha is None:
            # Tag doesn't exist or can't be resolved — suspicious but not a mismatch
            continue

        if actual_sha.lower() != pinned_sha:
            mismatches.append(SHACommentMismatch(
                owner=owner,
                repo=repo,
                pinned_sha=pinned_sha,
                comment_tag=comment_tag,
                actual_tag_sha=actual_sha,
                workflow_path=workflow_path,
                line_number=line_num,
            ))

    return mismatches


def _resolve_tag_sha(client: GitHubClient, owner: str, repo: str, tag: str) -> str | None:
    """
    Resolve a tag name to the commit SHA it actually points to, via the Git
    Refs API.

    Annotated tags are dereferenced to their target commit (mirroring
    resolve/ref_resolver.py's handling) — a lightweight tag's ref object
    already points straight at a commit, but an annotated tag's ref object
    points at a separate tag object whose own `sha` is *not* a commit SHA.
    Comparing that tag-object SHA against a `uses:` pin (which must always
    be a commit Sha per GitHub Actions' own pinning requirements) would
    produce a false "mismatch" for every annotated tag, regardless of
    whether the pin is actually correct — undermining the one check this
    module exists to run.
    """
    try:
        data = client._get(f"/repos/{owner}/{repo}/git/ref/tags/{tag}")
        obj = data.get("object")
        if not obj or "sha" not in obj:
            return None

        sha = obj["sha"]
        if obj.get("type") == "tag":
            try:
                tag_data = client._get(f"/repos/{owner}/{repo}/git/tags/{sha}")
                tag_obj = tag_data.get("object")
                if tag_obj and "sha" in tag_obj:
                    sha = tag_obj["sha"]
            except Exception:
                pass  # Keep the tag-object SHA if dereferencing fails
        return sha
    except Exception:
        pass
    return None
