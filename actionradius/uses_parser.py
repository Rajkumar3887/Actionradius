"""
uses_parser.py

Turns a raw `uses:` string from a workflow file into structured data we
can reason about. This is the single most important piece of the whole
tool — everything downstream depends on classifying these correctly.

Examples of what we need to handle:

    actions/checkout@v4
        -> owner=actions, repo=checkout, path=None, ref=v4, mutable (tag or branch — can't tell yet)

    actions/checkout@8410ad0592bd1c1ecd1912536d6bee2b5a4a0e5b
        -> full 40-char SHA — fully pinned, immutable

    aquasecurity/trivy-action@57a97c7
        -> a SHORT sha (7 chars). This is real: the Trivy team's own
           "safe version" advisory pinned trivy-action this way. Short
           SHAs ARE effectively immutable pins (unlike tags/branches,
           nobody can retarget a commit hash), but GitHub's own guidance
           still calls out FULL 40-char SHAs as the gold standard, since
           short hashes are marginally less explicit/verifiable. We'll
           track both as "sha" but flag is_full_sha separately, so our
           scoring can treat them slightly differently later.

    ./.github/actions/local-action
        -> local to the repo, not a third-party dependency at all

    org/repo/.github/workflows/build.yml@v1
        -> a REUSABLE WORKFLOW call, not an Action. Note the path ends
           in .yml/.yaml under .github/workflows/ — that's the tell.

    actions/checkout@${{ inputs.checkout_ref }}
        -> a dynamic expression. We can't resolve this from the YAML
           alone at all — flag it and move on, don't guess.
"""

import re
from dataclasses import dataclass
from typing import Literal, Optional

RefType = Literal["sha", "local", "unresolvable", "mutable_ref"]

# A ref is "probably a SHA" if it's 7-40 hex characters. Full SHAs are
# always 40; short SHAs (common in practice, e.g. `git rev-parse --short`)
# are usually 7-12. We accept the whole range.
_HEX_SHA_PATTERN = re.compile(r"^[0-9a-f]{7,40}$")


@dataclass
class UsesRef:
    raw: str
    owner: Optional[str]
    repo: Optional[str]
    path: Optional[str]           # subdirectory action, or a workflow file path
    ref: Optional[str]            # the part after @  (None for local refs)
    ref_type: RefType
    is_full_sha: bool             # only meaningful when ref_type == "sha"
    is_reusable_workflow: bool    # True if this calls a reusable workflow, not an Action


def parse_uses(raw: str) -> UsesRef:
    raw = raw.strip()

    # --- Case 1: local reference, e.g. "./.github/actions/my-action" ---
    if raw.startswith("./") or raw.startswith("../"):
        return UsesRef(
            raw=raw, owner=None, repo=None, path=raw, ref=None,
            ref_type="local", is_full_sha=False, is_reusable_workflow=False,
        )

    # --- Split off the "@ref" suffix ---
    if "@" not in raw:
        # Every third-party `uses:` must have an @ref. If it doesn't,
        # something's malformed or it's a syntax we don't recognize yet —
        # don't guess, flag it honestly.
        return UsesRef(
            raw=raw, owner=None, repo=None, path=None, ref=None,
            ref_type="unresolvable", is_full_sha=False, is_reusable_workflow=False,
        )

    location, ref = raw.rsplit("@", 1)

    # --- Case 2: dynamic expression as the ref, e.g. @${{ inputs.x }} ---
    if "${{" in ref:
        return UsesRef(
            raw=raw, owner=None, repo=None, path=location, ref=ref,
            ref_type="unresolvable", is_full_sha=False, is_reusable_workflow=False,
        )

    # --- Parse "owner/repo" or "owner/repo/sub/path" ---
    parts = location.split("/")
    if len(parts) < 2:
        return UsesRef(
            raw=raw, owner=None, repo=None, path=location, ref=ref,
            ref_type="unresolvable", is_full_sha=False, is_reusable_workflow=False,
        )

    owner, repo = parts[0], parts[1]
    path = "/".join(parts[2:]) if len(parts) > 2 else None

    is_reusable_workflow = path is not None and (path.endswith(".yml") or path.endswith(".yaml"))

    # --- Classify the ref itself ---
    if _HEX_SHA_PATTERN.match(ref.lower()):
        ref_type: RefType = "sha"
        is_full_sha = len(ref) == 40
    else:
        ref_type = "mutable_ref"
        is_full_sha = False

    return UsesRef(
        raw=raw, owner=owner, repo=repo, path=path, ref=ref,
        ref_type=ref_type, is_full_sha=is_full_sha, is_reusable_workflow=is_reusable_workflow,
    )
