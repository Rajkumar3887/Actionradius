import re
from typing import Literal
from actionradius.models import UsesRef

RefType = Literal["sha", "tag", "branch", "local", "unresolvable", "mutable_ref", "docker", "docker_digest"]

_HEX_SHA_PATTERN = re.compile(r"^[0-9a-f]{7,40}$")

def parse_uses(raw: str) -> UsesRef:
    raw = raw.strip()

    if raw.startswith("./") or raw.startswith("../"):
        return UsesRef(
            raw=raw, owner=None, repo=None, path=raw, ref=None,
            ref_type="local", is_reusable_workflow=False
        )

    if raw.startswith("docker://"):
        image_part = raw[len("docker://"):]
        ref_type = "docker"
        ref = "latest"
        repo = image_part
        if "@sha256:" in image_part:
            repo, ref = image_part.split("@", 1)
            ref_type = "docker_digest"
        elif ":" in image_part:
            repo, ref = image_part.split(":", 1)

        return UsesRef(
            raw=raw, owner="_docker", repo=repo, path=None, ref=ref,
            ref_type=ref_type, is_reusable_workflow=False
        )

    if "@" not in raw:
        return UsesRef(
            raw=raw, owner=None, repo=None, path=None, ref=None,
            ref_type="unresolvable", is_reusable_workflow=False
        )

    location, ref = raw.rsplit("@", 1)

    if "${{" in ref:
        return UsesRef(
            raw=raw, owner=None, repo=None, path=location, ref=ref,
            ref_type="unresolvable", is_reusable_workflow=False
        )

    parts = location.split("/")
    if len(parts) < 2:
        return UsesRef(
            raw=raw, owner=None, repo=None, path=location, ref=ref,
            ref_type="unresolvable", is_reusable_workflow=False
        )

    owner, repo = parts[0], parts[1]
    path = "/".join(parts[2:]) if len(parts) > 2 else None

    is_reusable_workflow = path is not None and (path.endswith(".yml") or path.endswith(".yaml"))

    if _HEX_SHA_PATTERN.match(ref.lower()):
        ref_type: RefType = "sha"
    else:
        ref_type = "mutable_ref"

    return UsesRef(
        raw=raw, owner=owner, repo=repo, path=path, ref=ref,
        ref_type=ref_type, is_reusable_workflow=is_reusable_workflow
    )
