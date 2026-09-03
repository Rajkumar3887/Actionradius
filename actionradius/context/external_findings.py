"""Parse SARIF output from external linters (zizmor, poutine) into a lookup."""

import json


def _normalize_workflow_path(uri: str) -> str:
    """
    Normalize a SARIF artifactLocation URI to a bare workflow path.

    Different tools use different URI conventions:
    - zizmor: "file:///path/to/.github/workflows/ci.yml" or ".github/workflows/ci.yml"
    - poutine: ".github/workflows/ci.yml" or "ci.yml"

    We want to normalize to ".github/workflows/ci.yml".
    """
    # Strip file:// scheme
    if uri.startswith("file:///"):
        uri = uri[len("file:///"):]
    elif uri.startswith("file://"):
        uri = uri[len("file://"):]

    # Find the .github/workflows/ part and take from there
    marker = ".github/workflows/"
    idx = uri.find(marker)
    if idx != -1:
        return uri[idx:]

    # If no marker found, assume it's just the filename and prepend
    # Only do this if it looks like a workflow file
    if uri.endswith((".yml", ".yaml")) and "/" not in uri:
        return f".github/workflows/{uri}"

    return uri


def load_external_sarif(sarif_path: str) -> set[str]:
    """
    Parse a SARIF file and return a set of workflow paths that have findings.

    Works with SARIF 2.1.0 output from zizmor, poutine, or any compatible scanner.
    Returns normalized workflow paths (e.g. ".github/workflows/ci.yml").
    """
    with open(sarif_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    tainted_paths: set[str] = set()

    for run in data.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                physical = location.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                uri = artifact.get("uri", "")
                if uri:
                    normalized = _normalize_workflow_path(uri)
                    tainted_paths.add(normalized)

    return tainted_paths
