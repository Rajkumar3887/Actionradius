"""Tests for SARIF ingestion of external linter findings."""

import json
import os
import tempfile
from actionradius.context.external_findings import load_external_sarif, _normalize_workflow_path


def _write_sarif(tmp_dir, sarif_data):
    path = os.path.join(tmp_dir, "findings.sarif")
    with open(path, "w") as f:
        json.dump(sarif_data, f)
    return path


def test_normalize_path_strips_file_scheme():
    assert _normalize_workflow_path("file:///home/user/repo/.github/workflows/ci.yml") == ".github/workflows/ci.yml"


def test_normalize_path_preserves_bare_path():
    assert _normalize_workflow_path(".github/workflows/ci.yml") == ".github/workflows/ci.yml"


def test_normalize_path_prepends_prefix_for_bare_filename():
    assert _normalize_workflow_path("ci.yml") == ".github/workflows/ci.yml"


def test_normalize_path_handles_windows_style():
    # Even on Windows, SARIF URIs use forward slashes
    result = _normalize_workflow_path("file:///C:/repo/.github/workflows/ci.yml")
    assert result == ".github/workflows/ci.yml"


def test_load_external_sarif_basic():
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "zizmor"}},
            "results": [{
                "ruleId": "unpinned-action",
                "message": {"text": "test"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": ".github/workflows/ci.yml"},
                        "region": {"startLine": 10}
                    }
                }]
            }]
        }]
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(tmp, sarif)
        result = load_external_sarif(path)
    assert ".github/workflows/ci.yml" in result


def test_load_external_sarif_multiple_runs():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "zizmor"}},
                "results": [{
                    "ruleId": "rule1",
                    "message": {"text": "test"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/a.yml"}}}]
                }]
            },
            {
                "tool": {"driver": {"name": "poutine"}},
                "results": [{
                    "ruleId": "rule2",
                    "message": {"text": "test"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/b.yml"}}}]
                }]
            }
        ]
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(tmp, sarif)
        result = load_external_sarif(path)
    assert ".github/workflows/a.yml" in result
    assert ".github/workflows/b.yml" in result


def test_load_external_sarif_file_uri():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "zizmor"}},
            "results": [{
                "ruleId": "rule1",
                "message": {"text": "test"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///home/user/repo/.github/workflows/deploy.yml"}}}]
            }]
        }]
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(tmp, sarif)
        result = load_external_sarif(path)
    assert ".github/workflows/deploy.yml" in result


def test_load_external_sarif_empty_results():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "zizmor"}},
            "results": []
        }]
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(tmp, sarif)
        result = load_external_sarif(path)
    assert len(result) == 0

from actionradius.context.external_findings import load_external_sarif_repo_scoped

def test_load_external_sarif_repo_scoped_success():
    sarif = {
        "runs": [{
            "versionControlProvenance": [{
                "repositoryUri": "https://github.com/myorg/myrepo",
                "mappedTo": {"uriBaseId": "SRCROOT"}
            }],
            "results": [{
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": ".github/workflows/ci.yml",
                    "uriBaseId": "SRCROOT"
                }}}]
            }]
        }]
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(tmp, sarif)
        res = load_external_sarif_repo_scoped(path)
    assert res is not None
    assert "myorg/myrepo:.github/workflows/ci.yml" in res


def test_load_external_sarif_repo_scoped_with_git_suffix():
    sarif = {
        "runs": [{
            "versionControlProvenance": [{
                "repositoryUri": "https://github.com/myorg/myrepo.git",
                "mappedTo": {"uriBaseId": "SRCROOT"}
            }],
            "results": [{
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": "deploy.yml",
                    "uriBaseId": "SRCROOT"
                }}}]
            }]
        }]
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(tmp, sarif)
        res = load_external_sarif_repo_scoped(path)
    assert res is not None
    assert "myorg/myrepo:.github/workflows/deploy.yml" in res


def test_load_external_sarif_repo_scoped_no_mapped_to():
    sarif = {
        "runs": [{
            "versionControlProvenance": [{
                "repositoryUri": "https://github.com/myorg/myrepo"
            }],
            "results": [{
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": ".github/workflows/ci.yml"
                }}}]
            }]
        }]
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(tmp, sarif)
        res = load_external_sarif_repo_scoped(path)
    # Should bail because the result doesn't have a uriBaseId mapping
    assert res is None


def test_load_external_sarif_repo_scoped_partial_failure_bails():
    sarif = {
        "runs": [{
            "versionControlProvenance": [{
                "repositoryUri": "https://github.com/myorg/myrepo",
                "mappedTo": {"uriBaseId": "SRCROOT"}
            }],
            "results": [
                {
                    "locations": [{"physicalLocation": {"artifactLocation": {
                        "uri": ".github/workflows/ci.yml",
                        "uriBaseId": "SRCROOT"
                    }}}]
                },
                {
                    "locations": [{"physicalLocation": {"artifactLocation": {
                        "uri": ".github/workflows/deploy.yml"
                        # missing uriBaseId
                    }}}]
                }
            ]
        }]
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(tmp, sarif)
        res = load_external_sarif_repo_scoped(path)
    # The whole thing should return None if even one result can't be tied
    assert res is None
