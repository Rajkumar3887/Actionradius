"""
Tests for report.py — JSON and HTML report generation.

Tests verify that both output formats contain the expected data and
structure, not pixel-perfect output. The key properties:

1. JSON is valid, parseable, and contains the right fields
2. HTML is well-formed and contains severity/status indicators
3. Both formats work for general scans and targeted/matcher scans

Run from project root: pytest tests/test_report.py -v
"""

import json
from actionradius.report import (
    generate_json_general, generate_json_targeted,
    generate_html_general, generate_html_targeted,
)
from actionradius.matcher import match_target, EXPOSED, SAFE, PINNED_UNKNOWN
from actionradius.workflow_parser import parse_workflow_yaml


def _load_fixture(name: str) -> str:
    with open(f"tests/fixtures/{name}", encoding="utf-8") as f:
        return f.read()


def _make_finding(owner, repo, file, severity, score, ref_raw, sha=None, rationale=None):
    """Helper to create a finding dict matching scan_repo's output shape."""
    from actionradius.uses_parser import parse_uses
    from actionradius.workflow_parser import UsesSite

    return {
        "owner": owner,
        "repo": repo,
        "file": file,
        "site": UsesSite(job_id="build", step_index=0, uses=parse_uses(ref_raw)),
        "sha": sha,
        "risk": {
            "score": score,
            "severity": severity,
            "rationale": rationale or [f"Test rationale ({severity})"],
        },
    }


# ---- JSON General Tests ----

def test_json_general_is_valid_json():
    findings = [
        _make_finding("my-org", "my-repo", ".github/workflows/ci.yml",
                       "CRITICAL", 8, "actions/checkout@v4", sha="abc123"),
    ]
    output = generate_json_general(total_sites=10, findings=findings)
    data = json.loads(output)  # should not raise

    assert data["scan_type"] == "general"
    assert data["summary"]["total_sites"] == 10
    assert data["summary"]["mutable_sites"] == 1
    assert data["summary"]["by_severity"]["CRITICAL"] == 1
    assert len(data["findings"]) == 1


def test_json_general_finding_fields():
    findings = [
        _make_finding("my-org", "my-repo", ".github/workflows/ci.yml",
                       "MEDIUM", 3, "actions/checkout@v4", sha="def456"),
    ]
    output = generate_json_general(total_sites=5, findings=findings)
    data = json.loads(output)

    f = data["findings"][0]
    assert f["owner"] == "my-org"
    assert f["repo"] == "my-repo"
    assert f["uses"] == "actions/checkout@v4"
    assert f["resolved_sha"] == "def456"
    assert f["risk"]["severity"] == "MEDIUM"
    assert f["risk"]["score"] == 3


def test_json_general_empty_findings():
    output = generate_json_general(total_sites=7, findings=[])
    data = json.loads(output)

    assert data["summary"]["mutable_sites"] == 0
    assert data["findings"] == []


# ---- JSON Targeted Tests ----

def test_json_targeted_is_valid_json():
    yaml_text = _load_fixture("risky_pull_request_target.yml")
    wf = parse_workflow_yaml(".github/workflows/scan.yml", yaml_text)
    results = match_target([wf], "aquasecurity", "trivy-action", "my-org", "my-repo")

    output = generate_json_targeted("aquasecurity/trivy-action", {"57a97c7"}, results)
    data = json.loads(output)

    assert data["scan_type"] == "targeted"
    assert data["target_action"] == "aquasecurity/trivy-action"
    assert "57a97c7" in data["safe_refs"]
    assert data["summary"]["exposed"] == 1
    assert len(data["matches"]) == 1


def test_json_targeted_match_fields():
    yaml_text = _load_fixture("risky_pull_request_target.yml")
    wf = parse_workflow_yaml(".github/workflows/scan.yml", yaml_text)
    results = match_target([wf], "aquasecurity", "trivy-action", "my-org", "my-repo")

    output = generate_json_targeted("aquasecurity/trivy-action", None, results)
    data = json.loads(output)

    m = data["matches"][0]
    assert m["status"] == "EXPOSED"
    assert m["owner"] == "my-org"
    assert m["ref"] == "v0.28.0"
    assert m["ref_type"] == "mutable_ref"


# ---- HTML General Tests ----

def test_html_general_contains_key_elements():
    findings = [
        _make_finding("my-org", "my-repo", ".github/workflows/ci.yml",
                       "CRITICAL", 8, "actions/checkout@v4", sha="abc123"),
    ]
    html = generate_html_general(total_sites=10, findings=findings, scan_label="my-org/my-repo")

    assert "<!DOCTYPE html>" in html
    assert "ActionRadius" in html
    assert "CRITICAL" in html
    assert "actions/checkout@v4" in html
    assert "my-org/my-repo" in html


def test_html_general_no_findings_shows_clean():
    html = generate_html_general(total_sites=7, findings=[])

    assert "SHA-pinned" in html  # the "all clean" message
    assert "<!DOCTYPE html>" in html


# ---- HTML Targeted Tests ----

def test_html_targeted_contains_triage_sections():
    yaml_text = _load_fixture("risky_pull_request_target.yml")
    wf = parse_workflow_yaml(".github/workflows/scan.yml", yaml_text)
    results = match_target([wf], "aquasecurity", "trivy-action", "my-org", "my-repo")

    html = generate_html_targeted("aquasecurity/trivy-action", {"57a97c7"}, results)

    assert "Incident Triage" in html
    assert "EXPOSED" in html
    assert "Fix these NOW" in html
    assert "v0.28.0" in html


def test_html_targeted_safe_section():
    yaml_text = _load_fixture("normal_ci.yml")
    wf = parse_workflow_yaml(".github/workflows/ci.yml", yaml_text)
    results = match_target([wf], "aquasecurity", "trivy-action", "my-org", "my-repo",
                            safe_refs={"57a97c7"})

    html = generate_html_targeted("aquasecurity/trivy-action", {"57a97c7"}, results)

    assert "SAFE" in html
    assert "No action needed" in html
