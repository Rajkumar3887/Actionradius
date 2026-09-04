import json
import os
import tempfile
from actionradius.models import (
    Finding,
    PermissionsContext,
    RepoRef,
    ResolvedRef,
    SecretsContext,
    TriggerContext,
    UsesRef,
    UsesSite,
)
from actionradius.report.html_report import generate_html_report
from actionradius.report.json_report import generate_json_report


def _create_sample_finding() -> Finding:
    repo = RepoRef(owner="test-org", name="test-repo", default_branch="main", is_private=False)
    uses = UsesRef(
        raw="actions/checkout@v4",
        owner="actions",
        repo="checkout",
        path=None,
        ref="v4",
        ref_type="mutable_ref",
        is_reusable_workflow=False,
    )
    site = UsesSite(
        workflow_path=".github/workflows/ci.yml",
        job_id="build",
        step_index=0,
        uses=uses,
        depth=0,
        source_chain=[],
    )
    resolved = ResolvedRef(uses=uses, current_sha="abc123", is_mutable=True)
    trigger = TriggerContext(events=["push"], risk="low", fork_reachable=False)
    perms = PermissionsContext(scope="workflow", contents="read", raw={})
    secrets = SecretsContext(inherits_all=False, explicit_secrets=[], has_real_secrets=False)

    return Finding(
        repo=repo,
        uses_site=site,
        resolved=resolved,
        compromise_status="UNKNOWN",
        historical_exposure="UNKNOWN",
        pin_type="mutable_ref",
        trigger=trigger,
        permissions=perms,
        secrets=secrets,
        severity="medium",
        score=4.0,
        rationale="Test rationale",
        publisher_trust="established",
    )


def test_json_report_writes_valid_json():
    finding = _create_sample_finding()
    tmp_path = tempfile.mktemp(suffix=".json")
    try:
        generate_json_report([finding], tmp_path)
        with open(tmp_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["repo"]["owner"] == "test-org"
        assert data[0]["publisher_trust"] == "established"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_html_report_contains_repo_name():
    finding = _create_sample_finding()
    tmp_path = tempfile.mktemp(suffix=".html")
    try:
        generate_html_report([finding], tmp_path, "test-action")
        with open(tmp_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "test-repo" in content
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
