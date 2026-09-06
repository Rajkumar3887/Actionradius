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
from actionradius.report.graph_report import generate_graph_report, _dot_escape


def _create_sample_finding(repo_name="test-repo", secret_names=None, fork_reachable=False, inherits_all=False) -> Finding:
    repo = RepoRef(owner="test-org", name=repo_name, default_branch="main", is_private=False)
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
    trigger = TriggerContext(events=["push"], risk="low", fork_reachable=fork_reachable)
    perms = PermissionsContext(scope="workflow", contents="read", raw={})
    secrets = SecretsContext(
        inherits_all=inherits_all,
        explicit_secrets=secret_names or [],
        has_real_secrets=bool(secret_names) or inherits_all,
    )

    return Finding(
        repo=repo,
        uses_site=site,
        resolved=resolved,
        compromise_status="COMPROMISED",
        historical_exposure="UNKNOWN",
        pin_type="mutable_ref",
        trigger=trigger,
        permissions=perms,
        secrets=secrets,
        severity="high",
        score=7.5,
        rationale="Test rationale",
        publisher_trust="established",
    )


def test_dot_escape_handles_quotes_and_backslashes():
    assert _dot_escape('evil"name') == 'evil\\"name'
    assert _dot_escape("back\\slash") == "back\\\\slash"
    assert _dot_escape("plain-name") == "plain-name"


def test_graph_report_generates_valid_structure():
    finding = _create_sample_finding(secret_names=["DEPLOY_TOKEN"])
    tmp_path = tempfile.mktemp(suffix=".dot")
    try:
        generate_graph_report([finding], tmp_path, "actions/checkout")
        with open(tmp_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert content.startswith("digraph BlastRadius {")
        assert content.strip().endswith("}")
        assert "test-org/test-repo" in content
        assert "DEPLOY_TOKEN" in content
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_graph_report_escapes_quotes_in_repo_and_secret_names():
    """A repo or secret name containing a double quote must not be able to
    break out of a DOT quoted string and inject extra graph statements."""
    finding = _create_sample_finding(
        repo_name='evil" -> "injected_node" [label="pwned',
        secret_names=['FOO" -> "also_injected'],
    )
    tmp_path = tempfile.mktemp(suffix=".dot")
    try:
        generate_graph_report([finding], tmp_path, "actions/checkout")
        with open(tmp_path, "r", encoding="utf-8") as f:
            content = f.read()
        # No unescaped `" -> "` sequence should appear (that's the DOT edge
        # syntax an injected quote could smuggle in).
        assert '" -> "injected_node' not in content
        assert '" -> "also_injected' not in content
        # The escaped quote should be present instead.
        assert '\\"' in content
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_graph_report_handles_inherit_all_secrets():
    finding = _create_sample_finding(inherits_all=True)
    tmp_path = tempfile.mktemp(suffix=".dot")
    try:
        generate_graph_report([finding], tmp_path, "actions/checkout")
        with open(tmp_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "INHERIT ALL" in content
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_graph_report_handles_fork_reachable_trigger():
    finding = _create_sample_finding(fork_reachable=True)
    tmp_path = tempfile.mktemp(suffix=".dot")
    try:
        generate_graph_report([finding], tmp_path, "actions/checkout")
        with open(tmp_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Fork-Reachable Trigger" in content
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_graph_report_dedupes_repeated_repo_nodes():
    """The same repo appearing in multiple findings should only get one node
    definition, even though its name is now escaped before being written."""
    f1 = _create_sample_finding(secret_names=["A"])
    f2 = _create_sample_finding(secret_names=["B"])
    tmp_path = tempfile.mktemp(suffix=".dot")
    try:
        generate_graph_report([f1, f2], tmp_path, "actions/checkout")
        with open(tmp_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert content.count('"test-org/test-repo" [shape=box') == 1
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
