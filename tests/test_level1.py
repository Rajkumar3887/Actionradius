"""
Level 1 tests — Core Correctness & Incident Exposure Accuracy.
All tests use mocked GitHub API responses. No live API calls.
"""

from unittest.mock import MagicMock, patch
import pytest

from actionradius.models import (
    UsesRef, ResolvedRef, RepoRef, UsesSite, Finding,
    TriggerContext, PermissionsContext, SecretsContext,
)
from actionradius.match.matcher import (
    is_in_bad_range, determine_compromise_status, is_compromised,
)


# --- Helpers ---

def _make_resolved(sha: str | None, ref_type: str = "sha", is_mutable: bool = False,
                   owner: str = "org", repo: str = "action") -> ResolvedRef:
    uses = UsesRef(
        raw=f"{owner}/{repo}@{sha or 'unknown'}",
        owner=owner, repo=repo, path=None,
        ref=sha, ref_type=ref_type,
        is_reusable_workflow=False,
    )
    return ResolvedRef(uses=uses, current_sha=sha, is_mutable=is_mutable)


def _mock_client_compare(responses: dict) -> MagicMock:
    """
    Create a mock GitHubClient where _get returns pre-canned responses
    based on the URL path.
    responses: dict mapping partial URL strings to return values.
    """
    client = MagicMock()
    def side_effect(path, **kwargs):
        for key, val in responses.items():
            if key in path:
                if isinstance(val, Exception):
                    raise val
                return val
        raise ValueError(f"Unmocked path: {path}")
    client._get.side_effect = side_effect
    return client


# --- Test 1: SHA inside compromised range ---

def test_sha_inside_bad_range_is_compromised():
    """A resolved SHA that falls inside the bad commit range → COMPROMISED."""
    client = _mock_client_compare({
        "compare/BAD_FROM...CURRENT_SHA": {"status": "ahead"},    # SHA is after bad_from
        "compare/CURRENT_SHA...BAD_TO":   {"status": "ahead"},    # fix is after SHA
    })
    resolved = _make_resolved("CURRENT_SHA")

    result = is_in_bad_range(client, resolved, "BAD_FROM", "BAD_TO")
    assert result == "COMPROMISED"


# --- Test 2: SHA outside compromised range ---

def test_sha_outside_bad_range_is_safe():
    """A resolved SHA that is before the bad range → SAFE."""
    client = _mock_client_compare({
        "compare/BAD_FROM...SAFE_SHA": {"status": "behind"},  # SHA is before bad_from
    })
    resolved = _make_resolved("SAFE_SHA")

    result = is_in_bad_range(client, resolved, "BAD_FROM", "BAD_TO")
    assert result == "SAFE"


# --- Test 3: Tag resolves to compromised SHA ---

def test_tag_resolving_to_bad_sha_is_compromised():
    """action@v1 → BAD_SHA via tag resolution → COMPROMISED."""
    client = _mock_client_compare({
        "compare/BAD_FROM...BAD_SHA": {"status": "identical"},  # SHA IS the bad commit
        "compare/BAD_SHA...BAD_TO":   {"status": "ahead"},      # fix is after SHA
    })
    # Simulate a tag that already resolved to BAD_SHA
    resolved = _make_resolved("BAD_SHA", ref_type="mutable_ref", is_mutable=True)

    result = is_in_bad_range(client, resolved, "BAD_FROM", "BAD_TO")
    assert result == "COMPROMISED"


# --- Test 4: Tag resolves to safe SHA ---

def test_tag_resolving_to_safe_sha_is_safe():
    """action@v1 → SAFE_SHA (after the fix) → SAFE."""
    client = _mock_client_compare({
        "compare/BAD_FROM...SAFE_SHA": {"status": "ahead"},    # SHA is after bad_from
        "compare/SAFE_SHA...BAD_TO":   {"status": "behind"},   # fix is before SHA → SHA is after fix
    })
    resolved = _make_resolved("SAFE_SHA", ref_type="mutable_ref", is_mutable=True)

    result = is_in_bad_range(client, resolved, "BAD_FROM", "BAD_TO")
    assert result == "SAFE"


# --- Test 5: Unresolvable reference ---

def test_unresolvable_ref_is_unknown():
    """action@unknown with no resolved SHA → UNKNOWN."""
    client = MagicMock()
    resolved = _make_resolved(None, ref_type="unresolvable")

    result = is_in_bad_range(client, resolved, "BAD_FROM", "BAD_TO")
    assert result == "UNKNOWN"


# --- Test 6: Historical exposure ---

def test_historical_exposure_is_unknown_without_history():
    """
    A workflow currently pointing to a safe SHA — without Git history mining,
    historical_exposure must be reported as UNKNOWN, not invented.
    """
    client = _mock_client_compare({
        "compare/BAD_FROM...SAFE_SHA": {"status": "behind"},
    })
    resolved = _make_resolved("SAFE_SHA")

    status = is_in_bad_range(client, resolved, "BAD_FROM", "BAD_TO")
    assert status == "SAFE"

    # Construct a Finding and verify historical_exposure is UNKNOWN
    trigger = TriggerContext([], "low", False)
    perms = PermissionsContext("workflow", "read", {})
    secrets = SecretsContext(False, [], False)
    repo = RepoRef(owner="org", name="repo", default_branch="main", is_private=False)
    site = UsesSite(
        workflow_path=".github/workflows/ci.yml",
        job_id="build", step_index=0,
        uses=resolved.uses, depth=0, source_chain=[],
    )

    finding = Finding(
        repo=repo, uses_site=site, resolved=resolved,
        compromise_status=status,
        historical_exposure="UNKNOWN",
        pin_type=resolved.uses.ref_type,
        trigger=trigger, permissions=perms, secrets=secrets,
        severity="info", score=0.0, rationale="Safe",
    )

    assert finding.historical_exposure == "UNKNOWN"
    assert finding.compromise_status == "SAFE"
    assert finding.is_compromised_version is False


# --- Test 7: CLI validation — mutually exclusive flags ---

def test_cli_rejects_safe_ref_with_bad_range():
    """--safe-ref and --bad-from/--bad-to together must produce exit code 1."""
    from typer.testing import CliRunner
    from actionradius.cli import app

    runner = CliRunner()
    result = runner.invoke(app, [
        "scan",
        "--target", "actions/checkout",
        "--repo", "org/repo",
        "--safe-ref", "abc123",
        "--bad-from", "BAD_FROM",
        "--bad-to", "BAD_TO",
    ])

    assert result.exit_code == 1
    assert "mutually exclusive" in result.output.lower() or "mutually exclusive" in (result.stderr or "").lower()


# --- Test: determine_compromise_status unifies both modes ---

def test_determine_status_uses_bad_range_when_provided():
    """When bad_range is given, determine_compromise_status uses range checking."""
    client = _mock_client_compare({
        "compare/BAD_FROM...SHA": {"status": "ahead"},
        "compare/SHA...BAD_TO":   {"status": "ahead"},
    })
    resolved = _make_resolved("SHA")

    result = determine_compromise_status(
        client, resolved,
        safe_refs=[],
        bad_range={"introduced": "BAD_FROM", "fixed": "BAD_TO"},
    )
    assert result == "COMPROMISED"


def test_determine_status_uses_safe_refs_when_no_range():
    """When only safe_refs is given, falls back to allowlist mode."""
    resolved = _make_resolved("KNOWN_SAFE_SHA")

    result = determine_compromise_status(
        client=None, resolved=resolved,
        safe_refs=["KNOWN_SAFE_SHA"],
        bad_range=None,
    )
    assert result == "SAFE"


def test_determine_status_returns_unknown_when_nothing_provided():
    """When neither safe_refs nor bad_range is given, returns UNKNOWN."""
    resolved = _make_resolved("SOME_SHA")

    result = determine_compromise_status(
        client=None, resolved=resolved,
        safe_refs=[],
        bad_range=None,
    )
    assert result == "UNKNOWN"

def test_mismatch_detector_raises_warning():
    """Verify that an exception in detect_sha_comment_mismatches causes a warning instead of a silent pass."""
    from actionradius.cli import _scan_workflows
    from actionradius.models import RepoRef
    import typer
    
    client = MagicMock()
    repos = [RepoRef("owner", "repo", "main", False)]
    # Mock fetch_workflow_contents to return a dummy workflow
    with patch("actionradius.cli.fetch_workflow_contents") as mock_fetch:
        mock_fetch.return_value = {".github/workflows/ci.yml": "name: CI"}
        with patch("actionradius.cli.parse_workflow_yaml") as mock_parse:
            mock_parse.return_value = MagicMock()
            with patch("actionradius.cli.detect_sha_comment_mismatches") as mock_mismatch:
                mock_mismatch.side_effect = Exception("Simulated API failure")
                with patch("typer.secho") as mock_secho:
                    _scan_workflows(client, repos, "target", [], None, None, [], [])
                    # Check that secho was called with the warning message
                    calls = [call.args[0] for call in mock_secho.call_args_list]
                    assert any("WARNING: SHA/comment mismatch detection failed" in call for call in calls)

def test_exfil_check_raises_warning():
    """Verify that an unexpected exception in check_exfil_repos causes a warning."""
    from actionradius.inventory.repo_lister import check_exfil_repos
    import builtins
    
    client = MagicMock()
    client._get.side_effect = [
        [{"login": "member1"}], # /orgs/myorg/members
        Exception("Unexpected 500 Error") # /repos/member1/tpcp-docs
    ]
    
    with patch("builtins.print") as mock_print:
        hits = check_exfil_repos(client, "myorg")
        calls = [call.args[0] for call in mock_print.call_args_list]
        assert any("WARNING: tpcp-docs check failed" in call for call in calls)
        assert len(hits) == 0

def test_exfil_check_handles_404():
    """Verify that a 404 (ValueError) in check_exfil_repos is handled silently."""
    from actionradius.inventory.repo_lister import check_exfil_repos
    
    client = MagicMock()
    client._get.side_effect = [
        [{"login": "member1"}], # /orgs/myorg/members
        ValueError("Not found") # /repos/member1/tpcp-docs
    ]
    
    with patch("builtins.print") as mock_print:
        hits = check_exfil_repos(client, "myorg")
        assert not mock_print.called
        assert len(hits) == 0
