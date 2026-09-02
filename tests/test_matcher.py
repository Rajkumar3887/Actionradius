"""
Tests for matcher module — is_match, is_compromised, is_in_bad_range, determine_compromise_status.
Uses mocked GitHub API responses.
"""

from unittest.mock import MagicMock
from actionradius.models import UsesRef, ResolvedRef, UsesSite
from actionradius.match.matcher import (
    is_match, is_compromised, is_in_bad_range, determine_compromise_status,
)


def _site(owner: str, repo: str) -> UsesSite:
    return UsesSite(
        workflow_path=".github/workflows/ci.yml",
        job_id="build",
        step_index=0,
        uses=UsesRef(
            raw=f"{owner}/{repo}@v1",
            owner=owner, repo=repo, path=None, ref="v1",
            ref_type="mutable_ref", is_reusable_workflow=False,
        ),
        depth=0,
        source_chain=[],
    )


def _resolved(sha: str | None, owner="org", repo="action", is_mutable=False) -> ResolvedRef:
    uses = UsesRef(
        raw=f"{owner}/{repo}@{sha or 'unknown'}",
        owner=owner, repo=repo, path=None,
        ref=sha, ref_type="sha" if sha else "unresolvable",
        is_reusable_workflow=False,
    )
    return ResolvedRef(uses=uses, current_sha=sha, is_mutable=is_mutable)


# --- is_match ---

def test_is_match_exact():
    assert is_match(_site("actions", "checkout"), "actions/checkout") is True

def test_is_match_case_insensitive():
    assert is_match(_site("Actions", "Checkout"), "actions/checkout") is True

def test_is_match_wrong_action():
    assert is_match(_site("actions", "checkout"), "actions/setup-node") is False

def test_is_match_no_owner():
    site = _site("actions", "checkout")
    site.uses.owner = None
    assert is_match(site, "actions/checkout") is False


# --- is_compromised (safe-ref mode) ---

def test_compromised_without_safe_refs():
    resolved = _resolved("abc123")
    assert is_compromised(resolved, []) is True

def test_safe_ref_exact_match():
    resolved = _resolved("abc123")
    assert is_compromised(resolved, ["abc123"]) is False

def test_safe_ref_prefix_match():
    resolved = _resolved("abc123def456")
    assert is_compromised(resolved, ["abc123"]) is False

def test_compromised_when_not_in_safe_list():
    resolved = _resolved("abc123")
    assert is_compromised(resolved, ["zzz999"]) is True


# --- is_in_bad_range ---

def test_bad_range_sha_inside():
    client = MagicMock()
    client._get.side_effect = lambda path, **kw: (
        {"status": "ahead"} if "BAD_FROM" in path else {"status": "ahead"}
    )
    result = is_in_bad_range(client, _resolved("VICTIM_SHA"), "BAD_FROM", "BAD_TO")
    assert result == "COMPROMISED"

def test_bad_range_sha_before():
    client = MagicMock()
    client._get.return_value = {"status": "behind"}
    result = is_in_bad_range(client, _resolved("SAFE_SHA"), "BAD_FROM", "BAD_TO")
    assert result == "SAFE"

def test_bad_range_unresolvable():
    client = MagicMock()
    result = is_in_bad_range(client, _resolved(None), "BAD_FROM", "BAD_TO")
    assert result == "UNKNOWN"

def test_bad_range_api_error():
    client = MagicMock()
    client._get.side_effect = Exception("API error")
    result = is_in_bad_range(client, _resolved("SHA"), "BAD_FROM", "BAD_TO")
    assert result == "UNKNOWN"


# --- determine_compromise_status ---

def test_determine_prefers_bad_range_over_safe_refs():
    client = MagicMock()
    client._get.return_value = {"status": "behind"}
    result = determine_compromise_status(
        client, _resolved("SHA"),
        safe_refs=["other"],
        bad_range={"introduced": "BAD_FROM", "fixed": "BAD_TO"},
    )
    assert result == "SAFE"  # bad_range says safe, even though safe_refs would say compromised

def test_determine_falls_back_to_safe_refs():
    result = determine_compromise_status(
        None, _resolved("KNOWN_SAFE"),
        safe_refs=["KNOWN_SAFE"],
        bad_range=None,
    )
    assert result == "SAFE"

def test_determine_unknown_when_nothing_provided():
    result = determine_compromise_status(
        None, _resolved("SHA"),
        safe_refs=[],
        bad_range=None,
    )
    assert result == "UNKNOWN"
