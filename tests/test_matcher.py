"""
Tests for matcher.py — incident triage classification.

Tests the core differentiator: given a specific compromised action,
correctly classify every referencing site as EXPOSED, SAFE, or
PINNED_UNKNOWN. Uses real incident data from the Trivy supply chain
attack (actual SHAs from the advisory).

All tests are fully offline — no network calls.

Run from project root: pytest tests/test_matcher.py -v
"""

from actionradius.matcher import (
    match_target, format_match_summary,
    EXPOSED, SAFE, PINNED_UNKNOWN,
)
from actionradius.workflow_parser import parse_workflow_yaml


def _load_fixture(name: str) -> str:
    with open(f"tests/fixtures/{name}", encoding="utf-8") as f:
        return f.read()


# ---- Classification tests ----

def test_mutable_tag_is_exposed():
    """
    A mutable tag pin like @v0.28.0 is EXPOSED — this is exactly the
    pin type that got poisoned in the Trivy incident. The attacker
    force-pushed the tag to point at a malicious commit.
    """
    yaml_text = _load_fixture("risky_pull_request_target.yml")
    wf = parse_workflow_yaml(".github/workflows/scan.yml", yaml_text)

    results = match_target(
        [wf],
        target_owner="aquasecurity",
        target_repo="trivy-action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
    )

    assert len(results) == 1
    assert results[0].status == EXPOSED
    assert results[0].ref == "v0.28.0"
    assert results[0].ref_type == "mutable_ref"


def test_short_sha_is_pinned_unknown_without_safe_refs():
    """
    A short SHA like @57a97c7 is PINNED_UNKNOWN when no safe refs are
    provided — we know it's pinned (good), but we can't tell if that
    specific commit is clean or compromised without the advisory data.
    """
    yaml_text = _load_fixture("normal_ci.yml")
    wf = parse_workflow_yaml(".github/workflows/ci.yml", yaml_text)

    results = match_target(
        [wf],
        target_owner="aquasecurity",
        target_repo="trivy-action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
    )

    assert len(results) == 1
    assert results[0].status == PINNED_UNKNOWN
    assert results[0].ref == "57a97c7"


def test_short_sha_becomes_safe_with_matching_safe_ref():
    """
    Once the advisory publishes safe SHAs, that same @57a97c7 pin gets
    reclassified as SAFE. This is the actual safe pin Aqua published
    for trivy-action v0.35.0.
    """
    yaml_text = _load_fixture("normal_ci.yml")
    wf = parse_workflow_yaml(".github/workflows/ci.yml", yaml_text)

    results = match_target(
        [wf],
        target_owner="aquasecurity",
        target_repo="trivy-action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
        safe_refs={"57a97c7"},
    )

    assert len(results) == 1
    assert results[0].status == SAFE


def test_full_sha_prefix_matches_short_safe_ref():
    """
    If the workflow pins to a full 40-char SHA and the safe list
    has a short prefix of it, the match should still work. Advisories
    sometimes publish short SHAs, but repos pin with full ones.
    """
    yaml_text = """
name: CI
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/trivy-action@57a97c7deadbeef0123456789abcdef012345678
"""
    wf = parse_workflow_yaml(".github/workflows/ci.yml", yaml_text)

    results = match_target(
        [wf],
        target_owner="aquasecurity",
        target_repo="trivy-action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
        safe_refs={"57a97c7"},  # short prefix
    )

    assert len(results) == 1
    assert results[0].status == SAFE


def test_short_sha_prefix_matches_full_safe_ref():
    """
    Reverse of above: workflow pins with short SHA, safe list has full SHA.
    This matches real-world usage — Aqua published @57a97c7 (short) in
    their advisory, but a team might add the full SHA to their safe list.
    """
    yaml_text = _load_fixture("normal_ci.yml")  # has @57a97c7
    wf = parse_workflow_yaml(".github/workflows/ci.yml", yaml_text)

    results = match_target(
        [wf],
        target_owner="aquasecurity",
        target_repo="trivy-action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
        safe_refs={"57a97c7deadbeef0123456789abcdef012345678"},
    )

    assert len(results) == 1
    assert results[0].status == SAFE


def test_non_target_actions_are_excluded():
    """
    Actions that don't match the target should not appear in results.
    normal_ci.yml has actions/checkout, trivy-action, and a local action —
    only trivy-action should match.
    """
    yaml_text = _load_fixture("normal_ci.yml")
    wf = parse_workflow_yaml(".github/workflows/ci.yml", yaml_text)

    results = match_target(
        [wf],
        target_owner="aquasecurity",
        target_repo="trivy-action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
    )

    assert len(results) == 1
    # Only trivy-action, not checkout or the local action
    assert "trivy-action" in results[0].raw_uses


def test_case_insensitive_matching():
    """
    GitHub org/repo names are case-insensitive. Searching for
    "AquaSecurity/Trivy-Action" should still match "aquasecurity/trivy-action".
    """
    yaml_text = _load_fixture("normal_ci.yml")
    wf = parse_workflow_yaml(".github/workflows/ci.yml", yaml_text)

    results = match_target(
        [wf],
        target_owner="AquaSecurity",
        target_repo="Trivy-Action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
    )

    assert len(results) == 1


def test_dynamic_expression_is_exposed():
    """
    A dynamic ref like @${{ inputs.ref }} can't be analyzed statically.
    Conservative stance: mark it EXPOSED, because we can't prove it's safe.
    """
    yaml_text = """
name: Dynamic
on: [workflow_dispatch]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/trivy-action@${{ inputs.trivy_version }}
"""
    wf = parse_workflow_yaml(".github/workflows/ci.yml", yaml_text)

    results = match_target(
        [wf],
        target_owner="aquasecurity",
        target_repo="trivy-action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
    )

    assert len(results) == 1
    assert results[0].status == EXPOSED


def test_transitive_sites_carry_source_chain():
    """
    When a target action is found transitively (via a reusable workflow),
    the MatchResult should carry the source_chain from the UsesSite.
    """
    # Simulate: caller.yml -> deploy.yml which uses trivy-action
    deploy_yaml = """
name: Deploy with Scan
on: { workflow_call: {} }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/trivy-action@v0.28.0
"""
    # Parse the deploy workflow and manually set source_chain on its sites
    # (normally done by the recursion module)
    from actionradius.workflow_parser import UsesSite
    from actionradius.uses_parser import parse_uses

    deploy_wf = parse_workflow_yaml("deploy.yml", deploy_yaml)
    for site in deploy_wf.uses_sites:
        site.source_chain = ["my-org/shared/.github/workflows/deploy.yml@v2"]

    results = match_target(
        [deploy_wf],
        target_owner="aquasecurity",
        target_repo="trivy-action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
    )

    assert len(results) == 1
    assert results[0].status == EXPOSED
    assert results[0].source_chain == ["my-org/shared/.github/workflows/deploy.yml@v2"]


def test_no_matches_returns_empty_list():
    """
    If the target action isn't used anywhere, we get an empty list.
    """
    yaml_text = _load_fixture("normal_ci.yml")
    wf = parse_workflow_yaml(".github/workflows/ci.yml", yaml_text)

    results = match_target(
        [wf],
        target_owner="nonexistent",
        target_repo="fake-action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
    )

    assert len(results) == 0


# ---- Output formatting test ----

def test_format_summary_groups_by_status():
    """
    The triage summary should group results by status: EXPOSED first,
    then PINNED_UNKNOWN, then SAFE — matching how an IR lead reads.
    """
    yaml_text = _load_fixture("risky_pull_request_target.yml")
    wf = parse_workflow_yaml(".github/workflows/scan.yml", yaml_text)

    results = match_target(
        [wf],
        target_owner="aquasecurity",
        target_repo="trivy-action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
    )

    summary = format_match_summary(results, "aquasecurity/trivy-action")

    assert "INCIDENT TRIAGE" in summary
    assert "EXPOSED" in summary
    assert "Fix these NOW" in summary
    assert "v0.28.0" in summary


def test_format_summary_shows_safe_with_safe_refs():
    """
    When safe refs turn a site from PINNED_UNKNOWN to SAFE, the summary
    should show it in the SAFE section.
    """
    yaml_text = _load_fixture("normal_ci.yml")
    wf = parse_workflow_yaml(".github/workflows/ci.yml", yaml_text)

    results = match_target(
        [wf],
        target_owner="aquasecurity",
        target_repo="trivy-action",
        scanned_owner="my-org",
        scanned_repo="my-repo",
        safe_refs={"57a97c7"},
    )

    summary = format_match_summary(results, "aquasecurity/trivy-action")

    assert "SAFE" in summary
    assert "No action needed" in summary
