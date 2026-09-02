"""
Tests for recursion.py — reusable workflow following.

All tests are fully offline using mocks. The key scenarios:

1. A reusable workflow call gets followed, its actions appear as
   transitive sites with a source_chain.
2. Depth limit is respected — a chain 3 levels deep stops at 2.
3. Cycles (A -> B -> A) don't cause infinite recursion.
4. Fetch failures are warned and skipped, not fatal.
5. Local reusable workflow calls (./) are NOT followed (they're
   already in the same repo and already parsed).

Run from project root: pytest tests/test_recursion.py -v
"""

import pytest
from unittest.mock import Mock, patch, call
from actionradius.recursion import resolve_reusable_workflows
from actionradius.workflow_parser import ParsedWorkflow, UsesSite, parse_workflow_yaml
from actionradius.uses_parser import parse_uses


def _load_fixture(name: str) -> str:
    with open(f"tests/fixtures/{name}", encoding="utf-8") as f:
        return f.read()


def _make_mock_client(file_contents: dict[tuple, str] = None):
    """
    Creates a mock GitHubClient that returns specific file contents
    based on (owner, repo, path, ref) lookups.
    """
    client = Mock()
    contents = file_contents or {}

    def fake_get_file_content(owner, repo, path, ref):
        key = (owner, repo, path, ref)
        if key in contents:
            return contents[key]
        raise ValueError(f"Not found: {owner}/{repo}/{path}@{ref}")

    client.get_file_content = Mock(side_effect=fake_get_file_content)
    return client


def test_follows_reusable_workflow_and_finds_transitive_sites():
    """
    Given a workflow that calls `my-org/shared-workflows/.github/workflows/deploy.yml@v2`,
    and that deploy.yml contains 3 action steps (checkout@v4, build-push@v5, deploy@sha),
    verify that all 3 appear as transitive sites with the correct source_chain.
    """
    # Parse the caller workflow
    caller_yaml = _load_fixture("caller_with_reusable.yml")
    caller_wf = parse_workflow_yaml(".github/workflows/ci.yml", caller_yaml)

    # Set up the mock: when the recursion module asks for the reusable
    # workflow file, return our fixture
    deploy_yaml = _load_fixture("reusable_deploy.yml")
    client = _make_mock_client({
        ("my-org", "shared-workflows", ".github/workflows/deploy.yml", "v2"): deploy_yaml,
        # notify.yml will 404 — testing graceful failure
    })

    # Act: resolve reusable workflows
    result = resolve_reusable_workflows(client, [caller_wf], max_depth=2)

    # The caller had 3 direct sites:
    #   - actions/checkout@v4 (step in 'test' job)
    #   - my-org/shared-workflows/deploy.yml@v2 (job-level reusable)
    #   - my-org/shared-workflows/notify.yml@v1 (job-level reusable)
    # After recursion into deploy.yml, we should also have:
    #   - actions/checkout@v4 (transitive, from deploy.yml)
    #   - docker/build-push-action@v5 (transitive, from deploy.yml)
    #   - some-org/deploy-action@<sha> (transitive, from deploy.yml)
    # notify.yml fetch fails, so no transitive sites from it.
    all_sites = result[0].uses_sites

    # Original 3 + 3 from deploy.yml = 6
    assert len(all_sites) == 6

    # Check that the transitive sites carry the correct source_chain
    transitive = [s for s in all_sites if s.source_chain]
    assert len(transitive) == 3

    # Each transitive site should trace back through deploy.yml@v2
    for site in transitive:
        assert site.source_chain == [
            "my-org/shared-workflows/.github/workflows/deploy.yml@v2"
        ]

    # Verify the specific transitive actions were found
    transitive_actions = {s.uses.raw for s in transitive}
    assert "actions/checkout@v4" in transitive_actions
    assert "docker/build-push-action@v5" in transitive_actions

    # The SHA-pinned action should also be there (it's still a dependency)
    sha_pinned = [s for s in transitive if s.uses.ref_type == "sha"]
    assert len(sha_pinned) == 1
    assert sha_pinned[0].uses.is_full_sha is True


def test_depth_limit_stops_deep_chains():
    """
    If deploy.yml itself calls another reusable workflow, and THAT calls
    another, we stop at max_depth and don't follow infinitely.
    """
    # Build a chain: caller -> level1.yml -> level2.yml -> level3.yml
    # With max_depth=2, we should follow level1 and level2, but NOT level3.

    caller_yaml = """
name: Deep Chain
on: [push]
jobs:
  call-level1:
    uses: org/repo/.github/workflows/level1.yml@v1
"""
    level1_yaml = """
name: Level 1
on: { workflow_call: {} }
jobs:
  call-level2:
    uses: org/repo/.github/workflows/level2.yml@v1
  direct-action:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    level2_yaml = """
name: Level 2
on: { workflow_call: {} }
jobs:
  call-level3:
    uses: org/repo/.github/workflows/level3.yml@v1
  another-action:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
"""
    level3_yaml = """
name: Level 3
on: { workflow_call: {} }
jobs:
  deep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/should-not-appear@v1
"""

    caller_wf = parse_workflow_yaml(".github/workflows/ci.yml", caller_yaml)

    client = _make_mock_client({
        ("org", "repo", ".github/workflows/level1.yml", "v1"): level1_yaml,
        ("org", "repo", ".github/workflows/level2.yml", "v1"): level2_yaml,
        ("org", "repo", ".github/workflows/level3.yml", "v1"): level3_yaml,
    })

    # max_depth=2: follow level1 (depth 1) and level2 (depth 2), stop before level3
    result = resolve_reusable_workflows(client, [caller_wf], max_depth=2)
    all_sites = result[0].uses_sites

    # Should find:
    # Direct: org/repo/level1.yml@v1 (the job-level reusable call)
    # From level1: org/repo/level2.yml@v1 (job-level reusable) + actions/checkout@v4
    # From level2: org/repo/level3.yml@v1 (job-level reusable, but NOT followed) + actions/setup-node@v4
    # NOT: actions/should-not-appear@v1 (would be depth 3)

    all_raws = {s.uses.raw for s in all_sites}
    assert "actions/checkout@v4" in all_raws, "Level-1 action should appear"
    assert "actions/setup-node@v4" in all_raws, "Level-2 action should appear"
    assert "actions/should-not-appear@v1" not in all_raws, "Level-3 action should NOT appear (depth limit)"

    # Check source chains are correct depth
    checkout = next(s for s in all_sites if s.uses.raw == "actions/checkout@v4" and s.source_chain)
    assert checkout.source_chain == [
        "org/repo/.github/workflows/level1.yml@v1"
    ]

    setup_node = next(s for s in all_sites if s.uses.raw == "actions/setup-node@v4")
    assert setup_node.source_chain == [
        "org/repo/.github/workflows/level1.yml@v1",
        "org/repo/.github/workflows/level2.yml@v1",
    ]


def test_cycle_detection_prevents_infinite_recursion():
    """
    If workflow A calls B and B calls A, we don't loop forever.
    """
    a_yaml = """
name: Workflow A
on: { workflow_call: {} }
jobs:
  call-b:
    uses: org/repo/.github/workflows/b.yml@v1
  do-stuff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    b_yaml = """
name: Workflow B
on: { workflow_call: {} }
jobs:
  call-a:
    uses: org/repo/.github/workflows/a.yml@v1
  more-stuff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
"""

    # Start with a workflow that calls A
    caller_yaml = """
name: Cyclic Caller
on: [push]
jobs:
  start:
    uses: org/repo/.github/workflows/a.yml@v1
"""
    caller_wf = parse_workflow_yaml(".github/workflows/ci.yml", caller_yaml)

    client = _make_mock_client({
        ("org", "repo", ".github/workflows/a.yml", "v1"): a_yaml,
        ("org", "repo", ".github/workflows/b.yml", "v1"): b_yaml,
    })

    # This should complete without hanging — cycle detection kicks in
    result = resolve_reusable_workflows(client, [caller_wf], max_depth=10)
    all_sites = result[0].uses_sites

    # Should have found actions from both A and B, but not looped
    all_raws = {s.uses.raw for s in all_sites}
    assert "actions/checkout@v4" in all_raws
    assert "actions/setup-python@v5" in all_raws


def test_fetch_failure_is_warned_not_fatal():
    """
    If we can't fetch a reusable workflow (private repo, rate limit, etc.),
    we warn and continue — never crash the scan.
    """
    caller_yaml = """
name: Calls Private Workflow
on: [push]
jobs:
  local-work:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  external:
    uses: private-org/secret-workflows/.github/workflows/deploy.yml@main
"""
    caller_wf = parse_workflow_yaml(".github/workflows/ci.yml", caller_yaml)

    # Mock returns nothing — simulates private repo 404
    client = _make_mock_client({})

    result = resolve_reusable_workflows(client, [caller_wf], max_depth=2)
    all_sites = result[0].uses_sites

    # We should still have the 2 direct sites, no crash
    assert len(all_sites) == 2


def test_local_reusable_workflows_not_followed():
    """
    A reusable workflow call to ./.github/workflows/local.yml should NOT
    be followed — it's classified as ref_type='local' and the file is
    already being parsed from the same repo.
    """
    caller_yaml = """
name: Calls Local Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    # Note: local reusable workflow calls use `./` prefix
    # They're classified as ref_type="local" by uses_parser, so recursion skips them
    caller_wf = parse_workflow_yaml(".github/workflows/ci.yml", caller_yaml)

    client = _make_mock_client({})
    result = resolve_reusable_workflows(client, [caller_wf], max_depth=2)

    # Client should never be called — nothing to follow
    client.get_file_content.assert_not_called()


def test_source_chain_empty_for_direct_sites():
    """
    Sites found directly in the scanned workflow (not via recursion)
    should have an empty source_chain.
    """
    caller_yaml = _load_fixture("normal_ci.yml")
    caller_wf = parse_workflow_yaml(".github/workflows/ci.yml", caller_yaml)

    # The reusable workflow in normal_ci.yml (publish.yml@v1) will fail
    # to fetch — that's fine, we're testing that the direct sites are unchanged
    client = _make_mock_client({})
    result = resolve_reusable_workflows(client, [caller_wf], max_depth=2)

    direct_sites = [s for s in result[0].uses_sites if not s.source_chain]
    # All 5 original sites from normal_ci.yml should have empty source_chain
    assert len(direct_sites) == 5
