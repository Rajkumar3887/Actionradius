from unittest.mock import Mock, patch, MagicMock
import base64
from actionradius.parser.composite_resolver import resolve_reusable_workflows
from actionradius.models import (
    RepoRef, WorkflowFile, TriggerContext, PermissionsContext,
    SecretsContext, UsesSite, UsesRef,
)


def _make_dummy_workflow(sites=None) -> WorkflowFile:
    repo = RepoRef("org", "repo", "main", False)
    return WorkflowFile(
        repo=repo, path=".github/workflows/main.yml",
        triggers=TriggerContext([], "low", False),
        permissions=PermissionsContext("workflow", "read", {}),
        secrets=SecretsContext(False, [], False),
        runs_on_self_hosted=False,
        uses_sites=sites or [],
    )


def _make_reusable_site(owner="org", repo="shared", path=".github/workflows/reusable.yml", ref="v1") -> UsesSite:
    return UsesSite(
        workflow_path=".github/workflows/main.yml",
        job_id="call-reusable",
        step_index=None,
        uses=UsesRef(
            raw=f"{owner}/{repo}/{path}@{ref}",
            owner=owner, repo=repo, path=path, ref=ref,
            ref_type="mutable_ref", is_reusable_workflow=True,
        ),
        depth=0,
        source_chain=[],
    )


def test_depth_cap_prevents_infinite_recursion():
    """Recursion depth is capped at max_depth — parse is called at most max_depth times."""
    client = MagicMock()
    # Return base64-encoded minimal YAML for any content fetch
    minimal_yaml = base64.b64encode(b"name: CI\n").decode()
    client._get.return_value = {"content": minimal_yaml}

    # First call: workflow with a reusable site
    site = _make_reusable_site(owner="org", repo="shared")
    wf = _make_dummy_workflow(sites=[site])

    # Each parse returns a workflow with another reusable site (different path to avoid visited-set)
    call_count = [0]

    def mock_parse(repo_ref, path, yaml_text):
        call_count[0] += 1
        # Return a workflow with yet another reusable site at a unique path
        next_site = _make_reusable_site(
            owner="org", repo="shared",
            path=f".github/workflows/level{call_count[0]}.yml",
        )
        return _make_dummy_workflow(sites=[next_site])

    with patch("actionradius.parser.composite_resolver.parse_workflow_yaml", side_effect=mock_parse):
        resolve_reusable_workflows(client, [wf], max_depth=1)

    # With max_depth=1, only the first reusable workflow is followed (depth=1),
    # but the next one would be depth=2 which exceeds max_depth=1
    assert call_count[0] == 1


def test_visited_set_prevents_cycles():
    """A self-referencing reusable workflow should not cause infinite loops."""
    client = MagicMock()
    minimal_yaml = base64.b64encode(b"name: CI\n").decode()
    client._get.return_value = {"content": minimal_yaml}

    # Workflow references a reusable workflow
    site = _make_reusable_site(owner="org", repo="shared")
    wf = _make_dummy_workflow(sites=[site])

    # The reusable workflow references itself (cycle)
    def mock_parse(repo_ref, path, yaml_text):
        cyclic_site = _make_reusable_site(owner="org", repo="shared")
        return _make_dummy_workflow(sites=[cyclic_site])

    with patch("actionradius.parser.composite_resolver.parse_workflow_yaml", side_effect=mock_parse):
        resolve_reusable_workflows(client, [wf], max_depth=5)

    # The visited set should prevent re-fetching the same (owner, repo, path, ref) tuple.
    # client._get should be called exactly once for the content fetch.
    content_calls = [
        c for c in client._get.call_args_list
        if "contents" in str(c)
    ]
    assert len(content_calls) == 1, (
        f"Expected 1 content fetch (visited set should block cycle), got {len(content_calls)}"
    )
