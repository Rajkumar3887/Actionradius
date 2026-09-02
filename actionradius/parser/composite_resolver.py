from actionradius.github_client import GitHubClient
from actionradius.models import WorkflowFile, UsesSite
from actionradius.parser.workflow_parser import parse_workflow_yaml

def resolve_reusable_workflows(
    client: GitHubClient,
    workflows: list[WorkflowFile],
    max_depth: int = 2,
) -> list[WorkflowFile]:
    visited: set[tuple[str, str, str, str]] = set()

    for wf in workflows:
        transitive_sites: list[UsesSite] = []

        for site in wf.uses_sites:
            if site.uses.is_reusable_workflow and site.uses.ref_type != "local":
                _follow_reusable(
                    client=client,
                    repo_ref=wf.repo,
                    site=site,
                    source_chain=[site.uses.raw],
                    depth=1,
                    max_depth=max_depth,
                    visited=visited,
                    out=transitive_sites,
                )

        wf.uses_sites.extend(transitive_sites)

    return workflows

def _follow_reusable(
    client: GitHubClient,
    repo_ref,
    site: UsesSite,
    source_chain: list[str],
    depth: int,
    max_depth: int,
    visited: set[tuple[str, str, str, str]],
    out: list[UsesSite],
) -> None:
    if depth > max_depth:
        return

    ref = site.uses
    if not all([ref.owner, ref.repo, ref.path, ref.ref]):
        return

    visit_key = (ref.owner, ref.repo, ref.path, ref.ref)
    if visit_key in visited:
        return
    visited.add(visit_key)

    try:
        data = client._get(f"/repos/{ref.owner}/{ref.repo}/contents/{ref.path}", params={"ref": ref.ref})
        import base64
        yaml_text = base64.b64decode(data["content"]).decode("utf-8")
        parsed = parse_workflow_yaml(repo_ref, f"{ref.owner}/{ref.repo}/{ref.path}", yaml_text)
    except Exception as e:
        print(f"  WARNING: couldn't follow reusable workflow {ref.raw}: {e}")
        return

    for ts in parsed.uses_sites:
        transitive_site = UsesSite(
            workflow_path=ts.workflow_path,
            job_id=ts.job_id,
            step_index=ts.step_index,
            uses=ts.uses,
            depth=depth,
            source_chain=list(source_chain),
        )
        out.append(transitive_site)

        if ts.uses.is_reusable_workflow and ts.uses.ref_type != "local":
            _follow_reusable(
                client=client,
                repo_ref=repo_ref,
                site=ts,
                source_chain=source_chain + [ts.uses.raw],
                depth=depth + 1,
                max_depth=max_depth,
                visited=visited,
                out=out,
            )
