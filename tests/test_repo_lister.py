from unittest.mock import MagicMock, patch

from actionradius.inventory.repo_lister import get_org_repos, get_repo, check_exfil_repos


def _repo_data(name, owner="myorg", fork=False, archived=False, private=False, branch="main"):
    return {
        "name": name,
        "owner": {"login": owner},
        "default_branch": branch,
        "private": private,
        "fork": fork,
        "archived": archived,
    }


def test_get_org_repos_paginates_until_short_page():
    client = MagicMock()
    page1 = [_repo_data(f"repo{i}") for i in range(100)]
    page2 = [_repo_data("repo100")]

    def fake_get(endpoint, params=None):
        if params.get("per_page") == 1:
            return [_repo_data("probe")]
        page = params["page"]
        return page1 if page == 1 else page2

    client._get.side_effect = fake_get
    repos = get_org_repos(client, "myorg")

    assert len(repos) == 101
    assert repos[0].owner == "myorg"
    assert repos[-1].name == "repo100"


def test_get_org_repos_filters_forks_and_archived_by_default():
    client = MagicMock()

    def fake_get(endpoint, params=None):
        if params.get("per_page") == 1:
            return [_repo_data("probe")]
        return [
            _repo_data("normal-repo"),
            _repo_data("forked-repo", fork=True),
            _repo_data("archived-repo", archived=True),
        ]

    client._get.side_effect = fake_get
    repos = get_org_repos(client, "myorg")

    names = {r.name for r in repos}
    assert names == {"normal-repo"}


def test_get_org_repos_includes_forks_and_archived_when_requested():
    client = MagicMock()

    def fake_get(endpoint, params=None):
        if params.get("per_page") == 1:
            return [_repo_data("probe")]
        return [
            _repo_data("normal-repo"),
            _repo_data("forked-repo", fork=True),
            _repo_data("archived-repo", archived=True),
        ]

    client._get.side_effect = fake_get
    repos = get_org_repos(client, "myorg", include_forks=True, include_archived=True)

    names = {r.name for r in repos}
    assert names == {"normal-repo", "forked-repo", "archived-repo"}


def test_get_org_repos_falls_back_to_user_endpoint_on_404():
    client = MagicMock()
    calls = []

    def fake_get(endpoint, params=None):
        calls.append(endpoint)
        if params.get("per_page") == 1:
            raise ValueError("404 Not Found")
        if endpoint == "/users/someuser/repos":
            return [_repo_data("personal-repo", owner="someuser")]
        raise AssertionError(f"unexpected endpoint: {endpoint}")

    client._get.side_effect = fake_get
    repos = get_org_repos(client, "someuser")

    assert len(repos) == 1
    assert "/users/someuser/repos" in calls


def test_get_org_repos_probe_failure_does_not_crash_and_warns():
    """A non-404 failure on the org/user disambiguation probe (rate limit,
    transient error, etc.) must not crash the whole scan — it should assume
    the org endpoint and let the real paginated call surface any genuine
    problem on its own."""
    client = MagicMock()

    def fake_get(endpoint, params=None):
        if params.get("per_page") == 1:
            raise RuntimeError("503 Service Unavailable")
        assert endpoint == "/orgs/myorg/repos"
        return [_repo_data("repo1")]

    client._get.side_effect = fake_get

    with patch("builtins.print") as mock_print:
        repos = get_org_repos(client, "myorg")
        calls = [c.args[0] for c in mock_print.call_args_list]
        assert any("WARNING" in c and "probe" in c for c in calls)

    assert len(repos) == 1


def test_get_repo_returns_single_repo_ref():
    client = MagicMock()
    client._get.return_value = _repo_data("single-repo", owner="myorg", private=True)

    repo = get_repo(client, "myorg", "single-repo")
    assert repo.owner == "myorg"
    assert repo.name == "single-repo"
    assert repo.is_private is True


def test_check_exfil_repos_member_listing_failure_warns_and_falls_back():
    """If listing org members fails outright, the fallback to checking just
    the org account is a real coverage reduction and must be surfaced, not
    silently swallowed."""
    client = MagicMock()
    client._get.side_effect = [
        Exception("403 Forbidden: insufficient scope"),  # /orgs/myorg/members
        ValueError("404 Not Found"),  # /repos/myorg/tpcp-docs (fallback check)
    ]

    with patch("builtins.print") as mock_print:
        hits = check_exfil_repos(client, "myorg")
        calls = [c.args[0] for c in mock_print.call_args_list]
        assert any("WARNING" in c and "members" in c for c in calls)

    assert hits == []


def test_check_exfil_repos_detects_hit():
    client = MagicMock()
    client._get.side_effect = [
        [{"login": "member1"}, {"login": "member2"}],  # /orgs/myorg/members
        {"name": "tpcp-docs"},  # member1 has the exfil repo
        ValueError("404 Not Found"),  # member2 does not
    ]

    hits = check_exfil_repos(client, "myorg")
    assert hits == ["member1"]
