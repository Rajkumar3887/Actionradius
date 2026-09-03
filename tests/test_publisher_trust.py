from unittest.mock import MagicMock
from actionradius.context import publisher_trust
from actionradius.context.publisher_trust import check_publisher_trust


def _fresh_cache():
    """Each test needs an empty cache since it's a module-level singleton."""
    publisher_trust._TRUST_CACHE.clear()


def test_verified_org():
    _fresh_cache()
    client = MagicMock()

    def fake_get(path, params=None):
        if path == "/repos/actions/checkout":
            return {"stargazers_count": 5000}
        if path == "/users/actions":
            return {"created_at": "2018-01-01T00:00:00Z"}
        if path == "/orgs/actions":
            return {"is_verified": True}
        raise AssertionError(f"unexpected path {path}")

    client._get.side_effect = fake_get
    assert check_publisher_trust(client, "actions", "checkout") == "verified"


def test_new_org_low_stars():
    _fresh_cache()
    client = MagicMock()

    def fake_get(path, params=None):
        if path == "/repos/evil-corp/sketchy-action":
            return {"stargazers_count": 1}
        if path == "/users/evil-corp":
            return {"created_at": "2026-08-01T00:00:00Z"}
        if path == "/orgs/evil-corp":
            return {"is_verified": False}
        raise AssertionError(f"unexpected path {path}")

    client._get.side_effect = fake_get
    assert check_publisher_trust(client, "evil-corp", "sketchy-action") == "new_org"


def test_established_unverified():
    _fresh_cache()
    client = MagicMock()

    def fake_get(path, params=None):
        if path == "/repos/some-org/popular-action":
            return {"stargazers_count": 500}
        if path == "/users/some-org":
            return {"created_at": "2015-01-01T00:00:00Z"}
        if path == "/orgs/some-org":
            return {"is_verified": False}
        raise AssertionError(f"unexpected path {path}")

    client._get.side_effect = fake_get
    assert check_publisher_trust(client, "some-org", "popular-action") == "established"


def test_lookup_failure_returns_unknown():
    _fresh_cache()
    client = MagicMock()
    client._get.side_effect = Exception("rate limited")
    assert check_publisher_trust(client, "someone", "some-repo") == "unknown"


def test_personal_account_publisher_skips_verification():
    """/orgs/{owner} 404s for personal accounts — should still classify via repo/user data."""
    _fresh_cache()
    client = MagicMock()

    def fake_get(path, params=None):
        if path == "/repos/octocat/hello-world":
            return {"stargazers_count": 3}
        if path == "/users/octocat":
            return {"created_at": "2026-07-01T00:00:00Z"}
        if path == "/orgs/octocat":
            raise ValueError("Not found")
        raise AssertionError(f"unexpected path {path}")

    client._get.side_effect = fake_get
    assert check_publisher_trust(client, "octocat", "hello-world") == "new_org"


def test_result_is_cached_per_owner_repo():
    _fresh_cache()
    client = MagicMock()
    client._get.side_effect = [
        {"stargazers_count": 500},
        {"created_at": "2015-01-01T00:00:00Z"},
        {"is_verified": False},
    ]

    first = check_publisher_trust(client, "some-org", "popular-action")
    call_count_after_first = client._get.call_count
    second = check_publisher_trust(client, "some-org", "popular-action")

    assert first == second == "established"
    assert client._get.call_count == call_count_after_first  # no new calls on cache hit
