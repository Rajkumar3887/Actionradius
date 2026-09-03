from unittest.mock import MagicMock
from actionradius.models import UsesRef
from actionradius.resolve.ref_resolver import resolve_mutable_ref, _RESOLUTION_CACHE


def test_sha_ref_is_not_mutable():
    _RESOLUTION_CACHE.clear()
    ref_val = "abc1234567890abcdef1234567890abcdef123456"
    uses = UsesRef(
        raw=f"org/action@{ref_val}",
        owner="org",
        repo="action",
        path=None,
        ref=ref_val,
        ref_type="sha",
        is_reusable_workflow=False,
    )
    client = MagicMock()
    client._get.return_value = {"status": "behind"}

    resolved = resolve_mutable_ref(client, uses)

    assert resolved.is_mutable is False
    assert resolved.current_sha == ref_val
    assert resolved.is_orphan is False
    client._get.assert_called_once_with(f"/repos/org/action/compare/HEAD...{ref_val}")


def test_tag_ref_resolves_to_sha_and_is_mutable():
    _RESOLUTION_CACHE.clear()
    uses = UsesRef(
        raw="org/action@v1",
        owner="org",
        repo="action",
        path=None,
        ref="v1",
        ref_type="mutable_ref",
        is_reusable_workflow=False,
    )
    client = MagicMock()
    client._get.return_value = {"object": {"sha": "abc123"}}

    resolved = resolve_mutable_ref(client, uses)

    assert resolved.is_mutable is True
    assert resolved.current_sha == "abc123"
    client._get.assert_called_once_with("/repos/org/action/git/ref/tags/v1")


def test_orphan_sha_detected_via_compare_api():
    _RESOLUTION_CACHE.clear()
    ref_val = "deadbeef" * 5
    uses = UsesRef(
        raw=f"org/action@{ref_val}",
        owner="org",
        repo="action",
        path=None,
        ref=ref_val,
        ref_type="sha",
        is_reusable_workflow=False,
    )
    client = MagicMock()
    client._get.return_value = {"status": "diverged"}

    resolved = resolve_mutable_ref(client, uses)

    assert resolved.is_orphan is True
    assert resolved.is_mutable is False
    client._get.assert_called_once_with(f"/repos/org/action/compare/HEAD...{ref_val}")