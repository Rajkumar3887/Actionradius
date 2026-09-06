from unittest.mock import MagicMock

from actionradius.match.sha_comment_check import (
    detect_sha_comment_mismatches,
    _resolve_tag_sha,
)


def test_no_mismatch_when_lightweight_tag_matches_pin():
    """A lightweight tag pointing straight at the pinned commit is not a
    mismatch."""
    client = MagicMock()
    client._get.return_value = {"object": {"sha": "a" * 40, "type": "commit"}}

    yaml = f"    uses: actions/checkout@{'a' * 40} # v4.0.0\n"
    mismatches = detect_sha_comment_mismatches(client, ".github/workflows/ci.yml", yaml)

    assert mismatches == []


def test_mismatch_detected_when_lightweight_tag_points_elsewhere():
    """The exact attack pattern this module exists to catch: the comment
    claims a tag, but the pinned SHA doesn't match what that tag resolves
    to."""
    client = MagicMock()
    client._get.return_value = {"object": {"sha": "b" * 40, "type": "commit"}}

    pinned = "a" * 40
    yaml = f"    uses: actions/checkout@{pinned} # v4.0.0\n"
    mismatches = detect_sha_comment_mismatches(client, ".github/workflows/ci.yml", yaml)

    assert len(mismatches) == 1
    m = mismatches[0]
    assert m.owner == "actions"
    assert m.repo == "checkout"
    assert m.pinned_sha == pinned
    assert m.comment_tag == "v4.0.0"
    assert m.actual_tag_sha == "b" * 40
    assert m.line_number == 1


def test_no_false_positive_for_matching_annotated_tag():
    """Regression test: an annotated tag's ref object points at a *tag*
    object, not a commit — resolving must dereference to the tag's target
    commit before comparing, or every correctly-pinned annotated tag would
    be flagged as a false mismatch."""
    client = MagicMock()
    tag_object_sha = "c" * 40
    commit_sha = "d" * 40

    def fake_get(path):
        if path == "/repos/org/action/git/ref/tags/v2.0.0":
            return {"object": {"sha": tag_object_sha, "type": "tag"}}
        if path == f"/repos/org/action/git/tags/{tag_object_sha}":
            return {"object": {"sha": commit_sha}}
        raise AssertionError(f"unexpected path: {path}")

    client._get.side_effect = fake_get

    yaml = f"    uses: org/action@{commit_sha} # v2.0.0\n"
    mismatches = detect_sha_comment_mismatches(client, ".github/workflows/ci.yml", yaml)

    assert mismatches == [], (
        "annotated tag correctly dereferenced to its commit should not be "
        "flagged as a mismatch"
    )


def test_mismatch_detected_for_annotated_tag_pointing_elsewhere():
    """An annotated tag still catches a real mismatch once dereferenced."""
    client = MagicMock()
    tag_object_sha = "c" * 40
    real_commit_sha = "d" * 40
    swapped_sha = "e" * 40

    def fake_get(path):
        if path == "/repos/org/action/git/ref/tags/v2.0.0":
            return {"object": {"sha": tag_object_sha, "type": "tag"}}
        if path == f"/repos/org/action/git/tags/{tag_object_sha}":
            return {"object": {"sha": real_commit_sha}}
        raise AssertionError(f"unexpected path: {path}")

    client._get.side_effect = fake_get

    yaml = f"    uses: org/action@{swapped_sha} # v2.0.0\n"
    mismatches = detect_sha_comment_mismatches(client, ".github/workflows/ci.yml", yaml)

    assert len(mismatches) == 1
    assert mismatches[0].actual_tag_sha == real_commit_sha
    assert mismatches[0].pinned_sha == swapped_sha


def test_annotated_tag_dereference_failure_falls_back_to_tag_object_sha():
    """If dereferencing the tag object fails, fall back to comparing
    against the tag-object SHA rather than crashing or silently skipping."""
    client = MagicMock()
    tag_object_sha = "c" * 40

    def fake_get(path):
        if path == "/repos/org/action/git/ref/tags/v2.0.0":
            return {"object": {"sha": tag_object_sha, "type": "tag"}}
        raise Exception("dereference failed")

    client._get.side_effect = fake_get

    assert _resolve_tag_sha(client, "org", "action", "v2.0.0") == tag_object_sha


def test_unresolvable_tag_is_skipped_not_flagged():
    """A tag that doesn't exist (or can't be resolved) is suspicious but is
    explicitly not treated as a confirmed mismatch."""
    client = MagicMock()
    client._get.side_effect = ValueError("404 Not Found")

    yaml = f"    uses: actions/checkout@{'a' * 40} # nonexistent-tag\n"
    mismatches = detect_sha_comment_mismatches(client, ".github/workflows/ci.yml", yaml)

    assert mismatches == []


def test_lines_without_sha_pins_are_ignored():
    client = MagicMock()
    yaml = "\n".join([
        "    uses: actions/checkout@v4",
        "    uses: actions/setup-node@main # not a sha",
        "    - run: echo hello",
    ])
    mismatches = detect_sha_comment_mismatches(client, ".github/workflows/ci.yml", yaml)
    assert mismatches == []
    client._get.assert_not_called()


def test_multiple_mismatches_across_lines_report_correct_line_numbers():
    client = MagicMock()
    client._get.return_value = {"object": {"sha": "z" * 40, "type": "commit"}}

    yaml = "\n".join([
        "name: CI",
        f"    uses: actions/checkout@{'a' * 40} # v4.0.0",
        "    - run: echo hello",
        f"    uses: actions/setup-python@{'b' * 40} # v5.0.0",
    ])
    mismatches = detect_sha_comment_mismatches(client, ".github/workflows/ci.yml", yaml)

    assert [m.line_number for m in mismatches] == [2, 4]
