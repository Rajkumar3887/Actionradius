import json
import tempfile
import os

from actionradius.drift import diff_reports, _finding_identity, _finding_label


def _finding(owner="org", name="repo", path=".github/workflows/ci.yml",
             uses_raw="actions/checkout@abc123", severity="medium",
             compromise_status="COMPROMISED"):
    return {
        "repo": {"owner": owner, "name": name},
        "uses_site": {"workflow_path": path, "uses": {"raw": uses_raw}},
        "severity": severity,
        "compromise_status": compromise_status,
    }


def _write_report(findings):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(findings, f)
    return path


def _run_diff(findings_a, findings_b, capsys):
    path_a = _write_report(findings_a)
    path_b = _write_report(findings_b)
    try:
        diff_reports(path_a, path_b)
        return capsys.readouterr().out
    finally:
        os.remove(path_a)
        os.remove(path_b)


def test_identical_reports_show_no_drift(capsys):
    f = _finding()
    output = _run_diff([f], [f], capsys)
    assert "No drift detected" in output


def test_new_finding_detected(capsys):
    output = _run_diff([], [_finding()], capsys)
    assert "NEW FINDINGS (1)" in output
    assert "org/repo:.github/workflows/ci.yml -> actions/checkout@abc123" in output


def test_resolved_finding_detected(capsys):
    output = _run_diff([_finding()], [], capsys)
    assert "RESOLVED FINDINGS (1)" in output


def test_escalation_detected(capsys):
    a = _finding(severity="low")
    b = _finding(severity="critical")
    output = _run_diff([a], [b], capsys)
    assert "ESCALATED FINDINGS (1)" in output
    assert "LOW -> CRITICAL" in output


def test_de_escalation_detected(capsys):
    a = _finding(severity="critical")
    b = _finding(severity="low")
    output = _run_diff([a], [b], capsys)
    assert "DE-ESCALATED FINDINGS (1)" in output
    assert "CRITICAL -> LOW" in output


def test_finding_identity_does_not_collide_on_ambiguous_string_join():
    """Regression test: the old `_finding_key` joined fields into a single
    string with ' -> ' as the separator between `workflow_path` and
    `uses_raw`. That makes the format ambiguous — shifting where the
    separator "appears" between two different (path, uses_raw) pairs can
    produce the exact same joined string for two genuinely different
    findings. The new tuple-based identity can't collide this way."""
    f1 = _finding(name="repo", path="a", uses_raw="b -> c")
    f2 = _finding(name="repo", path="a -> b", uses_raw="c")

    old_style_string_1 = f"org/repo:a -> b -> c"
    old_style_string_2 = f"org/repo:a -> b -> c"
    assert old_style_string_1 == old_style_string_2, "sanity check: the old format really was ambiguous here"

    assert _finding_identity(f1) != _finding_identity(f2), (
        "two structurally different findings must never share an identity, "
        "even when their old-style joined display strings coincide"
    )


def test_finding_identity_is_stable_and_matches_label_fields():
    f = _finding()
    identity = _finding_identity(f)
    assert identity == ("org", "repo", ".github/workflows/ci.yml", "actions/checkout@abc123")
    assert _finding_label(f) == "org/repo:.github/workflows/ci.yml -> actions/checkout@abc123"


def test_ambiguous_join_findings_are_not_silently_merged_in_diff(capsys):
    """End-to-end version of the collision regression: two findings that
    would have collided under the old string-key format must both show up
    as separate, independent entries in a real diff run."""
    finding_1 = _finding(name="repo", path="a", uses_raw="b -> c")
    finding_2 = _finding(name="repo", path="a -> b", uses_raw="c")

    output = _run_diff([], [finding_1, finding_2], capsys)
    assert "NEW FINDINGS (2)" in output, (
        "both findings must be reported — if the old string-key format's "
        "ambiguity caused them to collide, only 1 would appear here instead of 2"
    )


def test_load_report_error_exits_cleanly(capsys):
    import typer
    try:
        diff_reports("/nonexistent/path/a.json", "/nonexistent/path/b.json")
        assert False, "expected typer.Exit"
    except typer.Exit as e:
        assert e.exit_code == 1
