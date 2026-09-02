"""
Tests for uses_parser.py — using real strings, several pulled straight
from the Trivy incident research (the actual poisoned trivy-action tags,
the actual "safe version" pins Aqua published, the actual injection
vector commit).

Run from the project root: pytest -v
"""
import sys
sys.path.insert(0, "actionradius")
from uses_parser import parse_uses


def test_full_sha_pin():
    # The actual commit used to inject the malicious code into Trivy's
    # release workflow, per the GitHub discussion thread.
    ref = parse_uses("actions/checkout@70379aad1a8b40919ce8b382d3cd7d0315cde1d0")
    assert ref.owner == "actions"
    assert ref.repo == "checkout"
    assert ref.ref_type == "sha"
    assert ref.is_full_sha is True


def test_short_sha_pin():
    # The REAL "safe version" pin Aqua published for trivy-action v0.35.0.
    # This must NOT be misclassified as mutable — it's a short SHA, which
    # is a real, immutable (if slightly weaker) pin.
    ref = parse_uses("aquasecurity/trivy-action@57a97c7")
    assert ref.owner == "aquasecurity"
    assert ref.repo == "trivy-action"
    assert ref.ref_type == "sha"
    assert ref.is_full_sha is False  # short — flag it, but it IS a sha


def test_mutable_tag():
    # This is the exact pattern that let the attack happen: a tag pin
    # that the attacker force-pushed to point somewhere new.
    ref = parse_uses("aquasecurity/trivy-action@v0.28.0")
    assert ref.owner == "aquasecurity"
    assert ref.repo == "trivy-action"
    assert ref.ref == "v0.28.0"
    assert ref.ref_type == "mutable_ref"


def test_mutable_branch():
    # Branches and tags are indistinguishable from the YAML text alone —
    # both should classify as mutable_ref until resolved via the API.
    ref = parse_uses("some-org/some-action@main")
    assert ref.ref_type == "mutable_ref"


def test_local_action():
    ref = parse_uses("./.github/actions/local-action")
    assert ref.ref_type == "local"
    assert ref.owner is None


def test_reusable_workflow_call():
    ref = parse_uses("my-org/shared-workflows/.github/workflows/build.yml@v1")
    assert ref.owner == "my-org"
    assert ref.repo == "shared-workflows"
    assert ref.path == ".github/workflows/build.yml"
    assert ref.is_reusable_workflow is True
    assert ref.ref_type == "mutable_ref"


def test_subdirectory_action_not_reusable_workflow():
    # A composite action living in a subfolder — has a path, but it's
    # NOT a reusable workflow because it doesn't end in .yml/.yaml.
    ref = parse_uses("my-org/monorepo/actions/some-composite-action@v2")
    assert ref.path == "actions/some-composite-action"
    assert ref.is_reusable_workflow is False


def test_dynamic_expression_ref():
    ref = parse_uses("actions/checkout@${{ inputs.checkout_ref }}")
    assert ref.ref_type == "unresolvable"


def test_malformed_no_at_sign():
    ref = parse_uses("actions/checkout")
    assert ref.ref_type == "unresolvable"
