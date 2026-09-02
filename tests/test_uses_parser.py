from actionradius.parser.uses_parser import parse_uses

def test_full_sha_pin():
    ref = parse_uses("actions/checkout@70379aad1a8b40919ce8b382d3cd7d0315cde1d0")
    assert ref.owner == "actions"
    assert ref.repo == "checkout"
    assert ref.ref_type == "sha"

def test_short_sha_pin():
    ref = parse_uses("aquasecurity/trivy-action@57a97c7")
    assert ref.owner == "aquasecurity"
    assert ref.repo == "trivy-action"
    assert ref.ref_type == "sha"

def test_mutable_tag():
    ref = parse_uses("aquasecurity/trivy-action@v0.28.0")
    assert ref.owner == "aquasecurity"
    assert ref.repo == "trivy-action"
    assert ref.ref == "v0.28.0"
    assert ref.ref_type == "mutable_ref"

def test_mutable_branch():
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
    ref = parse_uses("my-org/monorepo/actions/some-composite-action@v2")
    assert ref.path == "actions/some-composite-action"
    assert ref.is_reusable_workflow is False

def test_dynamic_expression_ref():
    ref = parse_uses("actions/checkout@${{ inputs.checkout_ref }}")
    assert ref.ref_type == "unresolvable"

def test_malformed_no_at_sign():
    ref = parse_uses("actions/checkout")
    assert ref.ref_type == "unresolvable"
