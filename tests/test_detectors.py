from actionradius.match.typosquat import check_typosquat
from actionradius.match.sha_comment_check import detect_sha_comment_mismatches
from actionradius.models import UsesSite, UsesRef
from unittest.mock import MagicMock

def test_check_typosquat_match():
    # 'actions/checkot' is edit distance 1 from 'actions/checkout'
    site = UsesSite(
        workflow_path=".github/workflows/ci.yml",
        job_id="build",
        step_index=0,
        uses=UsesRef(
            raw="actions/checkot@v4",
            owner="actions", repo="checkot", path=None, ref="v4",
            ref_type="mutable_ref", is_reusable_workflow=False
        ),
        depth=0,
        source_chain=[]
    )
    result = check_typosquat(site)
    assert result is not None
    assert result["suspicious_action"] == "actions/checkot"
    assert result["similar_to"] == "actions/checkout"
    assert result["edit_distance"] == 1

def test_check_typosquat_safe():
    site = UsesSite(
        workflow_path=".github/workflows/ci.yml",
        job_id="build",
        step_index=0,
        uses=UsesRef(
            raw="actions/checkout@v4",
            owner="actions", repo="checkout", path=None, ref="v4",
            ref_type="mutable_ref", is_reusable_workflow=False
        ),
        depth=0,
        source_chain=[]
    )
    assert check_typosquat(site) is None

def test_detect_sha_comment_mismatches():
    client = MagicMock()
    # Mock the API so it returns a different SHA for 'v6.0.2'
    client._get.return_value = {"object": {"sha": "de0fac2e4500dabe0009e67214ff5f5447ce83dd"}}
    
    raw_yaml = "    uses: actions/checkout@70379aad1a8b40919ce8b382d3cd7d0315cde1d0 # v6.0.2"
    
    mismatches = detect_sha_comment_mismatches(client, ".github/workflows/ci.yml", raw_yaml)
    assert len(mismatches) == 1
    assert mismatches[0].pinned_sha == "70379aad1a8b40919ce8b382d3cd7d0315cde1d0"
    assert mismatches[0].comment_tag == "v6.0.2"
    assert mismatches[0].actual_tag_sha == "de0fac2e4500dabe0009e67214ff5f5447ce83dd"

def test_detect_sha_comment_no_mismatch():
    client = MagicMock()
    # Mock the API so it returns the same SHA
    client._get.return_value = {"object": {"sha": "70379aad1a8b40919ce8b382d3cd7d0315cde1d0"}}
    
    raw_yaml = "    uses: actions/checkout@70379aad1a8b40919ce8b382d3cd7d0315cde1d0 # v6.0.2"
    
    mismatches = detect_sha_comment_mismatches(client, ".github/workflows/ci.yml", raw_yaml)
    assert len(mismatches) == 0
