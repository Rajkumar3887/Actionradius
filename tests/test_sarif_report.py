import json
import os
from actionradius.report.sarif_report import generate_sarif_report
from actionradius.models import Finding, RepoRef, UsesSite, UsesRef

def test_sarif_filters_low_severity_and_maps_rules(tmp_path):
    out_path = tmp_path / "out.sarif"
    
    repo = RepoRef("owner", "repo", "main", False)
    uses = UsesRef("owner/action@v1", "owner", "action", "v1", "tag", "tag", False)
    site = UsesSite("path.yml", "job_1", 1, uses, 0, [])
    
    f_critical = Finding(repo, site, None, "COMPROMISED", "UNKNOWN", "tag", None, None, None, "critical", 10.0, "reason", is_typosquat=False)
    f_typosquat = Finding(repo, site, None, "UNKNOWN", "UNKNOWN", "tag", None, None, None, "high", 5.0, "reason", is_typosquat=True)
    f_low = Finding(repo, site, None, "SAFE", "UNKNOWN", "tag", None, None, None, "info", 0.0, "reason", is_typosquat=False)
    
    generate_sarif_report([f_critical, f_typosquat, f_low], str(out_path))
    
    with open(out_path, "r") as f:
        data = json.load(f)
        
    results = data["runs"][0]["results"]
    assert len(results) == 2  # Low finding should be filtered out
    
    # Check rule IDs
    rule_ids = {r["ruleId"] for r in results}
    assert "ActionRadius-CompromisedDependency" in rule_ids
    assert "ActionRadius-Typosquat" in rule_ids
