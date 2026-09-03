import json
from actionradius.models import Finding

def generate_sarif_report(findings: list[Finding], output_path: str):
    """
    Converts our findings into SARIF (Static Analysis Results Interchange Format).
    This allows the results to be ingested natively by GitHub Advanced Security.
    """
    
    results = []
    for f in findings:
        if f.severity not in ("critical", "high", "medium"):
            continue
            
        rule_id = "ActionRadius-Typosquat" if "typosquat" in (f.rationale or "").lower() \
                  else "ActionRadius-CompromisedDependency"
            
        # SARIF uses its own severity levels
        sarif_severity = "warning"
        if f.severity in ["critical", "high"]:
            sarif_severity = "error"
            
        results.append({
            "ruleId": rule_id,
            "level": sarif_severity,
            "message": {
                "text": f"Compromised GitHub Action detected: {f.uses_site.uses.raw}. Rationale: {f.rationale}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.uses_site.workflow_path
                        },
                        "region": {
                            # If we don't have the exact line number, default to line 1
                            "startLine": 1 
                        }
                    }
                }
            ]
        })

    sarif_log = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ActionRadius",
                        "informationUri": "https://github.com/your-username/actionradius",
                        "rules": [
                            {
                                "id": "ActionRadius-CompromisedDependency",
                                "shortDescription": {
                                    "text": "Compromised third-party GitHub Action dependency"
                                }
                            },
                            {
                                "id": "ActionRadius-Typosquat",
                                "shortDescription": {
                                    "text": "Typosquatted GitHub Action dependency"
                                }
                            }
                        ]
                    }
                },
                "results": results
            }
        ]
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_log, f, indent=2)
