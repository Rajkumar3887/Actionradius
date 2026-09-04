from actionradius.models import Finding, RepoRef, UsesSite, UsesRef, ResolvedRef, TriggerContext, PermissionsContext, SecretsContext
import dataclasses

f = Finding(
    repo=RepoRef("org","repo","main",False),
    uses_site=UsesSite("ci.yml", "build", 1, UsesRef("actions/checkout@v1", "actions", "checkout", None, "v1", "tag", False), 0, []),
    resolved=ResolvedRef(UsesRef("actions/checkout@v1", "actions", "checkout", None, "v1", "tag", False), "abc", True),
    compromise_status="SAFE",
    historical_exposure="UNKNOWN",
    pin_type="sha",
    trigger=TriggerContext([],"low",False),
    permissions=PermissionsContext("workflow","read",{}),
    secrets=SecretsContext(False,[],False),
    severity="info",
    score=0.0,
    rationale="",
    publisher_trust="verified"
)
d = dataclasses.asdict(f)
assert "publisher_trust" in d
assert d["publisher_trust"] == "verified"
print("OK")
