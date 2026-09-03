from actionradius.score.scoring import calculate_risk_score
from actionradius.models import TriggerContext, PermissionsContext, SecretsContext

def test_critical_score_for_ppe_vector():
    trigger = TriggerContext(["pull_request_target"], "high", True)
    perms = PermissionsContext("workflow", "read", {})
    secrets = SecretsContext(True, [], True)

    score, severity, _ = calculate_risk_score(True, "COMPROMISED", False, trigger, perms, secrets, False)

    assert score == 9.0
    assert severity == "critical"

def test_safe_workflow_is_info():
    trigger = TriggerContext([], "low", False)
    perms = PermissionsContext("workflow", "read", {})
    secrets = SecretsContext(False, [], False)

    score, severity, _ = calculate_risk_score(False, "SAFE", False, trigger, perms, secrets, False)

    assert score == 0.0
    assert severity == "info"

def test_medium_risk_for_mutable_pin_only():
    trigger = TriggerContext([], "low", False)
    perms = PermissionsContext("workflow", "read", {})
    secrets = SecretsContext(False, [], False)

    score, severity, _ = calculate_risk_score(True, "COMPROMISED", False, trigger, perms, secrets, False)

    assert score == 3.0
    assert severity == "medium"

def test_high_risk_for_explicit_secrets_and_permissions():
    trigger = TriggerContext([], "low", False)
    perms = PermissionsContext("workflow", "read", {})
    secrets = SecretsContext(False, ["NPM_TOKEN"], True)

    score, severity, _ = calculate_risk_score(True, "COMPROMISED", False, trigger, perms, secrets, False)

    assert score == 5.0
    assert severity == "high"

def test_orphan_commit_is_critical():
    trigger = TriggerContext([], "low", False)
    perms = PermissionsContext("workflow", "read", {})
    secrets = SecretsContext(False, [], False)

    score, severity, _ = calculate_risk_score(False, "COMPROMISED", True, trigger, perms, secrets, False)

    assert score == 16.0  # 8 for orphan, 8 for compromised bad SHA pin
    assert severity == "critical"

def test_unknown_compromise_scores_medium():
    """UNKNOWN status should not be treated as safe — it gets +4."""
    trigger = TriggerContext([], "low", False)
    perms = PermissionsContext("workflow", "read", {})
    secrets = SecretsContext(False, [], False)

    score, severity, _ = calculate_risk_score(False, "UNKNOWN", False, trigger, perms, secrets, False)

    assert score == 4.0
    assert severity == "medium"

def test_docker_mutable_tag_scores_high():
    """Docker mutable tag gets +2.0 plus +4.0 unknown_compromise = 6.0 high."""
    trigger = TriggerContext([], "low", False)
    perms = PermissionsContext("workflow", "read", {})
    secrets = SecretsContext(False, [], False)

    score, severity, rationale = calculate_risk_score(
        is_mutable=True,
        compromise_status="UNKNOWN",
        is_orphan=False,
        trigger=trigger,
        permissions=perms,
        secrets=secrets,
        runs_on_self_hosted=False,
        is_docker_mutable=True,
    )

    assert score == 6.0  # 2.0 docker_mutable_tag + 4.0 unknown_compromise
    assert severity == "high"
    assert "Docker tag" in rationale