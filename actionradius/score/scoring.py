import yaml
from pathlib import Path
from actionradius.models import Finding, CompromiseStatus

# --- Load configurable weights ---
_DEFAULT_WEIGHTS = {
    "orphan_commit": 8.0,
    "compromised_sha_pin": 8.0,
    "mutable_compromised": 3.0,
    "unknown_compromise": 4.0,
    "fork_reachable_trigger": 3.0,
    "privileged_trigger": 1.0,
    "secrets_inherit": 3.0,
    "explicit_secrets": 2.0,
    "self_hosted_runner": 2.0,
    "typosquat_penalty": 5.0,
}

_WEIGHTS = dict(_DEFAULT_WEIGHTS)

def load_weights(path: str | None = None):
    """Load scoring weights from a YAML file, falling back to defaults."""
    global _WEIGHTS
    _WEIGHTS = dict(_DEFAULT_WEIGHTS)

    if path is None:
        # Try the default location
        default_path = Path(__file__).parent.parent.parent / "data" / "weights.yaml"
        if default_path.exists():
            path = str(default_path)
        else:
            return

    with open(path, "r", encoding="utf-8") as f:
        overrides = yaml.safe_load(f)

    if isinstance(overrides, dict):
        for k, v in overrides.items():
            if k in _WEIGHTS and isinstance(v, (int, float)):
                _WEIGHTS[k] = float(v)

# Auto-load defaults on import
load_weights()


def calculate_risk_score(
    is_mutable: bool,
    compromise_status: CompromiseStatus,
    is_orphan: bool,
    trigger,
    permissions,
    secrets,
    runs_on_self_hosted: bool,
    is_typosquat: bool = False,
) -> tuple[float, str, str]:
    """
    Returns (score, severity, rationale).
    All weights are loaded from data/weights.yaml and can be overridden.
    Map: 0-1 low, 2-4 medium, 5-7 high, 8+ critical.
    """
    w = _WEIGHTS
    score = 0.0
    rationale = []

    if is_orphan:
        score += w["orphan_commit"]
        rationale.append(f"Orphan commit SHA detected (not on default branch) (+{w['orphan_commit']})")

    if compromise_status == "COMPROMISED":
        if not is_mutable:
            score += w["compromised_sha_pin"]
            rationale.append(f"Directly pinned to compromised SHA (+{w['compromised_sha_pin']})")
        else:
            score += w["mutable_compromised"]
            rationale.append(f"Mutable pin exposed to compromised commit (+{w['mutable_compromised']})")
    elif compromise_status == "UNKNOWN":
        score += w["unknown_compromise"]
        rationale.append(f"Compromise status unknown — cannot confirm safe (+{w['unknown_compromise']})")

    if trigger.fork_reachable:
        score += w["fork_reachable_trigger"]
        rationale.append(f"Fork-reachable trigger (+{w['fork_reachable_trigger']})")
    elif trigger.risk == "medium":
        score += w["privileged_trigger"]
        rationale.append(f"Privileged trigger (+{w['privileged_trigger']})")

    if secrets.inherits_all:
        score += w["secrets_inherit"]
        rationale.append(f"Inherited secrets (+{w['secrets_inherit']})")
    elif secrets.has_real_secrets:
        score += w["explicit_secrets"]
        rationale.append(f"Explicit secrets in scope (+{w['explicit_secrets']})")

    if runs_on_self_hosted:
        score += w["self_hosted_runner"]
        rationale.append(f"Self-hosted runner (+{w['self_hosted_runner']})")

    if is_typosquat:
        score += w["typosquat_penalty"]
        rationale.append(f"Suspected typosquat of a popular action (+{w['typosquat_penalty']})")

    if score >= 8:
        severity = "critical"
    elif score >= 5:
        severity = "high"
    elif score >= 2:
        severity = "medium"
    elif score > 0:
        severity = "low"
    else:
        severity = "info"

    return score, severity, ", ".join(rationale)
