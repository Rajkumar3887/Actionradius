from actionradius.models import Finding

def calculate_risk_score(is_mutable: bool, is_compromised: bool, is_orphan: bool, trigger, permissions, secrets, runs_on_self_hosted: bool) -> tuple[float, str, str]:
    """
    Returns (score, severity, rationale).
    Heuristic:
    - orphan commit SHA: +8 (critical immediately)
    - mutable pin AND compromised: +3 (if SHA pin is bad, skip to critical)
    - trigger fork_reachable: +3
    - privileged triggers: +1
    - real secrets in scope: +2, secrets inherit: +3
    - self-hosted runner: +2
    Map: 0-1 low, 2-4 medium, 5-7 high, 8+ critical.
    """
    score = 0.0
    rationale = []
    
    if is_orphan:
        score += 8.0
        rationale.append("Orphan commit SHA detected (not on default branch) (+8)")
        
    if not is_mutable and is_compromised:
        score += 8.0 # Skip straight to critical for bad SHA pins
        rationale.append("Directly pinned to compromised SHA (+8)")
    elif is_mutable and is_compromised:
        score += 3.0
        rationale.append("Mutable pin exposed to compromised commit (+3)")
        
    if trigger.fork_reachable:
        score += 3.0
        rationale.append("Fork-reachable trigger (+3)")
    elif trigger.risk == "medium":
        score += 1.0
        rationale.append("Privileged trigger (+1)")
        
    if secrets.inherits_all:
        score += 3.0
        rationale.append("Inherited secrets (+3)")
    elif secrets.has_real_secrets:
        score += 2.0
        rationale.append("Explicit secrets in scope (+2)")
        
    if runs_on_self_hosted:
        score += 2.0
        rationale.append("Self-hosted runner (+2)")
        
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
