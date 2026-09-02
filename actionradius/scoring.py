def calculate_risk_score(is_mutable: bool, context: dict) -> dict:
    """
    Calculates a risk score based on the v1 heuristic model.
    """
    score = 0
    rationale = []

    # 1. Pinning Risk
    if is_mutable:
        score += 3
        rationale.append("Mutable pin (+3)")
    
    # 2. Trigger Risk
    if context.get("has_pr_target", False):
        score += 3
        rationale.append("Fork-reachable trigger (pull_request_target) (+3)")
    
    # 3. Secrets Risk
    if context.get("inherits_secrets", False):
        score += 3
        rationale.append("Inherited secrets (+3)")
    elif context.get("explicit_secrets"):
        score += 2
        rationale.append("Explicit secrets in scope (+2)")
        
    # 4. Elevated Permissions Risk
    if context.get("elevated_permissions", False):
        score += 2
        rationale.append("Elevated permissions (+2)")

    # Map numeric score to severity band
    if score >= 7:
        severity = "CRITICAL"
    elif score >= 5:
        severity = "HIGH"
    elif score >= 3:
        severity = "MEDIUM"
    elif score > 0:
        severity = "LOW"
    else:
        severity = "INFO"

    return {
        "score": score,
        "severity": severity,
        "rationale": rationale
    }