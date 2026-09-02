import pytest
from actionradius.scoring import calculate_risk_score

def test_critical_score_for_ppe_vector():
    # Arrange: Mutable pin (+3), PR target (+3), Secrets inherit (+3) = 9 (CRITICAL)
    context = {
        "has_pr_target": True, 
        "inherits_secrets": True, 
        "explicit_secrets": [], 
        "elevated_permissions": False
    }
    
    # Act
    result = calculate_risk_score(is_mutable=True, context=context)
    
    # Assert
    assert result["score"] == 9
    assert result["severity"] == "CRITICAL"
    assert len(result["rationale"]) == 3

def test_safe_workflow_is_info():
    # Arrange: Hardened workflow
    context = {
        "has_pr_target": False, 
        "inherits_secrets": False, 
        "explicit_secrets": [], 
        "elevated_permissions": False
    }
    
    # Act
    result = calculate_risk_score(is_mutable=False, context=context)
    
    # Assert
    assert result["score"] == 0
    assert result["severity"] == "INFO"
    assert len(result["rationale"]) == 0

def test_medium_risk_for_mutable_pin_only():
    # Arrange: Unpinned action, but safe triggers and no secrets
    context = {
        "has_pr_target": False, 
        "inherits_secrets": False, 
        "explicit_secrets": [], 
        "elevated_permissions": False
    }
    
    # Act
    result = calculate_risk_score(is_mutable=True, context=context)
    
    # Assert
    assert result["score"] == 3
    assert result["severity"] == "MEDIUM"
    assert "Mutable pin (+3)" in result["rationale"]
    
def test_high_risk_for_explicit_secrets_and_permissions():
    # Arrange: Safe pin, but dangerous context if it were ever poisoned
    context = {
        "has_pr_target": False, 
        "inherits_secrets": False, 
        "explicit_secrets": ["NPM_TOKEN"], 
        "elevated_permissions": True
    }
    
    # Act
    result = calculate_risk_score(is_mutable=True, context=context)
    
    # Assert
    assert result["score"] == 7 # Mutable(3) + Secrets(2) + Perms(2)
    assert result["severity"] == "CRITICAL"