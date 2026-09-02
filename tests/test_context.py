from actionradius.context import analyze_context


def test_normal_workflow_has_no_risk():
    workflow = {
        "on": {
            "push": None
        },
        "permissions": {
            "contents": "read"
        },
        "jobs": {}
    }

    result = analyze_context(workflow)

    assert result["has_pr_target"] is False
    assert result["elevated_permissions"] is False
    assert result["inherits_secrets"] is False
    assert result["explicit_secrets"] == []


def test_pull_request_target_is_detected():
    workflow = {
        "on": {
            "pull_request_target": None
        }
    }

    result = analyze_context(workflow)

    assert result["has_pr_target"] is True


def test_write_all_is_detected():
    workflow = {
        "permissions": "write-all"
    }

    result = analyze_context(workflow)

    assert result["elevated_permissions"] is True


def test_job_write_permission_is_detected():
    workflow = {
        "jobs": {
            "build": {
                "permissions": {
                    "contents": "write"
                }
            }
        }
    }

    result = analyze_context(workflow)

    assert result["elevated_permissions"] is True


def test_inherited_secrets_are_detected():
    workflow = {
        "jobs": {
            "deploy": {
                "secrets": "inherit"
            }
        }
    }

    result = analyze_context(workflow)

    assert result["inherits_secrets"] is True


def test_explicit_secrets_are_detected():
    workflow = {
        "jobs": {
            "deploy": {
                "secrets": {
                    "AWS_KEY": "some-secret",
                    "DEPLOY_TOKEN": "another-secret"
                }
            }
        }
    }

    result = analyze_context(workflow)

    assert "AWS_KEY" in result["explicit_secrets"]
    assert "DEPLOY_TOKEN" in result["explicit_secrets"]