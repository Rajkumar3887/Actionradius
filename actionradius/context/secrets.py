from actionradius.models import SecretsContext

def extract_secrets(job_dict: dict) -> SecretsContext:
    inherits_all = False
    explicit_secrets = []
    
    raw_secrets = job_dict.get("secrets", {})
    if isinstance(raw_secrets, str) and raw_secrets == "inherit":
        inherits_all = True
    elif isinstance(raw_secrets, dict):
        explicit_secrets = list(raw_secrets.keys())
        
    has_real_secrets = inherits_all or len(explicit_secrets) > 0

    return SecretsContext(
        inherits_all=inherits_all,
        explicit_secrets=explicit_secrets,
        has_real_secrets=has_real_secrets
    )
