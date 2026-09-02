import re
from actionradius.models import SecretsContext

def extract_secrets(data) -> SecretsContext:
    inherits_all = False
    explicit_secrets = set()

    def _walk(obj):
        nonlocal inherits_all
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "secrets":
                    if isinstance(v, str) and v == "inherit":
                        inherits_all = True
                    elif isinstance(v, dict):
                        explicit_secrets.update(v.keys())
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)
        elif isinstance(obj, str):
            # Look for expressions like ${{ secrets.SOME_KEY }}
            matches = re.findall(r"\${{\s*secrets\.([A-Za-z0-9_]+)\s*}}", obj)
            for m in matches:
                explicit_secrets.add(m)

    _walk(data)

    has_real_secrets = inherits_all or len(explicit_secrets) > 0

    return SecretsContext(
        inherits_all=inherits_all,
        explicit_secrets=list(explicit_secrets),
        has_real_secrets=has_real_secrets
    )
