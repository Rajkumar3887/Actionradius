from datetime import datetime, timezone
from actionradius.github_client import GitHubClient

PublisherTrust = str  # "verified" | "established" | "new_org" | "unknown"

NEW_ORG_DAYS = 90
LOW_STAR_THRESHOLD = 10

# Process-lifetime cache keyed by (owner, repo)
_TRUST_CACHE: dict[tuple[str, str], PublisherTrust] = {}


def _parse_created_at(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def check_publisher_trust(client: GitHubClient, owner: str, repo: str) -> PublisherTrust:
    """
    Classifies the publisher of an `owner/repo` action as one of:
      - "verified"     — GitHub-verified org (`is_verified` on the org account)
      - "new_org"       — account created within the last NEW_ORG_DAYS days,
                          OR the repo has fewer than LOW_STAR_THRESHOLD stars
      - "established"  — account is older than NEW_ORG_DAYS days and repo has
                          reasonable stars, but isn't verified
      - "unknown"       — lookup failed (rate limit, 404, network error, etc.)

    `/users/{owner}` is used for account age since it resolves for both
    personal accounts and orgs; `/orgs/{owner}` is tried separately for the
    `is_verified` badge and simply skipped (not an org) if it 404s.

    Results are cached per (owner, repo) for the lifetime of the process,
    since the same publisher is looked up repeatedly across a fleet scan.
    """
    if not owner or not repo:
        return "unknown"

    cache_key = (owner, repo)
    if cache_key in _TRUST_CACHE:
        return _TRUST_CACHE[cache_key]

    if not client:
        return "unknown"

    trust: PublisherTrust = "unknown"
    try:
        repo_data = client._get(f"/repos/{owner}/{repo}")
        stargazers = repo_data.get("stargazers_count", 0)

        is_new = isinstance(stargazers, int) and stargazers < LOW_STAR_THRESHOLD

        account_created = None
        try:
            user_data = client._get(f"/users/{owner}")
            account_created = _parse_created_at(user_data.get("created_at"))
        except Exception:
            pass

        if account_created is not None:
            age_days = (datetime.now(timezone.utc) - account_created).days
            if age_days < NEW_ORG_DAYS:
                is_new = True

        is_verified = False
        try:
            org_data = client._get(f"/orgs/{owner}")
            is_verified = bool(org_data.get("is_verified", False))
        except Exception:
            # Not an org (personal-account publisher) or lookup failed —
            # verification simply doesn't apply.
            pass

        if is_verified:
            trust = "verified"
        else:
            trust = "new_org" if is_new else "established"
    except Exception:
        trust = "unknown"

    _TRUST_CACHE[cache_key] = trust
    return trust
