import requests

class GitHubClient:
    def __init__(self, token: str | None = None):
        self.base_url = "https://api.github.com"
        self.session = requests.Session()

        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.session.headers.update(headers)

        self.rate_limit_remaining: int | None = None
        self.rate_limit_reset: int | None = None

    def _get(self, path: str, params: dict | None = None, _attempt: int = 0) -> dict:
        MAX_RETRIES = 3
        url = f"{self.base_url}{path}"
        # A hang here (DNS/connect/read stall) would otherwise block the CLI
        # forever with no feedback; mirror the async client's 30s timeout.
        response = self.session.get(url, params=params, timeout=30.0)

        # Only update tracked rate-limit state when the header is present and
        # parseable — an absent/malformed header must not clobber a previous
        # good reading with a sentinel like -1.
        remaining_header = response.headers.get("X-RateLimit-Remaining")
        if remaining_header is not None:
            try:
                self.rate_limit_remaining = int(remaining_header)
            except (TypeError, ValueError):
                pass

        reset_header = response.headers.get("X-RateLimit-Reset")
        if reset_header is not None:
            try:
                self.rate_limit_reset = int(reset_header)
            except (TypeError, ValueError):
                pass

        if response.status_code == 403:
            if _attempt >= MAX_RETRIES:
                response.raise_for_status()
                
            import time
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                print(f"  WARNING: Secondary rate limit hit. Sleeping {retry_after}s...")
                time.sleep(int(retry_after) + 1)
                return self._get(path, params, _attempt=_attempt + 1)
                
            if self.rate_limit_remaining == 0:
                reset_time = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
                sleep_sec = max(reset_time - int(time.time()), 1)
                print(f"  WARNING: Primary rate limit hit. Sleeping {sleep_sec}s until {reset_time}...")
                time.sleep(sleep_sec)
                return self._get(path, params, _attempt=_attempt + 1)

        if response.status_code in (500, 502, 503, 504):
            # Transient server-side errors — not rate-limit related. Retry
            # with a short exponential backoff before giving up; a single
            # blip on GitHub's side shouldn't sink an otherwise-healthy scan.
            if _attempt >= MAX_RETRIES:
                response.raise_for_status()

            import time
            backoff = 2 ** _attempt
            print(f"  WARNING: GitHub API returned {response.status_code}. Retrying in {backoff}s...")
            time.sleep(backoff)
            return self._get(path, params, _attempt=_attempt + 1)

        if response.status_code == 404:
            raise ValueError(f"Not found: {url} (repo/path doesn't exist or is private)")
        response.raise_for_status()

        return response.json()
