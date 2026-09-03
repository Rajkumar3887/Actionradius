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
        response = self.session.get(url, params=params)

        self.rate_limit_remaining = int(response.headers.get("X-RateLimit-Remaining", -1))
        self.rate_limit_reset = int(response.headers.get("X-RateLimit-Reset", 0))

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
        if response.status_code == 404:
            raise ValueError(f"Not found: {url} (repo/path doesn't exist or is private)")
        response.raise_for_status()

        return response.json()
