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

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        response = self.session.get(url, params=params)

        self.rate_limit_remaining = int(response.headers.get("X-RateLimit-Remaining", -1))
        self.rate_limit_reset = int(response.headers.get("X-RateLimit-Reset", 0))

        if response.status_code == 403 and self.rate_limit_remaining == 0:
            raise RuntimeError(
                f"GitHub rate limit hit. Resets at unix time {self.rate_limit_reset}. "
                f"Pass a token to GitHubClient(token=...) to get a much higher limit."
            )
        if response.status_code == 404:
            raise ValueError(f"Not found: {url} (repo/path doesn't exist or is private)")
        response.raise_for_status()

        return response.json()
