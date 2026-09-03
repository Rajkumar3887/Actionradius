"""Async GitHub API client using httpx for concurrent scanning."""

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


def compute_concurrency(rate_limit_remaining: int | None) -> int:
    """
    Compute a safe concurrency level from the current rate-limit budget.

    Conservative: use at most 10% of remaining quota as parallel slots,
    clamped to [1, 20].
    """
    if rate_limit_remaining is None or rate_limit_remaining <= 0:
        return 1
    slots = max(1, min(rate_limit_remaining // 10, 20))
    return slots


class AsyncGitHubClient:
    """Async mirror of GitHubClient for concurrent fetching."""

    def __init__(self, token: str | None = None):
        if not HAS_HTTPX:
            raise ImportError("httpx is required for async scanning: pip install httpx")

        self.base_url = "https://api.github.com"
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=30.0,
        )
        self.rate_limit_remaining: int | None = None
        self.rate_limit_reset: int | None = None

    async def _get(self, path: str, params: dict | None = None) -> dict:
        """Single async GET — mirrors the sync client's backoff logic."""
        response = await self._client.get(path, params=params)

        self.rate_limit_remaining = int(response.headers.get("X-RateLimit-Remaining", -1))
        self.rate_limit_reset = int(response.headers.get("X-RateLimit-Reset", 0))

        if response.status_code == 404:
            raise ValueError(f"Not found: {path}")
        response.raise_for_status()

        return response.json()

    async def close(self):
        await self._client.aclose()
