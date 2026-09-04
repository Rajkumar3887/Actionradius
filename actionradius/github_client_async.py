"""Async GitHub API client using httpx for concurrent scanning."""

import asyncio

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


def recalibrate_concurrency(
    rate_limit_remaining: int | None,
    initial_limit: int,
    minimum: int = 1,
) -> int:
    """
    Decide the concurrency level a mid-scan check-in should apply, given the
    most recently observed ``rate_limit_remaining``.

    This never asks for *more* than ``initial_limit`` (the level the caller
    started the scan with / explicitly requested) — recalibration only ever
    throttles down from there, it doesn't grant extra parallelism beyond what
    was requested. It also never asks for less than ``minimum``, so a scan
    can always make forward progress even when the budget is nearly gone.

    Missing or unusable rate-limit data (``None``) is treated as "nothing to
    react to" — the caller keeps its current healthy target rather than being
    throttled based on absent information.
    """
    minimum = max(1, minimum)
    initial_limit = max(minimum, initial_limit)

    if rate_limit_remaining is None:
        return initial_limit

    target = compute_concurrency(rate_limit_remaining)
    return max(minimum, min(target, initial_limit))


class DynamicSemaphore:
    """
    An ``asyncio.Semaphore``-compatible primitive whose effective concurrency
    limit can be safely resized while tasks are actively acquiring/releasing
    it — used to shrink (or restore) in-flight request parallelism mid-scan
    as the GitHub rate-limit budget changes.

    Standard ``asyncio.Semaphore`` has no supported "resize" operation, and
    replacing it with a brand new Semaphore object mid-scan would orphan any
    task already waiting on the old one. Instead:

    * Growing the limit releases additional permits into the underlying
      semaphore (this is always safe — ``Semaphore.release()`` has no upper
      bound check).
    * Shrinking the limit *withholds* permits: it acquires them and simply
      never releases them back until the limit is grown again. Acquiring a
      permit only ever blocks until one is naturally released by a task that
      finishes its request, so this cannot deadlock as long as in-flight
      work keeps completing — it just means slightly delayed throttling
      rather than an abrupt cutoff.

    All resize operations are serialized behind an internal lock so
    concurrent recalibration calls (e.g. from several repos finishing at
    once) can't corrupt the internal accounting or double-count permits.
    """

    def __init__(self, initial: int, minimum: int = 1, maximum: int | None = None):
        if initial < 1:
            raise ValueError("initial concurrency must be >= 1")
        self._minimum = max(1, minimum)
        self._maximum = maximum if maximum is not None else initial
        self._maximum = max(self._minimum, self._maximum)
        initial = max(self._minimum, min(initial, self._maximum))

        self._sem = asyncio.Semaphore(initial)
        self._limit = initial
        self._resize_lock = asyncio.Lock()

    @property
    def limit(self) -> int:
        """The currently effective concurrency limit."""
        return self._limit

    async def acquire(self) -> None:
        await self._sem.acquire()

    def release(self) -> None:
        self._sem.release()

    def locked(self) -> bool:
        return self._sem.locked()

    async def __aenter__(self) -> "DynamicSemaphore":
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.release()

    async def resize(self, new_limit: int) -> int:
        """
        Adjust the effective concurrency limit, clamped to
        ``[minimum, maximum]``. Returns the limit actually applied.

        Safe to call repeatedly (idempotent when the target hasn't changed)
        and safe to call concurrently from multiple tasks.
        """
        new_limit = max(self._minimum, min(new_limit, self._maximum))
        async with self._resize_lock:
            delta = new_limit - self._limit
            if delta > 0:
                for _ in range(delta):
                    self._sem.release()
            elif delta < 0:
                for _ in range(-delta):
                    await self._sem.acquire()
            self._limit = new_limit
        return self._limit


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

    async def _get(self, path: str, params: dict | None = None, _attempt: int = 0) -> dict:
        """Single async GET — mirrors the sync client's backoff logic."""
        import time
        import asyncio
        MAX_RETRIES = 3
        
        response = await self._client.get(path, params=params)

        # Rate-limit headers may be absent (e.g. unauthenticated/non-rate-limited
        # endpoints) or malformed. Only update our tracked state when we can
        # actually parse a value — otherwise leave the previous reading in
        # place rather than clobbering it with a sentinel like -1, which
        # downstream concurrency recalibration would misread as "budget almost
        # gone" and throttle for no reason.
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
                
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                print(f"  WARNING: Secondary rate limit hit. Sleeping {retry_after}s...")
                await asyncio.sleep(int(retry_after) + 1)
                return await self._get(path, params, _attempt=_attempt + 1)
                
            if self.rate_limit_remaining == 0:
                reset_time = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
                sleep_sec = max(reset_time - int(time.time()), 1)
                print(f"  WARNING: Primary rate limit hit. Sleeping {sleep_sec}s until {reset_time}...")
                await asyncio.sleep(sleep_sec)
                return await self._get(path, params, _attempt=_attempt + 1)

        if response.status_code in (500, 502, 503, 504):
            # Transient server-side errors — retry with short exponential
            # backoff before giving up, mirroring the sync client.
            if _attempt >= MAX_RETRIES:
                response.raise_for_status()

            backoff = 2 ** _attempt
            print(f"  WARNING: GitHub API returned {response.status_code}. Retrying in {backoff}s...")
            await asyncio.sleep(backoff)
            return await self._get(path, params, _attempt=_attempt + 1)

        if response.status_code == 404:
            raise ValueError(f"Not found: {path}")
        response.raise_for_status()

        return response.json()

    async def close(self):
        await self._client.aclose()
