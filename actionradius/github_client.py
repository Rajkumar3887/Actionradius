"""
github_client.py

This is the ONLY file that talks to GitHub directly. Every other part of
ActionRadius will call functions from here instead of making its own HTTP
requests — that way, if we ever need to change how we authenticate, handle
rate limits, or retry failures, we only change it in one place.

Concepts you need for this file:

1. GitHub REST API — a normal HTTPS API. We send GET requests to URLs like
   https://api.github.com/repos/OWNER/REPO and get JSON back.

2. Authentication — without a token, GitHub allows 60 requests/hour per IP.
   With a "personal access token" (a secret string tied to your account),
   it's 5,000/hour. We support both, starting unauthenticated for now.

3. Rate limits — GitHub tells you how many requests you have left in
   *every response*, via headers like `X-RateLimit-Remaining`. We track
   this so we can warn before we run out, instead of just crashing.

4. The Git Trees API — the piece we care about most. Instead of asking
   "list files in this folder" once per folder (slow, many requests), we
   can ask for a repo's ENTIRE file tree in one single request using
   `?recursive=1`. That's the trick that keeps us inside rate limits.
"""

import requests


class GitHubClient:
    def __init__(self, token: str | None = None):
        self.base_url = "https://api.github.com"
        self.session = requests.Session()

        # GitHub's API wants this header on every request — it's how you
        # tell it "give me the standard JSON format, current version."
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.session.headers.update(headers)

        # We'll fill these in after our first real request.
        self.rate_limit_remaining: int | None = None
        self.rate_limit_reset: int | None = None

    def _get(self, path: str, params: dict | None = None) -> dict:
        """
        Internal helper: makes a GET request to api.github.com + path,
        updates our rate-limit tracking, and raises a clear error if
        something went wrong instead of failing silently.
        """
        url = f"{self.base_url}{path}"
        response = self.session.get(url, params=params)

        # Every GitHub response includes these headers — read them every
        # time so we always know our current budget.
        self.rate_limit_remaining = int(response.headers.get("X-RateLimit-Remaining", -1))
        self.rate_limit_reset = int(response.headers.get("X-RateLimit-Reset", 0))

        if response.status_code == 403 and self.rate_limit_remaining == 0:
            raise RuntimeError(
                f"GitHub rate limit hit. Resets at unix time {self.rate_limit_reset}. "
                f"Pass a token to GitHubClient(token=...) to get a much higher limit."
            )
        if response.status_code == 404:
            raise ValueError(f"Not found: {url} (repo/path doesn't exist or is private)")
        response.raise_for_status()  # raises for any other error status (401, 500, etc.)

        return response.json()

    def get_repo(self, owner: str, repo: str) -> dict:
        """Basic repo info — we mainly need this for the default branch name."""
        return self._get(f"/repos/{owner}/{repo}")

    def get_full_tree(self, owner: str, repo: str, branch: str) -> list[dict]:
        """
        Fetch the ENTIRE file tree for a repo in one request.

        Returns a list of dicts like:
          {"path": ".github/workflows/release.yml", "type": "blob", "sha": "...", ...}

        `type` is "blob" for files and "tree" for folders — we usually only
        care about blobs (actual files).
        """
        data = self._get(f"/repos/{owner}/{repo}/git/trees/{branch}", params={"recursive": "1"})
        if data.get("truncated"):
            # Huge repos (10,000+ files) get truncated by GitHub. We'll deal
            # with that case later — flagging it now so we never silently
            # miss files without knowing.
            print(f"  WARNING: tree for {owner}/{repo} was truncated by GitHub's API")
        return data.get("tree", [])

    def get_file_content(self, owner: str, repo: str, path: str, ref: str) -> str:
        """Fetch the raw text content of one file at a specific ref (branch/tag/sha)."""
        import base64
        data = self._get(f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref})
        return base64.b64decode(data["content"]).decode("utf-8")
