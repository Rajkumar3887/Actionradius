I am handing off the ActionRadius project to you. This is a fleet-wide GitHub Actions supply-chain scanner.

Please begin by reading `CLAUDE_HANDOFF.md` in the root of the project to understand the current architecture, completed features, and the verified state of the codebase.

Your instructions are:
1. **Inspect the supplied project** and read `CLAUDE_HANDOFF.md`.
2. **Verify the current state** by running `python -m pytest -v` (expect 137 tests to pass).
3. **DO NOT repeat completed work**. The dynamic concurrency recalibration, HTML XSS escaping, validation ordering, and external SARIF documentation are all completely finished.
4. **Inspect the implementation** around dynamic concurrency (`actionradius/github_client_async.py` and `actionradius/async_scan.py`) just to familiarize yourself with how it resizes semaphores based on rate limits.
5. **Independently check for regressions** before starting new work.
6. **Consider 5xx retry/backoff**. If you start making code changes, consider adding a backoff for transient 502/503/504 GitHub API errors, as this is the only remaining unaddressed edge case.
7. **Identify genuinely useful future improvements** but avoid unnecessary rewrites or adding cosmetic features like progress bars (these were already evaluated and rejected).
8. **DO NOT weaken tests**.
9. **Report your findings clearly** before making major changes.

Please confirm you have read the handoff file, run the tests, and are ready for the first task.
